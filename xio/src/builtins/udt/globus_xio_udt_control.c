/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_i_xio_udt.h"

static
int
globus_l_xio_udt_ack_window_predicate(
    void*                               datum,
    void*                               user_arg);

static
void
globus_l_xio_udt_store_ack_record(
    globus_l_handle_t*                  handle,
    int                                 ack_seq,
    int                                 seq);

static
int
globus_l_xio_udt_calculate_rtt_and_last_ack_ack(
    globus_l_handle_t*                                  handle,
    int                                                 ack_seq,
    int*                                                seq);

static
int
globus_l_xio_udt_get_pkt_arrival_speed(
    globus_l_xio_udt_read_history_t*            read_history);


static
globus_bool_t
globus_l_xio_udt_get_delay_trend(
    globus_l_xio_udt_read_history_t*           read_history);


static
int
globus_l_xio_udt_get_bandwidth(
    globus_l_xio_udt_read_history_t*           read_history);


static
void
globus_l_xio_udt_record_recent_rtt_pct_pdt(
    globus_l_xio_udt_read_history_t*            read_history,
    int                                         rtt);

static
void
globus_l_xio_udt_rate_control(
    globus_l_handle_t*                  handle);


static
void
globus_l_xio_udt_flow_control(
    globus_l_handle_t*                  handle,
    int                                 read_rate);

static
void
globus_l_xio_udt_write_ack(
    globus_l_handle_t *                 handle);

static
void
globus_l_xio_udt_write_nak_timer_expired(
    globus_l_handle_t *                          handle);

static
void
globus_l_xio_udt_write_keepalive(
    globus_l_handle_t *                 handle);

static
void
globus_l_xio_udt_write_ack_ack(
    globus_l_handle_t *                 handle,
    int                                 ack_seqno);

static
void
globus_l_xio_udt_write_fin_ack(
    globus_l_handle_t *                 handle);

static
void
globus_l_xio_udt_write_congestion_warning(
    globus_l_handle_t *                           handle);

static
void
globus_l_xio_udt_fin(
    void*                       user_arg);


/*
 *  The following functions are associated with ack window
 */ 
 
         /*
          *  Functionality:
          *    Predicate for globus_l_xio_udt_store_ack_record. i.e,
          *    globus_l_xio_udt_store_ack_record uses this routine to
          *    check if the seq is already in ack_window
          *  Parameters:
          *    1) [in] datum: ack record
          *    2) [in] user_arg: user provided argument (ack_seq)
          *  Returned value:
          *    1 if datum == user_arg else 0
          */   
          
static
int
globus_l_xio_udt_ack_window_predicate(
    void*                               datum,
    void*                               user_arg)
{   

    globus_l_xio_udt_ack_record_t * data =
        (globus_l_xio_udt_ack_record_t *) datum;
    int* ack_seq = (int*) user_arg; 
    GlobusXIOName(globus_l_xio_udt_ack_window_predicate);
    if (data->ack_seq == *ack_seq)
    {   
        return 1;
    }   
    return 0;
}   


      /*
       *  Functionality:
       *     Write an ACK record into the window.
       *  Parameters: 
       *    1) [in] handle: udt handle
       *     2) [in] seq: ACK seq. no.
       *     3) [in] ack: DATA ACK no.
       *  Returned value: 
       *     None. 
       */    
       
static
void
globus_l_xio_udt_store_ack_record(
    globus_l_handle_t*                  handle,
    int                                 ack_seq,
    int                                 seq)
/* seq - seqno of the data pkt and ack_seq - seqno of ack pkt */
{
    globus_l_xio_udt_ack_record_t* ack_record;
    globus_list_t* temp_list;
    GlobusXIOName(globus_l_xio_udt_store_ack_record);

    GlobusXIOUdtDebugEnter();

    temp_list = globus_list_search_pred(handle->ack_window,
        globus_l_xio_udt_ack_window_predicate, &ack_seq);
    if (temp_list != NULL)
    {
        ack_record = globus_list_first(temp_list);
    }
    else
    {
        ack_record = (globus_l_xio_udt_ack_record_t*)
            globus_malloc(sizeof(globus_l_xio_udt_ack_record_t));
    }
    ack_record->ack_seq = ack_seq;
    ack_record->seq = seq;
    GlobusTimeAbstimeGetCurrent(ack_record->time_stamp);
    if (temp_list == NULL)
    {
        globus_list_insert(&handle->ack_window, ack_record);
    }

    GlobusXIOUdtDebugExit();
    return;
}



      /*
       *   Functionality:
       *      Search the ACK-2 "seq" in the window, find out the DATA "ack"
       *      and caluclate RTT .
       *   Parameters:
       *      1) [in] handle: udt handle
       *      2) [in] seq: ACK-2 seq. no.
       *      3) [out] ack: the DATA ACK no. that matches the ACK-2 no.
       *   Returned value:
       *      RTT.
       */

static
int
globus_l_xio_udt_calculate_rtt_and_last_ack_ack(
    globus_l_handle_t*                                  handle,
    int                                                 ack_seq,
    int*                                                seq)
/* seq - seqno of the data pkt and ack_seq - seqno of ack pkt */
{
    globus_list_t* ack_window = handle->ack_window;
    globus_list_t* temp_list;
    globus_abstime_t curr_time;
    globus_reltime_t rtt;
    int rtt_usec;
    GlobusXIOName(globus_l_xio_udt_calculate_rtt_and_lask_ack_ack);

    GlobusXIOUdtDebugEnter();

    GlobusTimeReltimeSet(rtt, 0, 0);
    temp_list = globus_list_search_pred(ack_window,
        globus_l_xio_udt_ack_window_predicate, &ack_seq);
    if (temp_list != NULL)
    {
        globus_l_xio_udt_ack_record_t* ack_record;

        ack_record = globus_list_first(temp_list);
        *seq = ack_record->seq;
        GlobusTimeAbstimeGetCurrent(curr_time);
        GlobusTimeAbstimeDiff(rtt, curr_time, ack_record->time_stamp);
        globus_free(ack_record);
        globus_list_remove(&handle->ack_window, temp_list);
    }
    GlobusTimeReltimeToUSec(rtt_usec, rtt);

    GlobusXIOUdtDebugExit();
    return rtt_usec;
}


/*
 *  The following functions are associated with pkt time window
 */

      /*
       *  Functionality:
       *     Calculate the packes arrival speed.
       *  Parameters:
       *     1) None.
       *  Returned value:
       *     Packet arrival speed (packets per second).
       */

static
int
globus_l_xio_udt_get_pkt_arrival_speed(
    globus_l_xio_udt_read_history_t*            read_history)
{
    int i, j, m, count = 0;
    int sum = 0, median, interval;
    int pkt_arrival_speed = 0;
    GlobusXIOName(globus_l_xio_udt_get_pkt_arrival_speed);

    GlobusXIOUdtDebugEnter();

    /* sorting */
    /*
     * I store this value to avoid doing "GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE
     * >> 1" multiple times
     */
    m = GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE >> 1;
    for (i = 0; i <= m; ++ i)
    {
        for (j = i; j < GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE; ++ j)
        {
            if (read_history->pkt_window[i] > read_history->pkt_window[j])
            {
                interval = read_history->pkt_window[i];
                read_history->pkt_window[i] = read_history->pkt_window[j];
                read_history->pkt_window[j] = interval;
            }
        }
    }

    /* read the median value */
    median = (read_history->pkt_window[m - 1] +
        read_history->pkt_window[m]) >> 1;

    /* median filtering */
    for (i = 0; i < GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE; ++ i)
    {
        if ((read_history->pkt_window[i] < (median << 3)) &&
            (read_history->pkt_window[i] > (median >> 3)))
        {
            ++ count;
            sum += read_history->pkt_window[i];
        }
    }
    /* calculate speed, or return 0 if not enough valid value */
    if (count > m)
    {
        pkt_arrival_speed = (int)ceil(1000000.0 / (sum / count));
    }
 
    GlobusXIOUdtDebugExit();
    return pkt_arrival_speed;
}     
       
       
       
      /*     
       *  Functionality:
       *     Check if the rtt is increasing or not.
       *  Parameters:
       *     1) None.
       *  Returned value:
       *     GLOBUS_TRUE is RTT is increasing, otherwise GLOBUS_FALSE.
       */
    
static
globus_bool_t 
globus_l_xio_udt_get_delay_trend(
    globus_l_xio_udt_read_history_t*           read_history)
{   
    double pct = 0.0;
    double pdt = 0.0;
    int i;
    GlobusXIOName(globus_l_xio_udt_get_delay_trend);
    
    GlobusXIOUdtDebugEnter();
     
    for (i = 0; i < GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE; ++i)
    { 
        if (i != read_history->rtt_window_ptr)
        {
            pct += read_history->pct_window[i];
            pdt += read_history->pdt_window[i];
        }   
    }       
                
    /* calculate PCT and PDT value */
    pct /= GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE - 1;
    if (pdt != 0)
    {   
        pdt = (read_history->rtt_window[(read_history->rtt_window_ptr - 1 +
            GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE) %
            GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE] -
            read_history->rtt_window[read_history->rtt_window_ptr]) / pdt;
    }   

    GlobusXIOUdtDebugExit();
    /*  
     * PCT/PDT judgement reference: M. Jain, C. Dovrolis, Pathload: a
     * measurement tool for end-to-end available bandwidth 
     */     
    return ((pct > 0.66) && (pdt > 0.45)) || ((pct > 0.54) && (pdt > 0.55));
}



      /*
       *  Functionality:
       *     Estimate the bandwidth.
       *  Parameters:
       *     1) None.
       *  Returned value:
       *     Estimated bandwidth (packets per second).
       */

static
int
globus_l_xio_udt_get_bandwidth(
    globus_l_xio_udt_read_history_t*           read_history)
{
    /* sorting */
    int i, j, m, interval, median;
    int bandwidth = 0;
    GlobusXIOName(globus_l_xio_udt_get_bandwidth);

    GlobusXIOUdtDebugEnter();

    m = GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE >> 1;
    for (i = 0; i <= m; ++ i)
    {
        for (j = i; j < GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE; ++ j)
        {
            if (read_history->probe_window[i] > read_history->probe_window[j])
            {
                interval = read_history->probe_window[i];
                read_history->probe_window[i] = read_history->probe_window[j];
                read_history->probe_window[j] = interval;
            }
        }
    }

    /*
     * read the median value - interval is in usec and the interval gives the
     * time interval 2 subsequent packets
     */
    median = (read_history->probe_window[m - 1] +
             read_history->probe_window[m]) >> 1;

    if (median > 0)
    {
        bandwidth = (int)(1000000.0 / median);
    }

    GlobusXIOUdtDebugExit();
    return bandwidth;
}



      /*
       *  Functionality:
       *     Record time information of an arrived packet - used for
       *     calculating pkt arrival speed
       *  Parameters:
       *     1) None.
       *  Returned value:
       *     None.
       */
      
void   
globus_l_xio_udt_record_pkt_arrival(
    globus_l_xio_udt_read_history_t*           read_history)
{      
    globus_reltime_t pkt_interval;
    GlobusXIOName(globus_l_xio_udt_record_pkt_arrival);

    GlobusXIOUdtDebugEnter();

    GlobusTimeAbstimeGetCurrent(read_history->curr_arr_time);
    /* record the packet interval between the current and the last one */
    GlobusTimeAbstimeDiff(pkt_interval, read_history->curr_arr_time,
        read_history->last_arr_time);
    GlobusTimeReltimeToUSec(
        read_history->pkt_window[read_history->pkt_window_ptr], pkt_interval);
    
    /* the window is logically circular */
    read_history->pkt_window_ptr = (read_history->pkt_window_ptr + 1) %
        GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE;
    
    /* remember last packet arrival time */
    GlobusTimeAbstimeCopy(read_history->last_arr_time,
        read_history->curr_arr_time);
        
    GlobusXIOUdtDebugExit();
}           
                
                
                
      /*    
       *  Functionality:
       *     Record the recent RTT.
       *  Parameters:
       *     1) [in] read_history: reader history
       *     2) [in] rtt: the mose recent RTT from ACK-2.
       *  Returned value:
       *     None.
       */
             
static
void 
globus_l_xio_udt_record_recent_rtt_pct_pdt(
    globus_l_xio_udt_read_history_t*            read_history,
    int                                         rtt)
{
    GlobusXIOName(globus_l_xio_udt_record_recent_rtt_pct_pdt);
    
    GlobusXIOUdtDebugEnter();

    /* record RTT, comparison (1 or 0), and absolute difference */
    read_history->rtt_window[read_history->rtt_window_ptr] = rtt;
    read_history->pct_window[read_history->rtt_window_ptr] =
        (rtt > read_history->rtt_window[(read_history->rtt_window_ptr - 1 +
        GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE) % 
        GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE]) ? 1 : 0;
    read_history->pdt_window[read_history->rtt_window_ptr] =
        abs(rtt - read_history->rtt_window[(read_history->rtt_window_ptr - 1 +          GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE) %
        GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE]);

    /* the window is logically circular */
    read_history->rtt_window_ptr = (read_history->rtt_window_ptr + 1) %
        GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE;

    GlobusXIOUdtDebugExit();
}



      /*
       *  Functionality:
       *     Record the arrival time of the second probing packet and the
       *     interval between packet pairs - used for calculating bw
       *  Parameters:
       *     1) [in] read_history: reader history
       *  Returned value:
       *     None.
       */

void
globus_l_xio_udt_record_probe2_arrival(
    globus_l_xio_udt_read_history_t*           read_history)
{
    globus_reltime_t pkt_interval;
    GlobusXIOName(globus_l_xio_udt_record_probe2_arrival);

    GlobusXIOUdtDebugEnter();

    GlobusTimeAbstimeGetCurrent(read_history->curr_arr_time);
    /* record the probing packets interval */

    GlobusTimeAbstimeDiff(pkt_interval, read_history->curr_arr_time,
        read_history->probe_time);
    GlobusTimeReltimeToUSec(
        read_history->probe_window[read_history->probe_window_ptr],
        pkt_interval);

    /* the window is logically circular */
    read_history->probe_window_ptr = (read_history->probe_window_ptr + 1) %
        GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE;

    GlobusXIOUdtDebugExit();
}



      /*
       *  Functionality:
       *     Updates the inter packet interval based on the current situation
       *  Parameters:
       *     1) [in] handle: udt handle
       *  Returned value:
       *     None.
       */

static
void 
globus_l_xio_udt_rate_control(
    globus_l_handle_t*                  handle)
{       
    double curr_loss_rate;
    double inc;
    GlobusXIOName(globus_l_xio_udt_rate_control);
        
    GlobusXIOUdtDebugEnter();
    
    globus_mutex_lock(&handle->write_cntl->mutex);
    curr_loss_rate =
        handle->write_cntl->local_loss / handle->write_cntl->local_write;
    if (curr_loss_rate > 1.0)
    {   
        curr_loss_rate = 1.0;
    }        
       
    handle->write_cntl->local_write = 0;
    handle->write_cntl->local_loss = 0;
       
    handle->write_cntl->loss_rate =
        handle->write_cntl->loss_rate * GLOBUS_L_XIO_UDT_WEIGHT +
        curr_loss_rate * (1 - GLOBUS_L_XIO_UDT_WEIGHT);

    if (handle->write_cntl->loss_rate <= GLOBUS_L_XIO_UDT_LOSS_RATE_LIMIT)
    {
        int inter_pkt_interval = handle->write_cntl->inter_pkt_interval;
        int mss = handle->handshake->mss;
    
        /* During Slow Start, no rate increase */
        if (!handle->write_cntl->slow_start)
        {
            if (1000000.0/inter_pkt_interval > handle->bandwidth)
            {
                inc = 1.0/mss;
            }
            else
            {
                inc = pow(10, ceil(log10((handle->bandwidth - 1000000.0 /
                    inter_pkt_interval) * mss * 8))) * 0.0000015 / mss;
                if (inc < 1.0/mss)
                {
                    inc = 1.0/mss;
                }
            }
            handle->write_cntl->inter_pkt_interval =
                (int)((inter_pkt_interval * GLOBUS_L_XIO_UDT_SYN_INTERVAL) /
                (inter_pkt_interval * inc + GLOBUS_L_XIO_UDT_SYN_INTERVAL));

        }
    }
      
    /* 
     * the if below is to make sure inter-pkt-interval does not go below cpu 
     * frequency - right now it is hardcoded with the cpu frequency = 1 i.e,
     * 1 cpu clock per usec - gigahz processor
     */
    if (handle->write_cntl->inter_pkt_interval < 1)
    {   
        handle->write_cntl->inter_pkt_interval = 1;
    } 
    globus_mutex_lock(&handle->write_cntl->mutex);
    GlobusXIOUdtDebugExit();


}



      /*
       *  Functionality:
       *     Updates the flow window size based on the pkt arrival speed at
       *     the other end
       *  Parameters:
       *     1) [in] handle: udt handle
       *     2) [in] read_rate: pkt arrival speed(in pkts per second) at the
       *     other end
       *  Returned value:
       *     None.
       */

static
void
globus_l_xio_udt_flow_control(
    globus_l_handle_t*                  handle,
    int                                 read_rate)
{
    GlobusXIOName(globus_l_xio_udt_flow_control);

    GlobusXIOUdtDebugEnter();

    if (handle->write_cntl->slow_start == GLOBUS_TRUE)
    {
        handle->flow_wnd_size = handle->write_cntl->last_ack;
    }
    else if (read_rate > 0)
    {
        handle->flow_wnd_size = (int)ceil(handle->flow_wnd_size * 0.875 +
        read_rate / 1000000.0 * (handle->rtt + GLOBUS_L_XIO_UDT_SYN_INTERVAL)
        * 0.125);
    }

    /*
     * read_rate gives number of packets per second. the above formula is
     * W = W*0.875 + 0.125*AS*(RTT+SYN). need to check what AS is in the paper.
     */

    if (handle->flow_wnd_size > handle->handshake->max_flow_wnd_size)
    {
        handle->flow_wnd_size = handle->handshake->max_flow_wnd_size;
        handle->write_cntl->slow_start = GLOBUS_FALSE;
    }

    GlobusXIOUdtDebugExit();
}

    
static
void
globus_l_xio_udt_write_ack(
    globus_l_handle_t *                 handle)
{   
    
    globus_xio_iovec_t*                 iovec;
    int                                 ack = 0;
    int                                 last_ack; 
    int                                 last_ack_ack;
    GlobusXIOName(globus_l_xio_udt_write_ack);
    GlobusXIOUdtDebugEnter();
    
    globus_mutex_lock(&handle->write_mutex);
    
    iovec = (globus_xio_iovec_t*) globus_malloc(sizeof(globus_xio_iovec_t) * 2);
    if (iovec == NULL)
    {
        goto error_iovec;
    }
    iovec[0].iov_base = globus_malloc(GLOBUS_L_XIO_UDT_HEADER_SIZE);
    if (iovec[0].iov_base == NULL)
    {
        goto error_header;
    }
    iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;

    /* Set (bit-0 = 1) and (bit-1~3 = type) */

    *((int*)iovec[0].iov_base) = 0x80000000 | (GLOBUS_L_XIO_UDT_ACK << 28);

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
        ("inside ack read_cntl->last_ack is %d curr_seqno is %d "
        "reader_loss_length is %d\n",
        handle->read_cntl->last_ack, handle->read_cntl->curr_seqno,
        handle->reader_loss_info->length));

    last_ack = handle->read_cntl->last_ack;

    if (handle->reader_loss_info->length == 0)
    {
        int curr_seqno = handle->read_cntl->curr_seqno;
        /*
         * If there is no loss, the ACK is the current largest sequence number
         * plus 1.
         */
        if ((curr_seqno >= last_ack) &&
            (curr_seqno - last_ack < GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
        {
            ack = curr_seqno - last_ack + 1;
        }
        /*
         * even if curr_seqno == last_ack, you have 1 pkt to ack - coz
         * last_ack indicates that all pkts with seqno < last_ack are
         * ack'd already
         */
        else if (last_ack - curr_seqno > GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
        {
            ack = curr_seqno + GLOBUS_L_XIO_UDT_MAX_SEQ_NO - last_ack + 1;
        }
    }
    else
    {
        /*
         * If there is loss, ACK is the smallest sequence number in the reader i         * loss list.
         */
        ack = globus_l_xio_udt_get_first_reader_lost_seq(
            handle->reader_loss_info) - last_ack;
        if (ack > GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
        {
          GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,                ("difference between smallest seqno in reader loss list and "
            "handle->read_cntl->last_ack is greater than "
            "GLOBUS_L_XIO_UDT_SEQ_NO_THRESH"));
          goto error_data;
        }
        /*
         * there is a basic assumption/restriction in the protocol that
         * the difference between any 2 seq nos cannot be more than
         * GLOBUS_L_XIO_UDT_SEQ_NO_THRESH
         */
        else if (ack < -GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
        {
            ack += GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
        }
    }

    /*
     * There is new received packet to acknowledge, update related
     * information.
     */
    if (ack > 0)
    {
        last_ack = (last_ack + ack) % GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
        handle->read_cntl->last_ack = last_ack;
        if (globus_l_xio_udt_update_read_ack_point(handle, ack *
            handle->payload_size - globus_l_xio_udt_get_error_size(
            handle->irregular_pkt_info, last_ack)) == GLOBUS_TRUE)
        {
            handle->read_cntl->user_buf_border =
                last_ack + (int)ceil((double)handle->read_buf->udt_buf_size /
                handle->payload_size);
            /* 
             * sets user_buf_border to a high value as the user buffer
             * is fulfilled 
             */ 
        }
        globus_l_xio_udt_remove_irregular_pkts(handle->irregular_pkt_info,
            last_ack);
    }   
    else    
    /* if curr_time - last_ack_time < 2*rtt dont write an ack now  */
    {   
        globus_abstime_t curr_time;
        globus_reltime_t diff;
        int diff_usec;
        GlobusTimeAbstimeGetCurrent(curr_time);
        GlobusTimeAbstimeDiff(diff, curr_time, 
            handle->read_cntl->last_ack_time);
        GlobusTimeReltimeToUSec(diff_usec, diff);
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
            ("rtt is %d and diff_usec is %d\n", handle->rtt, diff_usec));
        if (diff_usec < 2 * handle->rtt)
        {
            goto error_no_ack_to_send;
        }
    }    
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
        ("inside ack send read_cntl->last_ack is %d last_ack_ack is %d\n",
        handle->read_cntl->last_ack, handle->read_cntl->last_ack_ack));
        
    /*  
     * Send out the ACK only if has not been received by the writer before           */ 
    last_ack_ack = handle->read_cntl->last_ack_ack; 
            
    if (((last_ack > last_ack_ack) && (last_ack - last_ack_ack <
        GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)) || (last_ack
        < last_ack_ack - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
    {    
        int ack_seqno;
        int* data = (int*) globus_malloc (sizeof(int)*4);
        if (data == NULL)
        {
            goto error_data;
        }   
        handle->read_cntl->ack_seqno = (handle->read_cntl->ack_seqno + 1) %
            GLOBUS_L_XIO_UDT_MAX_ACK_SEQ_NO;
        /*
         * data ACK seq. no., RTT, data receiving rate (packets per second),
         * and estimated link capacity (packets per second) 
         */
        data[0] = last_ack;
        data[1] = handle->rtt;
        data[2] = globus_l_xio_udt_get_pkt_arrival_speed(
            handle->read_history);
        data[3] = globus_l_xio_udt_get_bandwidth(handle->read_history);
        ack_seqno = handle->read_cntl->ack_seqno;
        *((int*)iovec[0].iov_base) |= ack_seqno;
        iovec[1].iov_base = data;
        iovec[1].iov_len = sizeof(int) * 4;
        globus_l_xio_udt_store_ack_record(handle, ack_seqno, last_ack);
        GlobusTimeAbstimeGetCurrent(handle->read_cntl->last_ack_time);
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
            ("ack sent for %d and the ack_seqno is %d\n",
            last_ack, ack_seqno));
        globus_fifo_enqueue(&handle->cntl_write_q, iovec);
        if (handle->write_pending == GLOBUS_FALSE)
        {
            handle->write_pending = GLOBUS_TRUE;
            globus_i_xio_udt_write(handle);
        }
    }

    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExit();
    return;

error_iovec:
error_header:
error_data:
error_no_ack_to_send:
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExitWithError();
    return;

}



static
void
globus_l_xio_udt_write_nak_timer_expired(
    globus_l_handle_t *                          handle)
{
    globus_xio_iovec_t*                          iovec;
    int                                          num_seq;
    int                                          length[2];
    int*                                         data;

    GlobusXIOName(globus_l_xio_udt_write_nak_timer_expired);
    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&handle->write_mutex);

    iovec = (globus_xio_iovec_t*) globus_malloc(sizeof(globus_xio_iovec_t) * 2);
    if (iovec == NULL)
    {
        goto error_iovec;
    }
    iovec[0].iov_base = globus_malloc(GLOBUS_L_XIO_UDT_HEADER_SIZE);
    if (iovec[0].iov_base == NULL)
    {
        goto error_header;
    }
    iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;

    /* Set (bit-0 = 1) and (bit-1~3 = type) */

    *((int*)iovec[0].iov_base) = 0x80000000 | (GLOBUS_L_XIO_UDT_NAK << 28);
        
    num_seq = handle->payload_size/sizeof(int);
    data = (int*) globus_malloc (sizeof(int)*num_seq);
        
    if (!data)
    {   
        goto error_data;
    }       
    globus_l_xio_udt_get_reader_loss_array(
        handle->reader_loss_info, data, length, num_seq,
        handle->rtt);
    if (length[0] > 0)
    {       
        iovec[1].iov_base = data;
        iovec[1].iov_len = length[1] * sizeof(int);
        *((int*)iovec[0].iov_base) |= length[0];
    }
    else
    {
        globus_free(data);
        goto error_no_nak_to_send;
    }

    globus_fifo_enqueue(&handle->cntl_write_q, iovec);
    if (handle->write_pending == GLOBUS_FALSE)
    {
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExit();
    return;


error_iovec:
error_header:
error_data:
error_no_nak_to_send:
    globus_mutex_unlock(&handle->write_mutex);   
    GlobusXIOUdtDebugExitWithError();            
    return;                                      

}   
    

void
globus_l_xio_udt_write_nak(
    globus_l_handle_t *                 handle,
    int                                 start_seq,
    int                                 end_seq)
{   
    globus_xio_iovec_t*                 iovec;
    int                                 loss_length;
    int*                                loss_data;
        
    GlobusXIOName(globus_l_xio_udt_write_nak);
    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&handle->write_mutex);

    iovec = (globus_xio_iovec_t*) globus_malloc(sizeof(globus_xio_iovec_t) * 2);
    if (iovec == NULL)
    {
        goto error_iovec;
    }
    iovec[0].iov_base = globus_malloc(GLOBUS_L_XIO_UDT_HEADER_SIZE);
    if (iovec[0].iov_base == NULL)
    {
        goto error_header;
    }
    loss_data = (int*) globus_malloc(sizeof(int)*2);
    if (loss_data == NULL)
    {
        goto error_loss_data;
    }

    iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;

    /* Set (bit-0 = 1) and (bit-1~3 = type) */

    *((int*)iovec[0].iov_base) = 0x80000000 | (GLOBUS_L_XIO_UDT_NAK << 28);

    globus_l_xio_udt_reader_loss_list_insert(
        handle->reader_loss_info,
        start_seq,
        end_seq);
    /*
     * pack loss list for NAK - most significant bit of a seqno in the loss
     * array indicates if the loss is a single pkt(msb = 0) or group of
     * consecutive pkts(msb = 1). If msb = 1 then next interger in the array
     * indicates the end seqno of the contiguous loss.
     */
    loss_data[0] = start_seq;
    loss_data[1] = end_seq;
    if (loss_data[0] != loss_data[1])
    {
        loss_data[0] |= 0x80000000;
    }
    loss_length = end_seq - start_seq + 1;
    if (loss_length < 0)
    {
        loss_length += GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
    }

    iovec[1].iov_base = loss_data;
    *((int*)iovec[0].iov_base) |= loss_length;
    iovec[1].iov_len = (loss_length > 1) ? 2 * sizeof(int)
        : sizeof(int);

    globus_fifo_enqueue(&handle->cntl_write_q, iovec);
    if (handle->write_pending == GLOBUS_FALSE)
    {
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExit();
    return;


error_iovec:
error_header:
error_loss_data:
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExitWithError();
    return;
    
}   
    
void    
globus_l_xio_udt_write_fin(
    globus_l_handle_t *                 handle)
{   
    globus_xio_iovec_t*                 iovec;
        
    GlobusXIOName(globus_l_xio_udt_write_fin);
    GlobusXIOUdtDebugEnter();
    
    globus_mutex_lock(&handle->write_mutex);
    
    iovec = (globus_xio_iovec_t*) globus_malloc(sizeof(globus_xio_iovec_t) * 2);
    if (iovec == NULL)
    {
        goto error_iovec;
    }   
    iovec[0].iov_base = globus_malloc(GLOBUS_L_XIO_UDT_HEADER_SIZE);
    if (iovec[0].iov_base == NULL)
    {
        goto error_header;
    }   
    iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
     
    /* Set (bit-0 = 1) and (bit-1~3 = type) */
    
    *((int*)iovec[0].iov_base) = 0x80000000 | (GLOBUS_L_XIO_UDT_FIN << 28);
    
    iovec[1].iov_base = NULL;
    iovec[1].iov_len = 0;
    
    if (handle->fin_count > GLOBUS_L_XIO_UDT_MAX_FIN_COUNT)
    {
        globus_l_xio_udt_pass_close(handle);
        globus_free(iovec[0].iov_base);
        iovec[0].iov_base = NULL;
    }
    else
    {
        if (handle->fin_count == 0) 
        { 
            globus_reltime_t period;
            GlobusTimeReltimeSet(period, 0, handle->rtt);
            globus_callback_register_periodic(
                &handle->fin_handle,
                &period,
                &period,
                globus_l_xio_udt_fin,
                handle);
        }
        ++handle->fin_count;
    }
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("snd FIN handle state is %d\n", handle->state));

    globus_fifo_enqueue(&handle->cntl_write_q, iovec);
    if (handle->write_pending == GLOBUS_FALSE)
    {
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExit();
    return;


error_iovec:
error_header:
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExitWithError();
    return;

}


static
void
globus_l_xio_udt_write_keepalive(
    globus_l_handle_t *                 handle)
{
    globus_xio_iovec_t*                 iovec;

    GlobusXIOName(globus_l_xio_udt_write_keepalive);
    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&handle->write_mutex);

    iovec = (globus_xio_iovec_t*) globus_malloc(sizeof(globus_xio_iovec_t) * 2);
    if (iovec == NULL)
    {
        goto error_iovec;
    }
    iovec[0].iov_base = globus_malloc(GLOBUS_L_XIO_UDT_HEADER_SIZE);
    if (iovec[0].iov_base == NULL)
    {
        goto error_header;
    }
    iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;

    /* Set (bit-0 = 1) and (bit-1~3 = type) */

    *((int*)iovec[0].iov_base) = 0x80000000 |
        (GLOBUS_L_XIO_UDT_KEEPALIVE << 28);

    iovec[1].iov_base = NULL;
    iovec[1].iov_len = 0;

    globus_fifo_enqueue(&handle->cntl_write_q, iovec);
    if (handle->write_pending == GLOBUS_FALSE)
    {
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExit();
    return;
    
error_iovec:
error_header:
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExitWithError();
    return;
    
}   
    

static
void
globus_l_xio_udt_write_ack_ack(
    globus_l_handle_t *                 handle,
    int                                 ack_seqno)
{   
    globus_xio_iovec_t*                 iovec;
 
    GlobusXIOName(globus_l_xio_udt_write_ack_ack);
    GlobusXIOUdtDebugEnter();
      
    globus_mutex_lock(&handle->write_mutex);
       
    iovec = (globus_xio_iovec_t*) globus_malloc(sizeof(globus_xio_iovec_t) * 2);
    if (iovec == NULL)
    {  
        goto error_iovec;
    }
    iovec[0].iov_base = globus_malloc(GLOBUS_L_XIO_UDT_HEADER_SIZE);
    if (iovec[0].iov_base == NULL)
    {
        goto error_header;
    }
    iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
    
    /* Set (bit-0 = 1) and (bit-1~3 = type) */
    
    *((int*)iovec[0].iov_base) = 0x80000000 | 
        (GLOBUS_L_XIO_UDT_ACK_ACK << 28);
    
    /* ACK packet seq. no. */
    *((int*)iovec[0].iov_base) |= ack_seqno;
    
    iovec[1].iov_base = NULL;
    iovec[1].iov_len = 0;

    globus_fifo_enqueue(&handle->cntl_write_q, iovec);
    if (handle->write_pending == GLOBUS_FALSE)
    {
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }
    globus_mutex_unlock(&handle->write_mutex); 
    GlobusXIOUdtDebugExit();
    return;
        
        
error_iovec:
error_header:
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExitWithError();
    return;

}


static
void
globus_l_xio_udt_write_fin_ack(
    globus_l_handle_t *                 handle)
{
    globus_xio_iovec_t*                 iovec;

    GlobusXIOName(globus_l_xio_udt_write_fin_ack);
    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&handle->write_mutex);

    iovec = (globus_xio_iovec_t*) globus_malloc(sizeof(globus_xio_iovec_t) * 2);
    if (iovec == NULL)
    {
        goto error_iovec;
    }
    iovec[0].iov_base = globus_malloc(GLOBUS_L_XIO_UDT_HEADER_SIZE);
    if (iovec[0].iov_base == NULL)
    {
        goto error_header;
    }
    iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;

    /* Set (bit-0 = 1) and (bit-1~3 = type) */

    *((int*)iovec[0].iov_base) = 0x80000000 |
        (GLOBUS_L_XIO_UDT_FIN_ACK << 28);

    iovec[1].iov_base = NULL;
    iovec[1].iov_len = 0;

    globus_fifo_enqueue(&handle->cntl_write_q, iovec);
    if (handle->write_pending == GLOBUS_FALSE)
    {
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExit();
    return;


error_iovec:
error_header:
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExitWithError();
    return;

}


static
void
globus_l_xio_udt_write_congestion_warning(
    globus_l_handle_t *                           handle)
{
    globus_xio_iovec_t*                           iovec;

    GlobusXIOName(globus_l_xio_udt_write_congestion_warning);
    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&handle->write_mutex);
    
    iovec = (globus_xio_iovec_t*) globus_malloc(sizeof(globus_xio_iovec_t) * 2);
    if (iovec == NULL)
    {
        goto error_iovec;               
    }
    iovec[0].iov_base = globus_malloc(GLOBUS_L_XIO_UDT_HEADER_SIZE);
    if (iovec[0].iov_base == NULL)
    {
        goto error_header;
    }
    iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
    
    /* Set (bit-0 = 1) and (bit-1~3 = type) */
        
    *((int*)iovec[0].iov_base) = 0x80000000 |
        (GLOBUS_L_XIO_UDT_CONGESTION_WARNING << 28);
    
    /* Header only, no control information */
    iovec[1].iov_base = NULL;
    iovec[1].iov_len = 0;
    
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
        ("congestion warning sent\n"));
    GlobusTimeAbstimeGetCurrent(handle->read_cntl->last_warning_time);
    
    globus_fifo_enqueue(&handle->cntl_write_q, iovec);
    if (handle->write_pending == GLOBUS_FALSE)
    {
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExit();
    return;
        
    
error_iovec:
error_header:
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExitWithError();
    return;

}
    
    
void
globus_l_xio_udt_process_ack(
    globus_l_handle_t*                  handle)
{
    int                                 ack_seqno;
    int                                 last_ack;
    int                                 prev_last_ack;
    int                                 payload_size;   
    GlobusXIOName(globus_l_xio_udt_process_ack);
    GlobusXIOUdtDebugEnter();                     

    /* read ACK seq. no. */
    ack_seqno = (*(int*)handle->read_iovec[0].iov_base) & 0x0000FFFF;
    /* write ACK for ACK */
    globus_l_xio_udt_write_ack_ack(handle, ack_seqno);
    /* Got data ACK */
    last_ack = *(int *)handle->read_iovec[1].iov_base;
    prev_last_ack = handle->write_cntl->last_ack;
    /* protect packet retransmission */
    globus_mutex_lock(&handle->write_cntl->mutex);
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
        ("ack rcvd for %d and ack_seqno is %d\n", last_ack, ack_seqno));
    /* acknowledge the writing buffer */
    if ((last_ack > prev_last_ack) && (last_ack -
        prev_last_ack < GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
    {
        payload_size = handle->payload_size;
        globus_l_xio_udt_update_write_ack_point(handle,
            (last_ack - prev_last_ack) * payload_size, payload_size);
    }
    else if (last_ack < prev_last_ack - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
    {
        payload_size = handle->payload_size;
        globus_l_xio_udt_update_write_ack_point(handle,
            (last_ack - prev_last_ack + GLOBUS_L_XIO_UDT_MAX_SEQ_NO) *
            payload_size, payload_size);
    }
    else
    {
        globus_mutex_unlock(&handle->write_cntl->mutex);
        goto error_repeated_ack;
        /* discard it if it is a repeated ACK */
    }

    /* update writing variables */
    handle->write_cntl->last_ack = last_ack;
    globus_l_xio_udt_writer_loss_list_remove(handle->writer_loss_info,
        (handle->write_cntl->last_ack - 1 + GLOBUS_L_XIO_UDT_MAX_SEQ_NO) %
        GLOBUS_L_XIO_UDT_MAX_SEQ_NO);
    /* last_ack indicates that reader has received upto last_ack - 1  */

    globus_mutex_unlock(&handle->write_cntl->mutex);

    /* Update RTT */
    if (handle->rtt == GLOBUS_L_XIO_UDT_SYN_INTERVAL)
    {
        handle->rtt = *((int *)handle->read_iovec[1].iov_base + 1);
    }
    else
    {
        handle->rtt = (handle->rtt * 7 +
            *((int *)handle->read_iovec[1].iov_base + 1)) >> 3;
    }

    /* Update Flow Window Size */
    globus_l_xio_udt_flow_control(handle,
        *((int *)handle->read_iovec[1].iov_base + 2));

    /* Update Estimated Bandwidth */
    if (*((int *)handle->read_iovec[1].iov_base + 3) != 0)
    {
        handle->bandwidth = (handle->bandwidth * 7 +
            *((int *)handle->read_iovec[1].iov_base + 3)) >> 3;
    }
    
    /* Wake up the waiting writer and correct the writing rate */
    if (handle->write_cntl->inter_pkt_interval > handle->rtt)
    {
        handle->write_cntl->inter_pkt_interval = handle->rtt;
    }
    globus_mutex_lock(&handle->write_mutex);
    if ((handle->pending_write_oneshot == GLOBUS_FALSE) &&
        (handle->write_pending == GLOBUS_FALSE))
    {   
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }   
    globus_mutex_unlock(&handle->write_mutex);
        
    GlobusXIOUdtDebugExit();
    return; 
    
error_repeated_ack:
    GlobusXIOUdtDebugExitWithError();
    return;
        
}           
            
    
void
globus_l_xio_udt_process_nak(
    globus_l_handle_t*                  handle)
{       
    int*                                losslist;
    int                                 i;
    int                                 m;
    int                                 lost_seq;
    int                                 last_dec_seq;
    int                                 local_loss = 0;
    GlobusXIOName(globus_l_xio_udt_process_nak);
    
    GlobusXIOUdtDebugEnter();
    
    /*Slow Start Stopped, if it is not */
    handle->write_cntl->slow_start = GLOBUS_FALSE;
    
    /*
     * Rate Control on Loss - If the writer is writing pkt 1000, when it
     * receives loss NAK of pkt 500. The LastDecSeq is 1000. The writer
     * then will decrease the writing rate by 1/9. However, it can receive
     * more NAKs like 510, 520, etc. The problem is should the writer
     * decrease the writing rate at all NAKs. Clearly it cannot make sure
     * if the rate decrease at NAK 500 is enough to clear the congestion.
     * Since pkt 1000 has been sent out, any NAKs less than 1000 cannot
     * tell the writer this information. If the writer receives another
     * NAK larger than 1000, say 1010, then it knows the decrease at 500
     * is not enough and another decrease should be made. This is the
     * significance of LastDecSeq. However, this assumption is reasonable,
     * but it is also dangrous because it is too optimistic a stratagy.
     * If too many NAKs comes, the writer should decrease the rate even
     * they are less than LastDecSeq. The variable of DecCount decides how
     * many NAKs can cause a further rate decrease.
     */ 
            
    losslist = (int *)(handle->read_iovec[1].iov_base);
    lost_seq = losslist[0] & 0x7FFFFFFF;
    /*
     * the lock is for freeze, inter_pkt_interval and local_loss as they
     * are updated in either rate_control (called by globus_l_xio_udt_ack)
     * or write thread
     */
    globus_mutex_lock(&handle->write_cntl->mutex);
    last_dec_seq = handle->write_cntl->last_dec_seq;
    if (((lost_seq > last_dec_seq) && ((lost_seq - last_dec_seq) <
        GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)) || (lost_seq
        < (last_dec_seq - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)))
    {
        handle->write_cntl->inter_pkt_interval =
            handle->write_cntl->inter_pkt_interval *
            1.125;
        handle->write_cntl->last_dec_seq = handle->write_cntl->curr_seqno;
        handle->write_cntl->freeze = GLOBUS_TRUE;
        handle->write_cntl->nak_count = 1;
        handle->write_cntl->dec_count = 4;
    }
    else if (++ handle->write_cntl->nak_count >=
            pow(2.0, handle->write_cntl->dec_count))
    {
        handle->write_cntl->dec_count ++;
        handle->write_cntl->inter_pkt_interval =
            handle->write_cntl->inter_pkt_interval *
            1.125;
    }

    /* decode loss list message and insert loss into the writer loss list */
    for (i = 0, m = handle->read_iovec[1].iov_len/sizeof(int); i < m; i ++)
    {
        if ((losslist[i] & 0x80000000) && ((losslist[i] & 0x7FFFFFFF) >=
            handle->write_cntl->last_ack))
        {
            local_loss +=
                globus_l_xio_udt_writer_loss_list_insert(
                    handle->writer_loss_info, losslist[i] & 0x7FFFFFFF,
                    losslist[i + 1]);
            i++;
        }
        else if (losslist[i] >= handle->write_cntl->last_ack)
        {
            local_loss +=
                globus_l_xio_udt_writer_loss_list_insert(
                    handle->writer_loss_info, losslist[i], losslist[i]);
        }
    }
    handle->write_cntl->local_loss += local_loss;

    globus_mutex_unlock(&handle->write_cntl->mutex);

    globus_mutex_lock(&handle->write_mutex);
    if ((handle->pending_write_oneshot == GLOBUS_FALSE) &&
        (handle->write_pending == GLOBUS_FALSE))
    {
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }
    globus_mutex_unlock(&handle->write_mutex);
    /*
     * In case there is only one loss, then a seq with same start and end
     * seqno. is inserted into the loss list
     */
     
    GlobusXIOUdtDebugExit(); 
    return;
}    
    
    
void    
globus_l_xio_udt_process_fin(
    globus_l_handle_t*                  handle)
{       
            
    GlobusXIOName(globus_l_xio_udt_process_fin);
    GlobusXIOUdtDebugEnter();
        
    globus_mutex_lock(&handle->state_mutex);
    if (handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
    {
        handle->state = GLOBUS_L_XIO_UDT_CLOSE_WAIT;
        globus_l_xio_udt_write_fin_ack(handle);
    }
    else if (handle->state == GLOBUS_L_XIO_UDT_FIN_WAIT1)
    {   
        globus_reltime_t timeout;
        handle->state = GLOBUS_L_XIO_UDT_CLOSING;
        globus_l_xio_udt_write_fin_ack(handle);
        GlobusTimeReltimeSet(timeout, 0,
            2 * GLOBUS_L_XIO_UDT_CLOSE_TIMEOUT);
        globus_callback_register_oneshot(&handle->fin_close_handle,
            &timeout, globus_l_xio_udt_fin_close, handle);
    }   
    else if (handle->state == GLOBUS_L_XIO_UDT_FIN_WAIT2)
    {   
        globus_reltime_t timeout;
        handle->state = GLOBUS_L_XIO_UDT_TIME_WAIT;
        globus_l_xio_udt_write_fin_ack(handle);
        GlobusTimeReltimeSet(timeout, 0, GLOBUS_L_XIO_UDT_CLOSE_TIMEOUT);
        globus_callback_unregister(handle->fin_close_handle,
            NULL, NULL, NULL);
        globus_callback_register_oneshot(NULL,
            &timeout, globus_l_xio_udt_pass_close, handle);
    }       
    else if (handle->state == GLOBUS_L_XIO_UDT_CLOSING)
    {               
        globus_l_xio_udt_write_fin_ack(handle);
    }
    globus_mutex_unlock(&handle->state_mutex);
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("rcv FIN handle state is %d\n", handle->state));
    globus_mutex_lock(&handle->read_buf->mutex);
    if (handle->read_buf->user_buf_size > 0)
    {
        int nbytes = 0;
        int i;
        for (i = handle->read_buf->user_buf_ack->iovec_num - 1; i >= 0; --i)
        {
            nbytes += handle->read_buf->user_iovec[i].iov_len;
        }       
        nbytes += handle->read_buf->user_buf_ack->base_ptr;
        handle->read_buf->pending_finished_read = GLOBUS_TRUE;
        handle->read_buf->result = GlobusXIOErrorEOF();
        handle->read_buf->nbytes = nbytes;
        handle->read_buf->user_buf_size = 0;
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("rcv FIN nbytes %d\n", nbytes));

    }
    globus_mutex_unlock(&handle->read_buf->mutex);
    if (handle->write_buf->size > 0)
    {
        handle->write_buf->nbytes = handle->write_buf->size -
            handle->write_buf->curr_buf_size;
        handle->write_buf->pending_finished_write = GLOBUS_TRUE;
        handle->write_buf->result = GlobusXIOUdtErrorBrokenConnection();
    }

    GlobusXIOUdtDebugExit();
    return;
}

void
globus_l_xio_udt_process_congestion_warning(
    globus_l_handle_t*                           handle)
{

    GlobusXIOName(globus_l_xio_udt_process_congestion_warning);
    GlobusXIOUdtDebugEnter();

    /*
     * Slow Start Stopped, if it is not - not need any lock here coz
     * no 2 differents update this variable. Its updated in 2 locations
     * in process_cntl and once in flow_control but flow_control is called
     * from process_cntl
     */
    handle->write_cntl->slow_start = GLOBUS_FALSE;

    globus_mutex_lock(&handle->write_cntl->mutex);

    /* One way packet delay is increasing, so decrease the writing rate */
    handle->write_cntl->inter_pkt_interval =
        (int)ceil(handle->write_cntl->inter_pkt_interval * 1.125);

    globus_mutex_unlock(&handle->write_cntl->mutex);

    handle->write_cntl->last_dec_seq = handle->write_cntl->curr_seqno;
    handle->write_cntl->nak_count = 1;
    handle->write_cntl->dec_count = 4;


    GlobusXIOUdtDebugExit();
    return;
}

void
globus_l_xio_udt_process_ack_ack(
    globus_l_handle_t*                  handle)
{
    int                                 rtt;
    int                                 last_ack_ack;
    int                                 prev_last_ack_ack;
    GlobusXIOName(globus_l_xio_udt_process_ack_ack);
    GlobusXIOUdtDebugEnter();
        
    /* update RTT */
    rtt = globus_l_xio_udt_calculate_rtt_and_last_ack_ack(handle,
            (*(int*)handle->read_iovec[0].iov_base) & 0x0000FFFF,
            &last_ack_ack);
    
    if (rtt > 0)
    {
        globus_abstime_t                    curr_time;
        globus_reltime_t                    warning_interval;
        int                                 warning_interval_usec;
        
        globus_l_xio_udt_record_recent_rtt_pct_pdt(handle->read_history,
            rtt);
    
        /* check packet delay trend */
        GlobusTimeAbstimeGetCurrent(curr_time);
        GlobusTimeAbstimeDiff(warning_interval, curr_time,
            handle->read_cntl->last_warning_time);
        GlobusTimeReltimeToUSec(warning_interval_usec, warning_interval);
        if (globus_l_xio_udt_get_delay_trend(handle->read_history) &&
            (warning_interval_usec > handle->rtt * 2))  
        {
            globus_l_xio_udt_write_congestion_warning(handle);
        }
    
        /* RTT EWMA */
        if (handle->rtt == GLOBUS_L_XIO_UDT_SYN_INTERVAL)
        {       
            handle->rtt = rtt;
        } 
        else
        {
            handle->rtt = (handle->rtt * 7 + rtt) >> 3;
        }
        prev_last_ack_ack = handle->read_cntl->last_ack_ack;

        /* update last ACK that has been received by the writer */ 
        if (((prev_last_ack_ack < last_ack_ack) &&
            (last_ack_ack - prev_last_ack_ack < 
            GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
            || (prev_last_ack_ack > last_ack_ack + 
            GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
        {
            handle->read_cntl->last_ack_ack = last_ack_ack;
        }
    }

    GlobusXIOUdtDebugExit();
    return;
}


void
globus_l_xio_udt_process_fin_ack(       
    globus_l_handle_t*                  handle)
{   

    GlobusXIOName(globus_l_xio_udt_process_fin_ack);
    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&handle->state_mutex);
    if (handle->state == GLOBUS_L_XIO_UDT_FIN_WAIT1)
    {
        globus_reltime_t timeout;
        handle->state = GLOBUS_L_XIO_UDT_FIN_WAIT2;
        GlobusTimeReltimeSet(timeout, 0,
            2 * GLOBUS_L_XIO_UDT_CLOSE_TIMEOUT);
        globus_callback_register_oneshot(&handle->fin_close_handle,
            &timeout, globus_l_xio_udt_fin_close, handle);
    }
    else if (handle->state == GLOBUS_L_XIO_UDT_CLOSING)
    {
        globus_reltime_t timeout;
        handle->state = GLOBUS_L_XIO_UDT_TIME_WAIT;
        GlobusTimeReltimeSet(timeout, 0, GLOBUS_L_XIO_UDT_CLOSE_TIMEOUT);
        globus_callback_unregister(handle->fin_close_handle,
            NULL, NULL, NULL);
        globus_callback_register_oneshot(NULL,
            &timeout, globus_l_xio_udt_pass_close, handle);
    }
    else if (handle->state == GLOBUS_L_XIO_UDT_LAST_ACK)
    {
        globus_callback_unregister(handle->fin_close_handle,
            NULL, NULL, NULL);
        globus_l_xio_udt_pass_close(handle);
    }
    globus_mutex_unlock(&handle->state_mutex);
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("rcv FIN_ACK handle state is %d\n", handle->state));

    GlobusXIOUdtDebugExit();
    return;
}

void    
globus_l_xio_udt_ack(
    void*                       user_arg)
{           
    globus_l_handle_t*          handle;
    GlobusXIOName(globus_l_xio_udt_ack);
                
    GlobusXIOUdtDebugEnter();
                    
    handle = (globus_l_handle_t*) user_arg;
    if (handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
    {   
        globus_mutex_lock(&handle->read_cntl->mutex);
        if (handle->read_cntl->curr_seqno >= handle->read_cntl->last_ack_ack)
        {               
             globus_l_xio_udt_write_ack(handle);
        }
        handle->read_cntl->nak_interval = handle->rtt;
        /* do not resent the loss report within too short period */
        if (handle->read_cntl->nak_interval < GLOBUS_L_XIO_UDT_SYN_INTERVAL)
        {       
            handle->read_cntl->nak_interval = GLOBUS_L_XIO_UDT_SYN_INTERVAL;
        }       
        {
            globus_reltime_t nak_period;
            GlobusTimeReltimeSet(nak_period, 0,
                handle->read_cntl->nak_interval);
            globus_callback_adjust_period(handle->nak_handle, &nak_period);
        }
        /* Periodical rate control. */
        if (handle->write_cntl->local_write > 0)
        {
            globus_l_xio_udt_rate_control(handle);
        }
        globus_mutex_unlock(&handle->read_cntl->mutex);
    }
    else
    {
        globus_callback_unregister(handle->ack_handle, NULL, NULL, NULL);
    }
    globus_mutex_lock(&handle->read_buf->mutex);
    if (handle->read_buf->pending_finished_read)
    {
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
            ("read finished nbytes = %d\n", handle->read_buf->nbytes));
            handle->read_buf->pending_finished_read = GLOBUS_FALSE;
        globus_mutex_unlock(&handle->read_buf->mutex);
        /* 
         * As a rule of thumb, no action should wait for the finished read or
         * write or open to come back. So we should unlock any mutex before
         * calling finished read/write ...
         */
        globus_xio_driver_finished_read(handle->user_read_op,
            handle->read_buf->result, handle->read_buf->nbytes);
    }   
    else
    {
        globus_mutex_unlock(&handle->read_buf->mutex);
    }
    GlobusXIOUdtDebugExit();
}
                                        


void
globus_l_xio_udt_nak(
    void*                       user_arg)
{
    globus_l_handle_t*          handle;
    GlobusXIOName(globus_l_xio_udt_nak);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    if (handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
    {
        globus_mutex_lock(&handle->read_cntl->mutex);
        if (handle->read_cntl->curr_seqno >= handle->read_cntl->last_ack_ack)
        {
            if (handle->reader_loss_info->length > 0)
            {
                /* NAK timer expired, and there is loss to be reported. */
                globus_l_xio_udt_write_nak_timer_expired(handle);
            }
        }
        globus_mutex_unlock(&handle->read_cntl->mutex);
    }
    else
    {
        globus_callback_unregister(handle->nak_handle, NULL, NULL, NULL);
    }
    GlobusXIOUdtDebugExit();
}


void
globus_l_xio_udt_exp(
    void*                       user_arg)
{
    globus_l_handle_t*          handle;
    GlobusXIOName(globus_l_xio_udt_exp);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    if (handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
    {
        globus_abstime_t                curr_time;
        globus_reltime_t                diff;
        int                             diff_usec;
        int                             writer_loss_length;

        globus_mutex_lock(&handle->read_cntl->mutex);
        GlobusTimeAbstimeGetCurrent(curr_time);
        GlobusTimeAbstimeDiff(diff, curr_time,
            handle->read_cntl->time_last_heard);
        GlobusTimeReltimeToUSec(diff_usec, diff);

        globus_mutex_lock(&handle->writer_loss_info->mutex);
        writer_loss_length = handle->writer_loss_info->length;
        globus_mutex_unlock(&handle->writer_loss_info->mutex);

        /*
         * If writer's loss list is not empty, the reader may probably waiting
         * for the retransmission (so it didn't send any ACK or NAK). The
         * writer should clear the loss list before it activates any EXP.
         */
    
        if ((diff_usec > handle->read_cntl->exp_interval) &&
           (writer_loss_length == 0))
        {
            /* Haven't received any information from the peer, it is dead?! */
            if (handle->read_cntl->exp_count > handle->max_exp_count)
            {
                /* Connection is broken. */
                GlobusXIOUdtDebugPrintf(
                    GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
                    ("close - peer dead\n"));
                globus_mutex_lock(&handle->state_mutex);        
                handle->state = GLOBUS_L_XIO_UDT_PEER_DEAD;
                globus_mutex_unlock(&handle->state_mutex);
            }
            else
            {   
                /*
                 * A general EXP event - Insert all the packets sent after last
                 * received acknowledgement into the writer loss list.
                 */
                if (((handle->write_cntl->curr_seqno + 1) %
                    GLOBUS_L_XIO_UDT_MAX_SEQ_NO)
                    != handle->write_cntl->last_ack) 
                {
                    globus_l_xio_udt_writer_loss_list_insert(
                        handle->writer_loss_info, handle->write_cntl->last_ack,
                        handle->write_cntl->curr_seqno);
                    globus_mutex_lock(&handle->write_mutex);
                    if ((handle->pending_write_oneshot == GLOBUS_FALSE) &&
                        (handle->write_pending == GLOBUS_FALSE))
                    {
                        handle->write_pending = GLOBUS_TRUE;
                        globus_i_xio_udt_write(handle);
                    }
                    globus_mutex_unlock(&handle->write_mutex);
                }
                else
                {
                    globus_l_xio_udt_write_keepalive(handle);
                }
    
                ++ handle->read_cntl->exp_count;
                handle->read_cntl->exp_interval =
                    (handle->read_cntl->exp_count * handle->rtt +
                    GLOBUS_L_XIO_UDT_SYN_INTERVAL);
                GlobusTimeAbstimeCopy(handle->read_cntl->time_last_heard,
                    curr_time);
            } 
        }
        globus_mutex_unlock(&handle->read_cntl->mutex);
    }   
    else
    {   
        globus_callback_unregister(handle->exp_handle, NULL, NULL, NULL);
    }   

    GlobusXIOUdtDebugExit();
}


static
void
globus_l_xio_udt_fin(
    void*                       user_arg)
{
    globus_l_handle_t*          handle;
    GlobusXIOName(globus_l_xio_udt_fin);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    globus_mutex_lock(&handle->state_mutex);
    if (handle->state == GLOBUS_L_XIO_UDT_FIN_WAIT1)
    {
        globus_l_xio_udt_write_fin(handle);
    }
    else
    {
        globus_callback_unregister(handle->fin_handle, NULL, NULL, NULL);
    }
    globus_mutex_unlock(&handle->state_mutex);
    GlobusXIOUdtDebugExit();
}


void
globus_l_xio_udt_fin_close(
    void*                       user_arg)
{
    globus_l_handle_t*          handle;
    GlobusXIOName(globus_l_xio_udt_fin);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    globus_mutex_lock(&handle->state_mutex);
    if ((handle->state == GLOBUS_L_XIO_UDT_FIN_WAIT2) ||
        (handle->state == GLOBUS_L_XIO_UDT_CLOSING) ||
        (handle->state == GLOBUS_L_XIO_UDT_LAST_ACK))
    {
        globus_l_xio_udt_pass_close(handle);
    }

    globus_mutex_unlock(&handle->state_mutex);
    GlobusXIOUdtDebugExit();
}

