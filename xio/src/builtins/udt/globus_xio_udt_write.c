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
globus_result_t
globus_l_xio_udt_add_write_buf(
    globus_l_xio_udt_write_buf_t*       write_buf,
    const char*                         data,
    int                                 len);

static
int
globus_l_xio_udt_read_data_to_transmit(
    globus_l_xio_udt_write_buf_t*       write_buf,
    const char**                        data,
    int                                 len);

static
int
globus_l_xio_udt_read_retransmit_data(
    globus_l_xio_udt_write_buf_t*               write_buf,
    const char**                                data,
    int                                         offset,
    int                                         len);

static
int
globus_l_xio_udt_writer_loss_list_insert_predicate(
    void*                               		datum,
    void*                               		user_arg);

static
int
globus_l_xio_udt_writer_loss_list_relation(
    void*                                       low_datum,
    void*                                       high_datum,
    void*                                       args);

static
int
globus_l_xio_udt_get_first_writer_lost_seq(
    globus_l_xio_udt_writer_loss_info_t*         writer_loss_info);

static
void
globus_l_xio_udt_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
void
globus_i_xio_udt_pass_write(
    globus_l_handle_t*          handle);

static
void
globus_i_xio_udt_write_retransmit_data(
    globus_l_handle_t*                          handle,
    int                                         seqno);

static
void
globus_i_xio_udt_write_data(
    globus_l_handle_t*          handle);

static
void
globus_l_xio_udt_write_data(
    void*                       user_arg);

      /*
       * Functionality:
       *  Insert a user buffer into the udt write buffer.
       * Parameters:
       *  1) [in] write_buf: udt write buffer
       *  2) [in] data: pointer to the user data block.
       *  3) [in] len: size of the block.
       * Returned value:
       *  None. 
       */

static
globus_result_t 
globus_l_xio_udt_add_write_buf(
    globus_l_xio_udt_write_buf_t*       write_buf,
    const char*                         data,
    int                                 len)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_add_write_buf);
    
    GlobusXIOUdtDebugEnter();

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
                ("udt add_write_buf -- len = %d\n", len));
    /* 
     *  write_buf->lock is acquired before this routine is
     *  called in udt_write
     */ 
    if (write_buf->first_blk == NULL)
    {
        /* Insert a block to the empty list */
    
        write_buf->first_blk = (globus_l_xio_udt_write_data_blk_t*)
            globus_malloc(sizeof(globus_l_xio_udt_write_data_blk_t));
        if (write_buf->first_blk == NULL)
        {
            result = GlobusXIOErrorMemory("write_buf");
            goto error_write_buf;
        }
        write_buf->first_blk->data = data;
        write_buf->first_blk->length = len;
        write_buf->first_blk->next = NULL;
        write_buf->last_blk = write_buf->first_blk;
        write_buf->curr_write_blk = write_buf->first_blk;
        write_buf->curr_write_pnt = 0;
        write_buf->curr_ack_blk = write_buf->first_blk;
        write_buf->curr_ack_pnt = 0;
    }
    else
    {
        /* Insert a new block to the tail of the list */
    
        write_buf->last_blk->next = (globus_l_xio_udt_write_data_blk_t*)
            globus_malloc(sizeof(globus_l_xio_udt_write_data_blk_t));
        if (write_buf->last_blk->next == NULL)
        {
            result = GlobusXIOErrorMemory("write_buf");
            goto error_write_buf;
        }
        write_buf->last_blk = write_buf->last_blk->next;
        write_buf->last_blk->data = data;
        write_buf->last_blk->length = len;
        write_buf->last_blk->next = NULL;
        if (write_buf->curr_write_blk == NULL)
        {
            write_buf->curr_write_blk = write_buf->last_blk;
        }
    }

    write_buf->size += len;
    write_buf->curr_buf_size += len;

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error_write_buf:
    GlobusXIOUdtDebugExitWithError();
    return result;

}


      /*
       *  Functionality:
       *    Find data position to pack a DATA packet from the furthest reading
       *    point.
       *  Parameters:
       *    1) [in] write_buf: udt write buffer
       *    2) [in] data: pointer to the pointer of the data position.
       *    3) [in] len: Expected data length.
       *  Returned value:
       *    Actual length of data read.
       */

static
int
globus_l_xio_udt_read_data_to_transmit(
    globus_l_xio_udt_write_buf_t*     write_buf,
    const char**                        data,
    int                                 len)
{
    int length_read = 0;
    GlobusXIOName(globus_l_xio_udt_read_data_to_transmit);

    GlobusXIOUdtDebugEnter();

    /*
     * proctected by mutex coz add_write_buf (called from the
     * globus_l_xio_udt_write updates the write blks and this routine is
     * called from globus_i_xio_udt_write (which runs as a seperate thread))
     */

    globus_mutex_lock(&write_buf->mutex);

    /* No data to read */
    if (write_buf->curr_write_blk != NULL)
    {
        int curr_write_pnt = write_buf->curr_write_pnt;
        /* Use a temporary variable to store the contents of variable
         * referenced by address (ie, variables using pointers). This holds
         * especially true for the contents of structures and arrays. This
         * allows the compiler to generate code that needs only to calculate
         * the data's address once, then stores the data for future use within
         * the function.
         */

        /* read data in the current writing block */
        if (curr_write_pnt + len < write_buf->curr_write_blk->length)
        {
            *data = write_buf->curr_write_blk->data + curr_write_pnt;
            write_buf->curr_write_pnt += len;
            length_read = len;
        }
        else
        {
            /*
             * Not enough data to read. Read an irregular packet and move the
             * current writing block pointer to the next block
             */

            length_read = write_buf->curr_write_blk->length -
                          curr_write_pnt;
            *data = write_buf->curr_write_blk->data + curr_write_pnt;
            write_buf->curr_write_blk = write_buf->curr_write_blk->next;
            write_buf->curr_write_pnt = 0;
        }

    }

    globus_mutex_unlock(&write_buf->mutex);
    GlobusXIOUdtDebugExit();
    return length_read;

}


      /*
       *  Functionality:
       *    Find data position to pack a DATA packet for a retransmission.
       *  Parameters:
       *    1) [in] write_buf: udt write buffer
       *    2) [in] data: pointer to the pointer of the data position.
       *    3) [in] offset: offset from the last ACK point.
       *    4) [in] len: Expected data length.
       *  Returned value:
       *    Actual length of data read.
       */

static
int
globus_l_xio_udt_read_retransmit_data(
    globus_l_xio_udt_write_buf_t*               write_buf,
    const char**                                data,
    int                                         offset,
    int                                         len)
{
    int length_read = 0;
    globus_l_xio_udt_write_data_blk_t *p;
    GlobusXIOName(globus_l_xio_udt_read_retransmit_data);

    GlobusXIOUdtDebugEnter();
    p = write_buf->curr_ack_blk;

    /*
     *  Locate to the data position by the offset
     *  offset is actually from curr_ack_pnt, so loffset gives the offset from
     *  beginning of the block i.e, curr_ack_blk->data. Also the offset is
     *  calculated assuming each pkt size = standard payload size ((1500 - 32)
     *  bytes) but it is not the case - if the block(i.e, the user provided
     *  data) is not a multiple of payload size then the last pkt of that block
     *  will be a irregular pkt with size < payload size, second line in the
     *  while below "loffset -= len - ((0 == write_buf->curr_ack_blk->length
     *  %len) ? len : (write_buf->curr_ack_blk->length % len))" takes care of
     *  that - since offset is calculated assuming all packets are of size
     *  equal to std. payload size - if there is an irregular pkt
     *  (write_buf->curr_ack_blk->length % len != 0 - note len is equal to
     *  standard payload size), it subtracts len - irregular pkt size from the
     *  offset
     */
    globus_mutex_lock(&write_buf->mutex);

    if (p != NULL)
    {
        int loffset;
        loffset = offset + write_buf->curr_ack_pnt;
        while ((p) && (p->length <= loffset))
        {
            loffset -= p->length;
            loffset -= len - ((0 == p->length % len) ?
                       len : (p->length % len));
            p = p->next;
        }
        if (p)
        {
            /* Read a regular data */
            if (loffset + len <= p->length)
            {
                *data = p->data + loffset;
                length_read = len;
            }
            else
            {
                /* Read an irregular data at the end of a block */
                *data = p->data + loffset;
                length_read =  p->length - loffset;
            }
        }
    }

    globus_mutex_unlock(&write_buf->mutex);
    GlobusXIOUdtDebugExit();
    return length_read;

}

      /*
       *  Functionality:
       *     Update the ACK point
       *  Parameters:
       *     1) [in] handle: udt handle
       *     2) [in] len: size of data acknowledged.
       *     3) [in] payloadsize: regular payload size that udt
       *             always try to read.
       *  Returned value:
       *     None.
       */

void
globus_l_xio_udt_update_write_ack_point(
    globus_l_handle_t*                          handle,
    int                                         len,
    int                                         payloadsize)
{
    int                                         length;
    int                                         temp;
    GlobusXIOName(globus_l_xio_udt_update_write_ack_point);

    GlobusXIOUdtDebugEnter();

    handle->write_buf->curr_ack_pnt += len;

    /* Remove the block if it is acknowledged */
    while ((handle->write_buf->curr_ack_blk) &&
        (handle->write_buf->curr_ack_pnt >=
        handle->write_buf->curr_ack_blk->length))
    {
        length = handle->write_buf->curr_ack_blk->length;
        handle->write_buf->curr_ack_pnt -= length;

        /*
         *  Update the size error between regular and irregular packets - again
         *  the subtracts that is done is becoz the len is calculated assuming
         *  all packets are regular (len = (ack seq received - last ack)*
         *  payload size) - as mentioned in the above subroutine - if there is
         *  an irregular packet then "payload size - irregular pkt size" is
         *  subtracted from ack_pnt
         */

        temp = length % payloadsize;
        if (temp != 0)
        {
            handle->write_buf->curr_ack_pnt -= payloadsize - temp;
        }

        handle->write_buf->curr_buf_size -= length;
        handle->write_buf->first_blk = handle->write_buf->curr_ack_blk->next;
        globus_free(handle->write_buf->curr_ack_blk);
        handle->write_buf->curr_ack_blk = handle->write_buf->first_blk;
    }

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
    ("update write ack -- write_buf_size = %d, len = %d, curr_buf_size = %d\n",
          handle->write_buf->size, len, handle->write_buf->curr_buf_size));

    /* write_buf->curr_buf_size indicates the size of unack'd data */
    if (handle->write_buf->curr_buf_size == 0)
    {
        handle->write_buf->first_blk = NULL;
        handle->write_buf->last_blk = NULL;
        handle->write_buf->curr_write_blk = NULL;
        handle->write_buf->curr_ack_blk = NULL;
        handle->write_buf->nbytes = handle->write_buf->size;
        handle->write_buf->result = GLOBUS_SUCCESS;
        handle->write_buf->pending_finished_write = GLOBUS_TRUE;
        handle->write_buf->size = 0;
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
           ("udt finished write -- nbytes = %d\n", handle->write_buf->size));
    }

    GlobusXIOUdtDebugExit();
    return;

}

static
int
globus_l_xio_udt_writer_loss_list_insert_predicate(
    void*                               		datum,
    void*                               		user_arg)
{   

    globus_l_xio_udt_writer_loss_seq_t * data1 =
        (globus_l_xio_udt_writer_loss_seq_t *) datum;
    globus_l_xio_udt_writer_loss_seq_t * data2 =
        (globus_l_xio_udt_writer_loss_seq_t *) user_arg;
    int start_seq1 = data1->start_seq;
    int start_seq2 = data2->start_seq;
    int end_seq1 = data1->end_seq;
    int end_seq2 = data2->end_seq;
    GlobusXIOName(globus_l_xio_udt_writer_loss_list_insert_predicate);

    /*
     * if there is any overlap between 2 seq (a,b) and (c,d) can be verified by
     * just checking if ((d < a) || (c > b)) since we know a < b and c < d. if
     * the condition in the "if" is GLOBUS_TRUE then there is no overlap and
     * otherwise there is overlap. The "less_than", "greater_than".. functions
     * take of wrap around situations. for eg assume max_seqno = 64,
     * seqno_thresh = 32 and if we have a seq (1,5) in the list and if the new
     * seq to add is (60,2) - there is an overlap here but if we just check if
     * ((2<1) || (60>5)) - we will conclude there is no overlap but actually
     * there - since we use the globus_l_xio_udt_less_than and
     * greater_than functions instead of < and > there wont be any problem.
     */
    
    if (globus_l_xio_udt_less_than(end_seq2, start_seq1) ||
        globus_l_xio_udt_greater_than(start_seq2, end_seq1))
    {
        return 0;
    }   
    return 1;
}       


      /* 
       *  Functionality:
       *     Insert a seq. no. into the writer loss list.
       *  Parameters:
       *     1) [in] writer_loss_info: writer loss information
       *     2) [in] seqno1: sequence number starts.
       *     3) [in] seqno2: sequence number ends.
       *  Returned value:
       *     number of packets that are not in the list previously.
       */

int
globus_l_xio_udt_writer_loss_list_insert(
    globus_l_xio_udt_writer_loss_info_t*        writer_loss_info,
    int                                         seqno1,
    int                                         seqno2)
{   
    globus_l_xio_udt_writer_loss_seq_t * lost_seq;
    globus_list_t * temp_list;
    globus_l_xio_udt_writer_loss_seq_t * temp_seq;
    int orig_length; 
    int length_added;
    GlobusXIOName(globus_l_xio_udt_writer_loss_list_insert);

    GlobusXIOUdtDebugEnter();

    lost_seq = (globus_l_xio_udt_writer_loss_seq_t *)
                globus_malloc(sizeof(globus_l_xio_udt_writer_loss_seq_t));
    globus_mutex_lock(&writer_loss_info->mutex);
    orig_length = writer_loss_info->length;
    lost_seq->start_seq = seqno1;
    lost_seq->end_seq = seqno2;
    temp_seq = NULL;
    /*
     * I need both the seqno for the predicate function otherwise i could have
     * avoided the allocation for lost_seq incase if there is an overlap
     */
    while ((temp_list = globus_list_search_pred(writer_loss_info->list,
      globus_l_xio_udt_writer_loss_list_insert_predicate, lost_seq)) != NULL)
    {
        temp_seq = (globus_l_xio_udt_writer_loss_seq_t *)
                    globus_list_first(temp_list);
        lost_seq->start_seq = globus_l_xio_udt_min_seqno(lost_seq->start_seq,
                                temp_seq->start_seq);
        lost_seq->end_seq = globus_l_xio_udt_max_seqno(lost_seq->end_seq,
                                temp_seq->end_seq);
        writer_loss_info->length += globus_l_xio_udt_get_length(
                                lost_seq->start_seq, temp_seq->start_seq) - 1;
        /*
         * -1 coz get_length gives b-a+1 temp_seq->start_seq is already
         * included in the length
         */
        writer_loss_info->length += globus_l_xio_udt_get_length(
                                temp_seq->end_seq, lost_seq->end_seq) - 1;
        /* -1 coz temp_seq->end_seq is already included in the length */
        globus_free(temp_seq);
        globus_list_remove(&writer_loss_info->list, temp_list);
    }
    /* there is no overlap */
    if (temp_seq == NULL)
    {
        writer_loss_info->length += globus_l_xio_udt_get_length(
                                lost_seq->start_seq, lost_seq->end_seq);
    }
    length_added = writer_loss_info->length - orig_length;
    globus_list_insert(&writer_loss_info->list, lost_seq);
    globus_mutex_unlock(&writer_loss_info->mutex);
    GlobusXIOUdtDebugExit();
    return length_added;
    /*
     * this variable is necessary because i dont want to access the shared
     * variable writer_loss_info after unlocking the mutex
     */

}


        /*
         *  Functionality
         *    Predicate for globus_l_xio_udt_writer_loss_list_remove. i.e,
         *    globus_l_xio_udt_writer_loss_list_remove uses this routine to
         *    check if there is anything to remove in the writer loss list
         *  Parameters:
         *    1) [in] datum: data present in the write loss list
         *    2) [in] user_arg: user provided argument (seqno)
         *  Returned value:
         *    1 if datum <= user_arg else 0
         */

int
globus_l_xio_udt_writer_loss_list_remove_predicate(
    void*                               datum,
    void*                               user_arg)
{

    globus_l_xio_udt_writer_loss_seq_t * data =
        (globus_l_xio_udt_writer_loss_seq_t *) datum;
    int* seqno = (int*) user_arg;
    GlobusXIOName(globus_l_xio_udt_writer_loss_list_remove_predicate);

    /*
     * since writer_loss_list_remove removes the sequences upto the seqno, u
     * return 1 if seqno is greater than end seq or if seqno lies between start
     * and end seq. If *seqno > data->end_seq then the whole seq has to be
     * removed else (*seqno <= data->end_seq but *seqno > data->start_seq)
     * either start or end has to be removed or there has to be a split
     */

    if (globus_l_xio_udt_not_less_than(*seqno, data->start_seq))
    {
        return 1;
    }
    return 0;
}


      /*
       *  Functionality:
       *     Remove ALL the seq. no. that are not greater than the parameter.
       *  Parameters:
       *     1) [in] writer_loss_info: writer loss information
       *     2) [in] seqno: sequence number.
       *  Returned value:
       *     None.
       */

void
globus_l_xio_udt_writer_loss_list_remove(
    globus_l_xio_udt_writer_loss_info_t*        writer_loss_info,
    int                                         seqno)
{
    globus_list_t * temp_list;
    globus_l_xio_udt_writer_loss_seq_t * temp_seq;
    GlobusXIOName(globus_l_xio_udt_writer_loss_list_remove);

    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&writer_loss_info->mutex);
    if (writer_loss_info->length > 0)
    {
        while ((temp_list = globus_list_search_pred(writer_loss_info->list,
            globus_l_xio_udt_writer_loss_list_remove_predicate, &seqno))
            != NULL)
        {
            temp_seq = (globus_l_xio_udt_writer_loss_seq_t *)
                            globus_list_first(temp_list);
            if (globus_l_xio_udt_greater_than(temp_seq->end_seq, seqno))
            { 
                writer_loss_info->length -= globus_l_xio_udt_get_length(
                                                temp_seq->start_seq, seqno);
                /* here get_length should return b-a+1 */
                temp_seq->start_seq = globus_l_xio_udt_inc_seqno(seqno);
                /* start_seq == end_seq if there is only one seqno in a node */
            }                           
            else
            {
                writer_loss_info->length -= globus_l_xio_udt_get_length(
                                        temp_seq->start_seq, temp_seq->end_seq);
                /* here again the get length should return b-a+1 */
    
                globus_free(temp_seq);
                globus_list_remove(&writer_loss_info->list, temp_list);
            }
        }
    }
    globus_mutex_unlock(&writer_loss_info->mutex);
     
    GlobusXIOUdtDebugExit();
    return;
}   
    
        
      /*
       *  Functionality:
       *     This is a relation function used to find the minimum element in a
       *     list. This used by the globus_list_min function (see the
       *     globus_l_xio_udt_get_first_writer_lost_seq(..) function below)
       *  Parameters:
       *     1) low_datum: a data in the list
       *     2) high_datum: another data in the list 
       *     3) args: NULL
       *  Returned value:
       *     1 if low_datum is less than high_datum 0 otherwise
       */ 
       
static 
int
globus_l_xio_udt_writer_loss_list_relation(
    void*                       		low_datum,
    void*                       		high_datum,
    void*                       		args)
{   

    globus_l_xio_udt_writer_loss_seq_t * data1 =
        (globus_l_xio_udt_writer_loss_seq_t *) low_datum;
    globus_l_xio_udt_writer_loss_seq_t * data2 = 
        (globus_l_xio_udt_writer_loss_seq_t *) high_datum;
    GlobusXIOName(globus_l_xio_udt_writer_loss_list_relation);

    if (globus_l_xio_udt_less_than(data1->start_seq, data2->start_seq))
    {
        return 1;
    }   
    return 0;
            
}       
            
      /*  
       *  Functionality:
       *     Read the first (smallest) loss seq. no. in the list and remove it.
       *  Parameters:
       *     None. 
       *  Returned value: 
       *     The seq. no. or -1 if the list is empty.
       */

static
int 
globus_l_xio_udt_get_first_writer_lost_seq(      
    globus_l_xio_udt_writer_loss_info_t*         writer_loss_info)
{   
    globus_list_t* temp_list;
    globus_l_xio_udt_writer_loss_seq_t * temp_seq;
    int seqno = -1; 
    GlobusXIOName(globus_l_xio_udt_get_first_writer_lost_seq);
    
    GlobusXIOUdtDebugEnter();
    
    globus_mutex_lock(&writer_loss_info->mutex);
    if (writer_loss_info->length > 0)
    {   
        temp_list = globus_list_min(writer_loss_info->list, 
                        globus_l_xio_udt_writer_loss_list_relation, NULL);
        temp_seq = (globus_l_xio_udt_writer_loss_seq_t*)
                        globus_list_first(temp_list);
        seqno = temp_seq->start_seq;
        temp_seq->start_seq = globus_l_xio_udt_inc_seqno(temp_seq->start_seq);
        if (globus_l_xio_udt_greater_than(temp_seq->start_seq,
                temp_seq->end_seq))
        {   
            globus_list_remove(&writer_loss_info->list, temp_list);
            globus_free(temp_seq);
        }
        --writer_loss_info->length;
    }
    globus_mutex_unlock(&writer_loss_info->mutex);
    
    GlobusXIOUdtDebugExit();
    return seqno;
}

      /*
       *  Functionality:
       *     write callback - schedules the next write operation at the
       *     appropriate time (the time interval between 2 consecutive  
       *     writes is determined by handle->write_cntl->inter_pkt_interval 
       *     and handle->write_cntl->freeze 
       *  Parameters: 
       *     1) [in] op: xio operation 
       *     2) [in] result: indicates the result of read operation
       *     3) [in] nbytes: number of bytes read
       *     4) [in] user_arg: udt driver handle
       *  Returned value:
       *     None.
       */
      
static
void     
globus_l_xio_udt_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{        
    globus_l_handle_t*                  handle;
    GlobusXIOName(globus_l_xio_udt_write_cb);
         
    GlobusXIOUdtDebugEnter();
         
    handle = (globus_l_handle_t*) user_arg;
             
    globus_mutex_lock(&handle->write_mutex);
             
    handle->write_handle = GLOBUS_NULL_HANDLE;
             
    if (handle->cntl_write_iovec[0].iov_base != NULL)
    {        
        globus_free(handle->cntl_write_iovec[0].iov_base);
        handle->cntl_write_iovec[0].iov_base = NULL;
        if ((handle->cntl_write_iovec[1].iov_base != NULL) &&
            (handle->cntl_write_iovec[1].iov_base != handle->handshake))
        {
            globus_free(handle->cntl_write_iovec[1].iov_base);
        }    
        handle->cntl_write_iovec[0].iov_base = NULL;
    }        
    else         
    {        
        globus_mutex_lock(&handle->write_cntl->mutex);
        handle->write_cntl->local_write ++;
        globus_mutex_unlock(&handle->write_cntl->mutex);  
    }            
    if (!globus_fifo_empty(&handle->cntl_write_q))
    {            
        globus_i_xio_udt_write(handle);
    }        
    else if (handle->pending_write_oneshot == GLOBUS_FALSE)
    {  
      if (0 == handle->write_cntl->curr_seqno %
        GLOBUS_L_XIO_UDT_PROBE_INTERVAL)
      {  
         /* writes out probing packet pair */
             globus_i_xio_udt_write(handle);
      }  

    /*
     * freeze, inter_pkt_interval, curr_seqno dont need locks coz there is no
     * write conflict and we dont care if the thread that reads these values
     * read the old or updated value. I was concerned about the memory
     * alignment i.e, if the alignment is not proper then if the thread that
     * update those values might get swapped out when the update is only done
     * partially (say only 2 bytes out of the 4 byte integer is written. But
     * gcc compiler might take of the alignment. in that case we are fine as
     * long as the variable is less than or equal to that size of the machine
     * word.
     */

      else if (handle->write_cntl->freeze == GLOBUS_TRUE)
      {
         globus_abstime_t curr_time;
         globus_reltime_t wait, diff;
         int diff_usec, wait_usec;
         globus_mutex_lock(&handle->write_cntl->mutex);
         handle->write_cntl->freeze = GLOBUS_FALSE;
         globus_mutex_unlock(&handle->write_cntl->mutex);
         /* writing is frozen! */
         /* do a globus_callback_register_oneshot here */
         GlobusTimeAbstimeGetCurrent(curr_time);
         GlobusTimeAbstimeDiff(diff, curr_time,
             handle->write_cntl->next_write_time);
         GlobusTimeReltimeToUSec(diff_usec, diff);
         if (globus_abstime_cmp(&handle->write_cntl->next_write_time,
             &curr_time) == 1)
         {
             wait_usec = GLOBUS_L_XIO_UDT_SYN_INTERVAL + diff_usec;
             GlobusTimeReltimeSet(wait, 0, wait_usec);
             GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
                 ("write oneshot delay = %d\n", wait_usec));
             handle->write_pending = GLOBUS_FALSE;
             handle->pending_write_oneshot = GLOBUS_TRUE;
             globus_callback_register_oneshot(&handle->write_handle, &wait,
                 globus_l_xio_udt_write_data, handle);
         }
         else
         {
             wait_usec = GLOBUS_L_XIO_UDT_SYN_INTERVAL - diff_usec;
             if (wait_usec <= 0)
             {
                 globus_i_xio_udt_write(handle);
             }
             else
             {
                 GlobusTimeReltimeSet(wait, 0, wait_usec);
                 handle->write_pending = GLOBUS_FALSE;
                 handle->pending_write_oneshot = GLOBUS_TRUE;
                 globus_callback_register_oneshot(&handle->write_handle,
                     &wait, globus_l_xio_udt_write_data, handle);
             }
         }
      }
      else
      {
         globus_abstime_t curr_time;

         /* wait for an inter-packet time. */
         /* register another oneshot here */
         GlobusTimeAbstimeGetCurrent(curr_time);
         if (globus_abstime_cmp(&handle->write_cntl->next_write_time,
             &curr_time) == 1)
         {
             globus_reltime_t wait, diff;
             int diff_usec, wait_usec; 
     
             GlobusTimeAbstimeDiff(diff, curr_time,  
                 handle->write_cntl->next_write_time);
             GlobusTimeReltimeToUSec(diff_usec, diff);
             wait_usec = handle->write_cntl->inter_pkt_interval - diff_usec;
             GlobusTimeReltimeSet(wait, 0, wait_usec);
             GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
                 ("write oneshot delay = %d\n", wait_usec));
             handle->write_pending = GLOBUS_FALSE;
             handle->pending_write_oneshot = GLOBUS_TRUE;
             globus_callback_register_oneshot(&handle->write_handle, &wait,
                 globus_l_xio_udt_write_data, handle);
         }
         else
         {
             globus_i_xio_udt_write(handle);
         }
      }  
    }    
    else     
    {    
        handle->write_pending = GLOBUS_FALSE;
    }             
    globus_mutex_unlock(&handle->write_mutex);
    GlobusXIOUdtDebugExit();
}            
             
                 
static       
void         
globus_i_xio_udt_pass_write(
    globus_l_handle_t*          handle)
{        
    globus_reltime_t            inter_pkt_interval;
    int                         i;
    int                         payload_size;   
    globus_result_t             result;
             
    GlobusXIOName(globus_i_xio_udt_pass_write);
             
    GlobusXIOUdtDebugEnter();
             
    /* Record the next write time */
    GlobusTimeReltimeSet(inter_pkt_interval, 0,
        handle->write_cntl->inter_pkt_interval)
    GlobusTimeAbstimeInc(handle->write_cntl->next_write_time,
        inter_pkt_interval);
    payload_size = handle->data_write_iovec[1].iov_len;
    do   
    { 
        result = globus_xio_driver_pass_write(
            handle->driver_write_op,
            handle->data_write_iovec,
            2,
            payload_size + GLOBUS_L_XIO_UDT_HEADER_SIZE,
            globus_l_xio_udt_write_cb,
            handle);
         i++;
     }
     while ((globus_error_errno_match(globus_error_peek(result),
          GLOBUS_XIO_MODULE, ECONNREFUSED)) && i < MAX_COUNT);

    if (result != GLOBUS_SUCCESS)
    {
        GlobusXIOUdtDebugPrintf(
          GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
          ("data pass write failed: [%s]\n",
          globus_error_print_chain(
          globus_error_peek(result))));
        goto error;
    }

    GlobusXIOUdtDebugExit();
    return;

error:
    handle->write_pending = GLOBUS_FALSE;
    GlobusXIOUdtDebugExitWithError();
    return;

}


static
void
globus_i_xio_udt_write_retransmit_data(
    globus_l_handle_t*                          handle,
    int                                         seqno)
{
    int                                         payload_size;
    int                                         offset;

    GlobusXIOName(globus_i_xio_udt_write_retransmit_data);

    GlobusXIOUdtDebugEnter();
    /*
     * protect write_cntl->last_ack from updating by ACK
     * processing
     */
    globus_mutex_lock(&handle->write_cntl->mutex);
    if ((seqno >= handle->write_cntl->last_ack) && (seqno <
        handle->write_cntl->last_ack +
        GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
    {
        offset = (seqno - handle->write_cntl->last_ack) * handle->payload_size;
    }
    else if (seqno < handle->write_cntl->last_ack -
        GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
    {
        offset = (seqno + GLOBUS_L_XIO_UDT_MAX_SEQ_NO -
            handle->write_cntl->last_ack) * handle->payload_size;
    }
    else
    {
        GlobusXIOUdtDebugPrintf(
            GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
            ("Retransmit failed. seqno is [%d], "
            "write_cntl->last_ack is [%d]\n", seqno,
            handle->write_cntl->last_ack));
        globus_mutex_unlock(&handle->write_cntl->mutex);
        goto error;
    }
    payload_size = globus_l_xio_udt_read_retransmit_data(
        handle->write_buf,
        (const char**)&handle->data_write_iovec[1].iov_base,
        offset,
        handle->payload_size);
    globus_mutex_unlock(&handle->write_cntl->mutex);
          
    if (payload_size > 0)
    {     
        *(int*)handle->data_write_iovec[0].iov_base = seqno;
        handle->data_write_iovec[1].iov_len = payload_size;
        globus_i_xio_udt_pass_write(handle);
    }
    else
    {
        handle->write_pending = GLOBUS_FALSE;
        GlobusXIOUdtDebugPrintf(
            GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
            ("payload_size is zero"));
    }
    GlobusXIOUdtDebugExit();
    return;

error:
    handle->write_pending = GLOBUS_FALSE;
    GlobusXIOUdtDebugExitWithError();
    return;
}   

    
    
static
void
globus_i_xio_udt_write_data(
    globus_l_handle_t*          handle)
{   
    int                         payload_size;   
    GlobusXIOName(globus_i_xio_udt_write_data);
     
    GlobusXIOUdtDebugEnter();
    payload_size = globus_l_xio_udt_read_data_to_transmit(
        handle->write_buf,
        (const char**)&handle->data_write_iovec[1].iov_base,
        handle->payload_size);
    if (payload_size > 0) 
    {
        handle->write_cntl->curr_seqno =
            (handle->write_cntl->curr_seqno + 1) %
            GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
        *(int*)handle->data_write_iovec[0].iov_base = 
            handle->write_cntl->curr_seqno; 
        handle->data_write_iovec[1].iov_len =
            payload_size;
        globus_i_xio_udt_pass_write(handle);
    }   
    else    
    {       
        handle->write_pending = GLOBUS_FALSE; 
        GlobusXIOUdtDebugPrintf(
            GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
            ("payload_size is zero"));
    }
    GlobusXIOUdtDebugExit();
}


      /*
       *  Functionality:
       *     oneshot callback - writes the appropriate data (in the user buf)
       *     - retransmit data have higher priority
       *  Parameters:
       *     1) [in] user_arg: udt driver handle
       *  Returned value:
       *     None.
       */

void
globus_i_xio_udt_write(
    globus_l_handle_t*          handle)
{
    GlobusXIOName(globus_i_xio_udt_write);

    GlobusXIOUdtDebugEnter();

    if ((handle->state != GLOBUS_L_XIO_UDT_CLOSED) &&
        (handle->state != GLOBUS_L_XIO_UDT_PEER_DEAD))
    {

        if (!globus_fifo_empty(&handle->cntl_write_q))
        {
            globus_size_t wait_for;
            handle->cntl_write_iovec =
                (globus_xio_iovec_t*)globus_fifo_dequeue(
                                        &handle->cntl_write_q);
            wait_for = handle->cntl_write_iovec[0].iov_len +
                       handle->cntl_write_iovec[1].iov_len;
            if (globus_xio_driver_pass_write(
                    handle->driver_write_op,
                    handle->cntl_write_iovec,
                    2,
                    wait_for,
                    globus_l_xio_udt_write_cb,
                    handle) != GLOBUS_SUCCESS)
            {
                GlobusXIOUdtDebugPrintf(
                    GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
                    ("cntl pass write failed \n"));
                goto error;
            }
        }
        else if (handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
        {
            int seqno;
            /* Loss retransmission always has higher priority. */
            if ((seqno = globus_l_xio_udt_get_first_writer_lost_seq(
                            handle->writer_loss_info)) >= 0)
            {
                globus_i_xio_udt_write_retransmit_data(handle, seqno);
            }
            /* If no loss, pack a new packet. */
            else if (((handle->write_cntl->curr_seqno -
                    handle->write_cntl->last_ack + 1 +
                    GLOBUS_L_XIO_UDT_MAX_SEQ_NO) %
                    GLOBUS_L_XIO_UDT_MAX_SEQ_NO) <
                    handle->flow_wnd_size)
            {
                globus_i_xio_udt_write_data(handle);
            }
            else
            {
                handle->write_pending = GLOBUS_FALSE;
                GlobusXIOUdtDebugPrintf(
                    GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
                    ("flow window exceeded"));
            }
        }
        else
        {
            handle->write_pending = GLOBUS_FALSE;
        }              
    }
    else
    {
        handle->write_pending = GLOBUS_FALSE;
    }
    GlobusXIOUdtDebugExit();
    return;
        
error:
    handle->write_pending = GLOBUS_FALSE;
    GlobusXIOUdtDebugExitWithError();
    return;
}           

static      
void                   
globus_l_xio_udt_write_data(
    void*                       user_arg)
{                   
    globus_l_handle_t*          handle;
    GlobusXIOName(globus_l_xio_udt_write_data);
                    
    GlobusXIOUdtDebugEnter();
            
    handle = (globus_l_handle_t*) user_arg;
    globus_mutex_lock(&handle->write_mutex);
    handle->pending_write_oneshot = GLOBUS_FALSE;  
    if (handle->write_pending == GLOBUS_FALSE)
    {       
        handle->write_pending = GLOBUS_TRUE;
        globus_i_xio_udt_write(handle);
    }   
    globus_mutex_unlock(&handle->write_mutex);
            
    GlobusXIOUdtDebugExit();
}


      /*
       *  Functionality:
       *     This gets called when user calls globus_xio_write. adds the data
       *     (buffer) provided by the user to the write buffer and
       *     fires a oneshot to do the actual writing
       *  Parameters:
       *     1) [in] driver_handle: udt driver handle
       *     2) [in] iovec: user's vector
       *     3) [in] iovec_count: vector count
       *     4) [in] op: xio operation
       *  Returned value:
       *     GLOBUS_SUCCESS
       */

globus_result_t
globus_l_xio_udt_write(
    void *                                       driver_specific_handle,
    const globus_xio_iovec_t *                   iovec,
    int                                          iovec_count,
    globus_xio_operation_t                       op)
{

    globus_l_handle_t*                           handle;
    globus_result_t                              result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_udt_write);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t *) driver_specific_handle;

    if (handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
    {
        int i;
        globus_mutex_lock(&handle->write_buf->mutex);
        for (i = 0; i < iovec_count; i++)
        {
            globus_l_xio_udt_add_write_buf(handle->write_buf,
                iovec[i].iov_base, iovec[i].iov_len);
        }
        handle->user_write_op = op;
        globus_mutex_unlock(&handle->write_buf->mutex);
        if (handle->first_write == GLOBUS_TRUE)
        {
            GlobusTimeAbstimeGetCurrent(handle->write_cntl->next_write_time);
            handle->first_write = GLOBUS_FALSE;
        }
        globus_l_xio_udt_write_data(handle);
    }
    else
    {
        result = GlobusXIOUdtErrorBrokenConnection();
    }

    GlobusXIOUdtDebugExit();
    return result;
}

void
globus_l_xio_udt_finish_write(
    void*                       user_arg)
{
    globus_l_handle_t*          handle;
    GlobusXIOName(globus_l_xio_udt_finish_write);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    globus_xio_driver_finished_write(handle->user_write_op,
        handle->write_buf->result, handle->write_buf->nbytes);

    GlobusXIOUdtDebugExit();
}
 
