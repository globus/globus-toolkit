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

extern globus_xio_stack_t globus_l_xio_udt_server_stack;
extern globus_xio_driver_t globus_l_xio_udt_udp_driver;
extern globus_xio_driver_t globus_l_xio_udt_server_udp_driver;

extern globus_l_attr_t globus_l_xio_udt_attr_default;

static
globus_result_t
globus_l_xio_udt_handle_init(
    globus_l_handle_t *                 handle);

static
void
globus_l_xio_udt_open_failed(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

static
void
globus_l_xio_udt_write_handshake(
    globus_l_handle_t*         	        handle);

static
void
globus_l_xio_udt_rewrite_handshake(
    void*                               user_arg);

static
void
globus_l_xio_udt_finished_open(
    void*                               user_arg);

static
void
globus_l_xio_udt_read_handshake_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
void
globus_l_xio_udt_cancel_read_handshake(
    void*                                  user_arg);

static
void
globus_l_xio_udt_write_handshake_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
void
globus_l_xio_udt_server_write_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
void
globus_l_xio_udt_server_write(
    globus_l_handle_t *                         handle);

static
void
globus_l_xio_udt_server_write_handshake(
    globus_l_handle_t *                         handle);

static
void
globus_l_xio_udt_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

static
globus_result_t
globus_l_xio_udt_set_udp_attributes(
    globus_xio_operation_t              op,
    const globus_l_attr_t *             attr);

static
int
globus_l_xio_udt_priority_q_cmp_func(
    void *                              priority_1,
    void *                              priority_2);

static
void
globus_l_xio_udt_server_read_cb(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg);


      /*
       *  Functionality:
       *     initialize driver handle
       *  Parameters:
       *     1) [in] handle: udt driver handle
       *  Returned value:
       *     GLOBUS_SUCCESS if initialization is successful
       *     otherwise a result object with an error
       */

static
globus_result_t
globus_l_xio_udt_handle_init(
    globus_l_handle_t *                handle)
{
    globus_result_t                    result;
    int                                res;
    GlobusXIOName(globus_l_xio_udt_handle_init);

    GlobusXIOUdtDebugEnter();

    /*
     * i'm trying to allocate space for read buf becoz the posiibility of
     * failure is high for this as it requires a huge space for the protocol
     * buffer
     */

    handle->read_buf = (globus_l_xio_udt_read_buf_t*)
        globus_malloc(sizeof(globus_l_xio_udt_read_buf_t));
    if(!handle->read_buf)
    {   
        result = GlobusXIOErrorMemory("read_buf");
        goto error_read_buf;
    }
    
    handle->read_buf->udt_buf = (globus_byte_t*)
        globus_malloc(handle->attr->protocolbuf);
    if(!handle->read_buf->udt_buf)
    {   
        result = GlobusXIOErrorMemory("read_buf");
        goto error_udt_buf;
    }
    
    handle->read_buf->user_buf_ack = (globus_l_xio_udt_user_buf_ack_t*)
        globus_malloc(sizeof(globus_l_xio_udt_user_buf_ack_t));
    if(!handle->read_buf->user_buf_ack)
    {   
        result = GlobusXIOErrorMemory("user_buf_ack");
        goto error_user_buf_ack;
    }
    /* 
     * need to allocate a buffer of size 4096000 for the protocol buffer -
     * but yet to determine source of the size parameter
     */
    
    handle->reader_loss_info = (globus_l_xio_udt_reader_loss_info_t*)
        globus_malloc(sizeof(globus_l_xio_udt_reader_loss_info_t));
    if(!handle->reader_loss_info)
    {   
        result = GlobusXIOErrorMemory("reader_loss_info");
        goto error_reader_loss_info;
    }

    handle->irregular_pkt_info = (globus_l_xio_udt_irregular_pkt_info_t*)
        globus_malloc(sizeof(globus_l_xio_udt_irregular_pkt_info_t));
    if(!handle->irregular_pkt_info)
    {
        result = GlobusXIOErrorMemory("irregular_pkt_info");
        goto error_irregular_pkt_info;
    }

    handle->read_history = (globus_l_xio_udt_read_history_t*)
        globus_malloc(sizeof(globus_l_xio_udt_read_history_t));
    if(!handle->read_history)
    {
        result = GlobusXIOErrorMemory("read_history");
        goto error_read_history;
    }

    handle->read_cntl = (globus_l_xio_udt_read_cntl_t*)
        globus_malloc(sizeof(globus_l_xio_udt_read_cntl_t));
    if(!handle->read_cntl)
    {
        result = GlobusXIOErrorMemory("read_cntl");
        goto error_read_cntl;
    }

    handle->write_buf = (globus_l_xio_udt_write_buf_t*)
        globus_malloc(sizeof(globus_l_xio_udt_write_buf_t));
    if(!handle->write_buf)
    {
        result = GlobusXIOErrorMemory("write_buf");
        goto error_write_buf;
    }

    handle->writer_loss_info = (globus_l_xio_udt_writer_loss_info_t*)
        globus_malloc(sizeof(globus_l_xio_udt_writer_loss_info_t));
    if(!handle->writer_loss_info)
    {
        result = GlobusXIOErrorMemory("writer_loss_info");
        goto error_writer_loss_info;
    }

    handle->write_cntl = (globus_l_xio_udt_write_cntl_t*)
        globus_malloc(sizeof(globus_l_xio_udt_write_cntl_t));
    if(!handle->write_cntl)
    {
        result = GlobusXIOErrorMemory("write_cntl");
        goto error_write_cntl;
    }

    /* 28 bytes for ip header and 4 bytes for udt header */
    handle->payload_size = handle->handshake->mss - 32;
    handle->payload = (globus_byte_t*) globus_malloc(handle->payload_size);
    if(!handle->payload)
    {
        result = GlobusXIOErrorMemory("payload");
        goto error_payload;
    }

    res = globus_fifo_init(&handle->cntl_write_q);
    if (res != 0)
    {
        goto error_cntl_write_q;
    }
    /* Initial window size is 2 packets */
    handle->flow_wnd_size = 2;  
    handle->rtt = 10 * GLOBUS_L_XIO_UDT_SYN_INTERVAL;
    handle->bandwidth = 1;
    handle->cancel_read_handle = GLOBUS_NULL_HANDLE;
    handle->driver_read_op = NULL;
    handle->driver_write_op = NULL;
    handle->read_iovec[1].iov_base = NULL;
    globus_mutex_init(&handle->state_mutex, NULL);
    globus_mutex_init(&handle->write_mutex, NULL);
    handle->first_write = GLOBUS_TRUE;
    handle->write_pending = GLOBUS_FALSE;
    handle->pending_write_oneshot = GLOBUS_FALSE;
    handle->write_handle = GLOBUS_NULL_HANDLE;
    
    handle->write_cntl->nak_count = 0;
    handle->write_cntl->last_ack = 0;
    handle->write_cntl->local_write = 0;
    handle->write_cntl->local_loss = 0;
    handle->write_cntl->curr_seqno = -1;
    handle->write_cntl->loss_rate = 0.0;
    handle->write_cntl->last_dec_seq = -1;
    handle->write_cntl->dec_count = 1;
    handle->write_cntl->freeze = GLOBUS_FALSE;
    handle->write_cntl->slow_start = GLOBUS_TRUE;
    handle->write_cntl->inter_pkt_interval = 1; 
    globus_mutex_init(&handle->write_cntl->mutex, NULL);
    
    handle->read_cntl->last_ack = 0;
    handle->read_cntl->last_ack_ack = 0;
    handle->read_cntl->ack_seqno = -1;
    handle->read_cntl->curr_seqno = -1;
    handle->read_cntl->next_expect = 0;
    handle->read_cntl->exp_count = 0;
    globus_mutex_init(&handle->read_cntl->mutex, NULL);
    {
        char *exp_count_env;
        handle->max_exp_count = GLOBUS_L_XIO_UDT_MAX_EXP_COUNT;
        exp_count_env = globus_module_getenv(
            "GLOBUS_UDT_PEER_DEAD_INTERVAL");
        if (exp_count_env)
        {
            handle->max_exp_count = atoi(exp_count_env);
        }
    }   
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
                ("max exp count = %d\n", handle->max_exp_count));
    handle->read_cntl->next_slot_found = GLOBUS_FALSE;
    GlobusTimeAbstimeGetCurrent(handle->read_cntl->last_ack_time);
    GlobusTimeAbstimeGetCurrent(handle->read_cntl->last_warning_time);
    GlobusTimeAbstimeGetCurrent(handle->read_cntl->time_last_heard);  
    handle->read_cntl->nak_interval = handle->rtt;
    handle->read_cntl->exp_interval = 11 * GLOBUS_L_XIO_UDT_SYN_INTERVAL;
        
    handle->read_buf->start_pos = 0;
    handle->read_buf->last_ack_pos = 0;
    handle->read_buf->max_offset = 0;
    handle->read_buf->udt_buf_size = handle->attr->protocolbuf;
    handle->read_buf->user_buf = GLOBUS_FALSE;
    handle->read_buf->user_buf_size = 0;
    handle->read_buf->into_udt_buf = GLOBUS_FALSE;
    handle->read_buf->pending_finished_read = GLOBUS_FALSE;
    handle->read_buf->nbytes = 0;
    globus_mutex_init(&handle->read_buf->mutex, NULL);

    handle->write_buf->first_blk = NULL;
    handle->write_buf->last_blk = NULL;
    handle->write_buf->curr_write_blk = NULL;
    handle->write_buf->curr_ack_blk = NULL;
    handle->write_buf->size = 0;
    handle->write_buf->curr_buf_size = 0;
    handle->write_buf->pending_finished_write = GLOBUS_FALSE;
    handle->write_buf->nbytes = 0;
    globus_mutex_init(&handle->write_buf->mutex, NULL);

    handle->irregular_pkt_info->length = 0;
    handle->reader_loss_info->length = 0;
    handle->writer_loss_info->length = 0;
    handle->irregular_pkt_info->list = NULL;
    handle->writer_loss_info->list = NULL;
    handle->reader_loss_info->list = NULL;
    globus_mutex_init(&handle->writer_loss_info->mutex, NULL);
    handle->ack_window = NULL;

    handle->read_history->pkt_window_ptr = 0;
    handle->read_history->rtt_window_ptr = 0;
    handle->read_history->probe_window_ptr = 0;
    {
        int i;
        /*
         * To take advantage of the fact that most target processors will
         * provide decrement-and-branch-if-zero type functionality into their
         * instruction sets.
         */
        for (i = GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE - 1; i >= 0; --i)
        {
            handle->read_history->pkt_window[i] = 0;
            handle->read_history->rtt_window[i] = 0;
            handle->read_history->pct_window[i] = 0;
            handle->read_history->pdt_window[i] = 0;
        }
    }
    GlobusTimeAbstimeGetCurrent(handle->read_history->last_arr_time);
    {
        globus_reltime_t ack_period, nak_period, exp_period;
        GlobusTimeReltimeSet(ack_period, 0, GLOBUS_L_XIO_UDT_SYN_INTERVAL);
        GlobusTimeReltimeSet(nak_period, 0, handle->read_cntl->nak_interval);
        GlobusTimeReltimeSet(exp_period, 0, handle->read_cntl->exp_interval);
        globus_callback_register_periodic(
            &handle->ack_handle,
            &ack_period,
            &ack_period,
            globus_l_xio_udt_ack,
            handle);
        globus_callback_register_periodic(
            &handle->nak_handle,
            &nak_period,
            &nak_period,
            globus_l_xio_udt_nak,
            handle);
        globus_callback_register_periodic(
            &handle->exp_handle,
            &exp_period,
            &exp_period,        
            globus_l_xio_udt_exp,
            handle);
    }
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
    
error_cntl_write_q:
    globus_free(handle->payload);
error_payload:
    globus_free(handle->write_cntl);
error_write_cntl:
    globus_free(handle->writer_loss_info);
error_writer_loss_info:
    globus_free(handle->write_buf);    
error_write_buf:
    globus_free(handle->read_cntl);
error_read_cntl:
    globus_free(handle->read_history);
error_read_history:
    globus_free(handle->irregular_pkt_info);    
error_irregular_pkt_info:
    globus_free(handle->reader_loss_info);
error_reader_loss_info:
    globus_free(handle->read_buf->user_buf_ack);
error_user_buf_ack: 
    globus_free(handle->read_buf->udt_buf);
error_udt_buf:
    globus_free(handle->read_buf);
error_read_buf:
    GlobusXIOUdtDebugExitWithError();
    return result;
         
}       
      /*
       *  Functionality:
       *     Takes care of things that need to be done if open fails
       *  Parameters:
       *     1) [in] op: open operation
       *     2) [in] result: indicates the result of open operation
       *     3) [in] handle: udt driver handle
       *  Returned value:
       *     None.
       */

static
void
globus_l_xio_udt_open_failed(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_handle_t*                  handle;
    globus_result_t                     res;
    GlobusXIOName(globus_l_xio_udt_open_failed);
    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    res = GlobusXIOUdtErrorOpenFailed();
    globus_xio_driver_finished_open(handle, op, res);
    globus_free(handle->read_iovec[1].iov_base);
    globus_free(handle->cntl_write_iovec);
    globus_free(handle->attr);
    globus_free(handle->handshake);
    globus_free(handle);

    GlobusXIOUdtDebugExit();
}

static
void
globus_l_xio_udt_write_handshake(
    globus_l_handle_t*  	        handle)
{
    int wait_for;
    globus_result_t result;
    globus_xio_iovec_t* iovec;
    GlobusXIOName(globus_l_xio_udt_write_handshake);
    GlobusXIOUdtDebugEnter();

    iovec = (globus_xio_iovec_t*) globus_malloc(sizeof(globus_xio_iovec_t));
    iovec[0].iov_base = handle->handshake;
    iovec[0].iov_len = sizeof(globus_l_xio_udt_handshake_t);
    wait_for = iovec[0].iov_len;
    result = globus_xio_driver_pass_write(handle->open_op,
        iovec, 1, wait_for,
        globus_l_xio_udt_write_handshake_cb, handle);
    if (result != GLOBUS_SUCCESS)
        goto error;
    GlobusXIOUdtDebugExit();
    return;

error:
    GlobusXIOUdtDebugExitWithError();
    return;
}

      /*
       *  Functionality:
       *     Rewrites handshake (called only by non-initiator if its read
       *     handshake timer times out)
       *  Parameters:
       *     1) [in] user_arg: udt driver handle
       *  Returned value:
       *     None.
       */   
    
static
void
globus_l_xio_udt_rewrite_handshake(
    void*                               user_arg)
{       
    globus_l_handle_t*                  handle;
    GlobusXIOName(globus_l_xio_udt_rewrite_handshake);
    
    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    if (handle->handshake_count < GLOBUS_L_XIO_UDT_MAX_HS_COUNT)
    {
        handle->handshake_count++;
        globus_l_xio_udt_write_handshake(handle);
    } 
    else  
    {        
        globus_xio_driver_pass_close(handle->open_op,
            globus_l_xio_udt_open_failed, handle);
    }  
       
    GlobusXIOUdtDebugExit();
}      
       


      /*
       *  Functionality:
       *     Initializes the handle and creates a new op to read data as this
       *     is called when a udt connection is opened
       *     successfully               
       *  Parameters:
       *     1) [in] user_arg: udt driver handle
       *  Returned value:               
       *     None.
       */

static
void
globus_l_xio_udt_finished_open(
    void*                               user_arg)
{   
    globus_l_handle_t*                  handle;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_finished_open);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    if (!handle->server)
    {
        unsigned char ipnum[GLOBUS_L_XIO_UDT_IP_LEN];
        char ipstr[GLOBUS_L_XIO_UDT_IP_LEN];
        char port[GLOBUS_L_XIO_UDT_IP_LEN];
        char* cs;
        int i;
       

        handle->handshake->mss = handle->remote_handshake->mss;
        handle->handshake->max_flow_wnd_size =
            handle->remote_handshake->max_flow_wnd_size;
        for (i = GLOBUS_L_XIO_UDT_IP_LEN - 1; i >= 0; --i)
        {
            ipnum[i] = (char)handle->remote_handshake->ip[i];
        }
        inet_ntop(AF_INET, ipnum, ipstr, GLOBUS_L_XIO_UDT_IP_LEN);
        sprintf(port, "%d", handle->remote_handshake->port);
        cs = globus_malloc(strlen(ipstr) + strlen(port) + 2);
        sprintf(cs, "%s:%s", ipstr, port);
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
        ("server contact(from handshake) = %s\n", cs));
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_CONNECT,
            cs);
        handle->remote_cs = cs;
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    else
    {
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("client contact (finished open) = %s\n", handle->remote_cs));
    }

    result = globus_l_xio_udt_handle_init(handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_udt_handle_init", result);
        globus_xio_driver_pass_close(handle->open_op,
            globus_l_xio_udt_open_failed, handle);
        goto error;
    }
    handle->state = GLOBUS_L_XIO_UDT_CONNECTED;
    globus_xio_driver_operation_create(&handle->driver_write_op,
        handle->driver_handle);
    globus_xio_driver_operation_create(&handle->driver_read_op,
        handle->driver_handle);
    handle->cntl_write_iovec[0].iov_base = NULL;
    handle->cntl_write_iovec[1].iov_base = NULL;
    globus_i_xio_udt_read(handle);
    globus_xio_driver_finished_open(handle, handle->open_op, GLOBUS_SUCCESS);

    GlobusXIOUdtDebugExit();
    return;

error:
    GlobusXIOUdtDebugExitWithError();
    return;

}



      /*
       *  Functionality:
       *     Callback for read handshake - initiator connects to the other side
       *     (using the contact info obtained from the handshake received) and
       *     writes the handshake data - non-initiator either rewrites the
       *     handshake or finishes open depending on the outcome of the read
       *     (either case it has to unregister the oneshot (timeout callback
       *     function))
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
globus_l_xio_udt_read_handshake_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{       
    globus_l_handle_t*                  handle;
    GlobusXIOName(globus_l_xio_udt_read_handshake_cb);
    
    GlobusXIOUdtDebugEnter();
        
    handle = (globus_l_handle_t*) user_arg;

    if (result != GLOBUS_SUCCESS)
    {
        globus_callback_unregister(handle->cancel_read_handle,
            globus_l_xio_udt_rewrite_handshake, handle, NULL);
    }           
    else
    {       
        globus_callback_unregister(handle->cancel_read_handle,
            globus_l_xio_udt_finished_open, handle, NULL);
    }
    
    GlobusXIOUdtDebugExit();
    return;
        
}   
    
    
    
static
void
globus_l_xio_udt_cancel_read_handshake(
    void*    		                   user_arg)
{
    globus_l_handle_t* handle = (globus_l_handle_t*) user_arg;
    GlobusXIOName(globus_l_xio_udt_cancel_read_handshake);

    GlobusXIOUdtDebugEnter();

    globus_xio_driver_operation_cancel(handle->driver_handle, handle->open_op);

    GlobusXIOUdtDebugExit();
}      


      /*
       *  Functionality:
       *     Callback for write handshake - on success, initiator - finishes
       *     open and do a pass_read, non-initiator - do a pass_read for
       *     handshake and registers a oneshot(to cancel this read) to be fired
       *     after a timeout. On failure, both initiator and non-initiator
       *     rewrites the handshake until the rewrite count exceeeds
       *     GLOBUS_L_XIO_UDT_MAX_HS_COUNT
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
globus_l_xio_udt_write_handshake_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_handle_t *                 handle;
    globus_xio_iovec_t                  iovec;
    int                                 wait_for;
    int                                 handshake_size;
    globus_reltime_t                    timeout;
    GlobusXIOName(globus_l_xio_udt_write_handshake_cb);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    handshake_size = sizeof(globus_l_xio_udt_handshake_t);
    handle->remote_handshake = (globus_l_xio_udt_handshake_t*)
        globus_malloc(handshake_size);
    iovec = handle->read_iovec[1];
    iovec.iov_base = handle->remote_handshake;
    iovec.iov_len = handshake_size;
    wait_for = handshake_size;
    result = globus_xio_driver_pass_read(
                op,
                &iovec,
                1,
                wait_for,
                globus_l_xio_udt_read_handshake_cb,
                handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    GlobusTimeReltimeSet(timeout, 2, handle->rtt);
    globus_callback_register_oneshot(
        &handle->cancel_read_handle,
        &timeout,
        globus_l_xio_udt_cancel_read_handshake,
        handle);

    GlobusXIOUdtDebugExit();
    return;
      
error: 
    globus_xio_driver_pass_close(op, globus_l_xio_udt_open_failed, handle);
    return;     
}      
       
       
       
static 
void   
globus_l_xio_udt_server_write_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_handle_t *                 handle;
    globus_l_server_t *                 server;
    GlobusXIOName(globus_l_xio_udt_server_write_cb);
    
    GlobusXIOUdtDebugEnter();           
    handle = (globus_l_handle_t*)user_arg;
    server = handle->server;            
    
    if (result != GLOBUS_SUCCESS)       
    {                                   
        goto error;
    }

    result = globus_xio_data_descriptor_destroy(server->write_data_desc);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_dd_destroy;
    }               
    if (handle->state == GLOBUS_L_XIO_UDT_PROCESSING)
    {
        globus_l_xio_udt_finished_open(handle);
    }
        
    globus_mutex_lock(&server->write_mutex);
                
    if (globus_fifo_empty(&server->handshake_write_q))
    {           
        server->write_pending = GLOBUS_FALSE;
    }           
    else        
    {
        globus_l_xio_udt_server_write(handle);
    }   
     
    globus_mutex_unlock(&server->write_mutex);
    
    GlobusXIOUdtDebugExit();
    return;
        
error_dd_destroy:
error:
    GlobusXIOUdtDebugExitWithError();
    return;


}



static
void
globus_l_xio_udt_server_write(
    globus_l_handle_t *                         handle)
{
    globus_l_xio_udt_handshake_t *              handshake;
    int                                         length;
    globus_l_server_t *                         server;
    globus_result_t                             result;
    GlobusXIOName(globus_l_xio_udt_server_write);

    GlobusXIOUdtDebugEnter();

    server = handle->server;
    handshake = globus_fifo_dequeue(&server->handshake_write_q);
    length = sizeof(globus_l_xio_udt_handshake_t);

    result = globus_xio_data_descriptor_init(
        &server->write_data_desc,
        server->xio_handle);

    if (result != GLOBUS_SUCCESS)
    {
        goto error_dd_init;
    }

    result = globus_xio_data_descriptor_cntl(
        server->write_data_desc,
        globus_l_xio_udt_server_udp_driver,
        GLOBUS_XIO_UDP_SET_CONTACT,
        handle->remote_cs);

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("client cs (server write) = %s, \n", handle->remote_cs));

    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_xio_register_write(
        server->xio_handle,
        (globus_byte_t*)handshake,
        length,
        length,
        server->write_data_desc,
        globus_l_xio_udt_server_write_cb,
        handle);

    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }


    GlobusXIOUdtDebugExit();
    return;

error_dd_init:
error:
    GlobusXIOUdtDebugExitWithError();
    return;

}

static
void
globus_l_xio_udt_server_write_handshake(
    globus_l_handle_t *                         handle)
{   
    globus_l_server_t *                         server;
    GlobusXIOName(globus_l_xio_udt_server_write_handshake);
    
    GlobusXIOUdtDebugEnter();
    
    server = handle->server;
    
    globus_mutex_lock(&server->write_mutex);
       
    globus_fifo_enqueue(&server->handshake_write_q, handle->handshake);
    if (!server->write_pending)         
    {   
        server->write_pending = GLOBUS_TRUE;
        globus_l_xio_udt_server_write(handle);
    }   
    
    globus_mutex_unlock(&server->write_mutex);
    
    GlobusXIOUdtDebugExit();
}   
        
        
      /*
       *  Functionality:
       *     open callback - on success, initiator - do a pass_read for
       *     handshake, non-initiator - write handshake. on failure
       *     finishes open (done in globus_l_xio_udt_open_failed)
       *  Parameters:
       *     1) [in] op: xio operation
       *     2) [in] result: indicates the result of read operation
       *     3) [in] user_arg: udt driver handle
       *  Returned value:
       *     None.
       */
        
static  
void    
globus_l_xio_udt_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_handle_t *                 handle;
    char *                              cs;
    char *                              port;
    unsigned char                       ip[GLOBUS_L_XIO_UDT_IP_LEN];
    int                                 i;
    GlobusXIOName(globus_l_xio_udt_open_cb);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t *) user_arg;
    if (result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }
    result = globus_xio_driver_handle_cntl(
        handle->driver_handle,
        globus_l_xio_udt_udp_driver,
        GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,
        &cs);

    if (result != GLOBUS_SUCCESS)
    {
        globus_xio_driver_pass_close(op, globus_l_xio_udt_open_failed,
            handle);
        goto error;
    }

    handle->handshake = (globus_l_xio_udt_handshake_t *)
        globus_malloc(sizeof(globus_l_xio_udt_handshake_t));
    if (!handle->handshake)
    {
        globus_xio_driver_pass_close(op, globus_l_xio_udt_open_failed,
            handle);
        goto error;
    }
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
        ("contact: %s\n", cs));
    port = strrchr(cs, ':');
    if(!port)
    {
        result = GlobusXIOErrorContactString("missing ':'");
        globus_xio_driver_pass_close(op, globus_l_xio_udt_open_failed,
            handle);
        goto error;
    }
    *port = 0;
    port++;
    handle->handshake->port = atoi(port);
    for (i = 0; i < GLOBUS_L_XIO_UDT_IP_LEN; i++)
        ip[i] = 0;
    inet_pton(AF_INET, cs, ip);
    for (i = 0; i < GLOBUS_L_XIO_UDT_IP_LEN; i++)
    {
        handle->handshake->ip[i] = (int)ip[i];
    }
    /*
     * i'm not allocating cs but it gets allocated in some function
     * call inside handle_cntl
     */
    globus_free(cs);

    handle->handshake->mss = handle->attr->mss;
    handle->handshake->max_flow_wnd_size = handle->attr->max_flow_wnd_size;

    if(handle->server)
    {
                                        
        if (handle->remote_handshake->mss < handle->handshake->mss)
        {
            handle->handshake->mss = handle->remote_handshake->mss;
        }
        if (handle->remote_handshake->max_flow_wnd_size <
            handle->handshake->max_flow_wnd_size)
        {
            handle->handshake->max_flow_wnd_size =
                handle->remote_handshake->max_flow_wnd_size;
        }
        globus_l_xio_udt_server_write_handshake(handle);
    }   
    else
    {   
        globus_l_xio_udt_write_handshake(handle);
    }
    GlobusXIOUdtDebugExit();
    return;
            
error_open:
    globus_l_xio_udt_open_failed(op, result, handle);
error:
    GlobusXIOUdtDebugExitWithError();
    return;
    
}   
        
            
static  
globus_result_t
globus_l_xio_udt_set_udp_attributes(
    globus_xio_operation_t              op,
    const globus_l_attr_t *             attr)
{   
    globus_result_t                     result;
    globus_l_attr_t *                   default_attr; 
    GlobusXIOName(globus_l_xio_udt_set_udp_attributes); 
            
    GlobusXIOUdtDebugEnter();
    
    result = globus_xio_driver_attr_cntl(
        op,
        globus_l_xio_udt_udp_driver,
        GLOBUS_XIO_UDP_SET_NO_IPV6,
        GLOBUS_TRUE);
    
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    default_attr = &globus_l_xio_udt_attr_default; 
     
    if (attr->handle != default_attr->handle)
    {           
        result = globus_xio_driver_attr_cntl(
            op, 
            globus_l_xio_udt_udp_driver, 
            GLOBUS_XIO_UDP_SET_HANDLE,
            attr->handle);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }

    if (attr->listener_serv != default_attr->listener_serv)
    {
        result = globus_xio_driver_attr_cntl(
            op,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_SET_SERVICE,
            attr->listener_serv);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }

    if (attr->bind_address != default_attr->bind_address)
    {
        result = globus_xio_driver_attr_cntl(
            op,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_SET_INTERFACE,
            attr->bind_address);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }


    if (attr->restrict_port != default_attr->restrict_port)
    {
        result = globus_xio_driver_attr_cntl(
            op,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_SET_RESTRICT_PORT,
            attr->restrict_port);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }


    if (attr->resuseaddr != default_attr->resuseaddr)
    {
        result = globus_xio_driver_attr_cntl(
            op,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_SET_REUSEADDR,
            attr->resuseaddr);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }

    result = globus_xio_driver_attr_cntl(
        op,
        globus_l_xio_udt_udp_driver,
        GLOBUS_XIO_UDP_SET_SNDBUF,
        attr->sndbuf); 
        
    if (result != GLOBUS_SUCCESS)
    {
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
            ("attr cntl - udp set sndbuf failed: [%s]\n",
             globus_error_print_chain(globus_error_peek(result))));
        goto error;
    }       
    result = globus_xio_driver_attr_cntl(
        op, 
        globus_l_xio_udt_udp_driver, 
        GLOBUS_XIO_UDP_SET_RCVBUF,
        attr->rcvbuf); 
    if (result != GLOBUS_SUCCESS)
    {
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
            ("attr cntl - udp set rcvbuf failed: [%s]\n",
             globus_error_print_chain(globus_error_peek(result))));
        goto error;
    }       
            
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
        
error:  
    GlobusXIOUdtDebugExitWithError();
    return result;
    
}

    
      /*
       *  Functionality:
       *     Does the first step in opening a udt connection - does some
       *     initialization and opens a udp connection
       *  Parameters:
       *     1) [in] driver_link: udt driver handle structure
       *     2) [in] driver_attr: udt driver attribute structure
       *     3) [in] op: xio operation
       *  Returned value:
       *     None.
       */

globus_result_t
globus_l_xio_udt_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{           
    globus_l_handle_t *                 handle;
    const globus_l_attr_t *             attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_open);
    
    GlobusXIOUdtDebugEnter();
    
    handle = (globus_l_handle_t *) driver_link;
    if(!handle)
    {   
        handle = (globus_l_handle_t *)
            globus_malloc(sizeof(globus_l_handle_t));
        if (!handle)
        {
            result = GlobusXIOErrorMemory("handle");
            goto error_handle;
        }
        handle->server = NULL;
    }

    attr = (globus_l_attr_t *)
        (driver_attr ? driver_attr : &globus_l_xio_udt_attr_default);

    result = globus_l_xio_udt_attr_copy((void**)&handle->attr, (void*)attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_udt_attr_copy", result);
        goto error_attr;
    }

    handle->handshake_count = 0;
    handle->fin_count = 0;
    handle->open_op = op;
    handle->read_iovec[0].iov_base = &handle->read_header;
    handle->cntl_write_iovec = (globus_xio_iovec_t*)
        globus_malloc(sizeof(globus_xio_iovec_t) * 2);
    if (!handle->cntl_write_iovec)
    {
        goto error_cntl_write_iovec;
    }
    handle->cntl_write_iovec[0].iov_base = &handle->cntl_write_header;
    handle->data_write_iovec[0].iov_base = &handle->data_write_header;
    handle->read_iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
    handle->cntl_write_iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
    handle->data_write_iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
    result = globus_l_xio_udt_set_udp_attributes(op, attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }

    handle->driver_handle = globus_xio_operation_get_driver_handle(op);
    if(handle->server)
    {
        globus_xio_contact_t            new_contact_info;
        char *                          cs;

        memset(&new_contact_info, 0, sizeof(globus_xio_contact_t));
        cs = globus_libc_strdup(handle->remote_cs);
        new_contact_info.host = cs;
        new_contact_info.port = strrchr(cs, ':');
        *new_contact_info.port = 0;
        new_contact_info.port++;

        result = globus_xio_driver_pass_open(
            op,
            &new_contact_info,
            globus_l_xio_udt_open_cb,
            handle);
        globus_free(cs);
    }
    else
    {       
        result = globus_xio_driver_pass_open(
            op,
            contact_info,
            globus_l_xio_udt_open_cb,
            handle);
    }   
    
    if(result != GLOBUS_SUCCESS)
    {    
        goto error_open;
    }
    
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
        
error_open: 
    globus_free(handle->cntl_write_iovec);
error_cntl_write_iovec:
    globus_free(handle->attr);
error_attr:
error_handle:
    GlobusXIOUdtDebugExitWithError();
    return result;
}

static
int
globus_l_xio_udt_priority_q_cmp_func(
    void *                              priority_1,
    void *                              priority_2)
{
    globus_abstime_t *                  timestamp_1;
    globus_abstime_t *                  timestamp_2;
    GlobusXIOName(globus_l_xio_udt_priority_q_cmp_func);

    timestamp_1 = (globus_abstime_t*)priority_1;
    timestamp_2 = (globus_abstime_t*)priority_2;
    return globus_abstime_cmp(timestamp_1, timestamp_2);

}


/*
 * server interface funcs
 */


static
void
globus_l_xio_udt_server_read_cb(
    globus_xio_handle_t                     xio_handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_l_server_t *                     server;
    globus_l_handle_t *                     handle;
    globus_l_handle_t *                     new_handle = NULL;
    globus_l_xio_udt_handshake_t *          handshake;
    globus_l_xio_udt_connection_info_t *  connection_info;
    globus_xio_operation_t                  op;
    unsigned char                           ipnum[GLOBUS_L_XIO_UDT_IP_LEN];
    char                                    ipstr[GLOBUS_L_XIO_UDT_IP_LEN];
    char                                    port[GLOBUS_L_XIO_UDT_IP_LEN];
    char *                                  cs;
    char *                                  contact=NULL;
    int                                     i;
    GlobusXIOName(globus_l_xio_udt_server_read_cb);

    GlobusXIOUdtDebugEnter();

    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    handle = (globus_l_handle_t*)user_arg;
    server = handle->server;
    op = NULL;
    globus_mutex_lock(&server->mutex);
    handshake = (globus_l_xio_udt_handshake_t*)buffer;

    for (i = GLOBUS_L_XIO_UDT_IP_LEN - 1; i >= 0; --i)
    {
        ipnum[i] = (char)handshake->ip[i];
    }
    inet_ntop(AF_INET, ipnum, ipstr, GLOBUS_L_XIO_UDT_IP_LEN);
    sprintf(port, "%d", handshake->port);
    cs = globus_malloc(strlen(ipstr) + strlen(port) + 2);
    sprintf(cs, "%s:%s", ipstr, port);
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("handshake from client cs = %s, \n", cs));
    result = globus_xio_data_descriptor_cntl(
        server->read_data_desc,
        globus_l_xio_udt_server_udp_driver,
        GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,
        &contact);
    if (result != GLOBUS_SUCCESS)
    {
        GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("get contact failed\n"));
        goto error;
    }
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("client contact(data descriptor) = %s, \n", contact));

    connection_info = (globus_l_xio_udt_connection_info_t*)
        globus_hashtable_lookup(&server->clients_hashtable, cs);
    if (connection_info)
    {
        if (connection_info->handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
        {
            globus_l_xio_udt_server_write_handshake(
                connection_info->handle);
        }
        else if (connection_info->handle->state == GLOBUS_L_XIO_UDT_QUEUED)
        {
            GlobusTimeAbstimeGetCurrent(connection_info->timestamp);
            globus_priority_q_modify(&server->clients_priority_q,
                connection_info, &connection_info->timestamp);
        }
        globus_free(cs);
    }
    else
    {
        connection_info = (globus_l_xio_udt_connection_info_t*)
            globus_malloc(sizeof(globus_l_xio_udt_connection_info_t));
        connection_info->handle = handle;
        handle->remote_cs = cs;
        handle->remote_handshake = handshake;
        if (server->op)
        {
            op = server->op;
            server->op = NULL;
            handle->state = GLOBUS_L_XIO_UDT_PROCESSING;
            new_handle = handle;
        }
        else
        {
            GlobusTimeAbstimeGetCurrent(
                connection_info->timestamp);
            globus_priority_q_enqueue(&server->clients_priority_q,
                connection_info, &connection_info->timestamp);
            handle->state = GLOBUS_L_XIO_UDT_QUEUED;
        }
        globus_hashtable_insert(&server->clients_hashtable,
            connection_info->handle->remote_cs, connection_info);
        handle = (globus_l_handle_t*)globus_malloc(
            sizeof(globus_l_handle_t));
        handle->server = server;
        handshake = (globus_l_xio_udt_handshake_t*)
            globus_malloc(sizeof(globus_l_xio_udt_handshake_t));
    }

    /* XXX why destroy and re-init? can't you just reuse it */
    result = globus_xio_data_descriptor_destroy(server->read_data_desc);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_dd_destroy;
    }
    result = globus_xio_data_descriptor_init(
        &server->read_data_desc,
        server->xio_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_dd_init;
    }    
    result = globus_xio_register_read(
                server->xio_handle,
                (globus_byte_t*)handshake,
                len,
                len,
                server->read_data_desc,
                globus_l_xio_udt_server_read_cb,
                handle);
                
    if (result != GLOBUS_SUCCESS)
        goto error;
        
    globus_mutex_unlock(&server->mutex);
    if (new_handle)     
    {           
        globus_xio_driver_finished_accept(op, new_handle, GLOBUS_SUCCESS);
    }   
    GlobusXIOUdtDebugExit();
    return;
    
error_dd_destroy:
error_dd_init:
error:  
    GlobusXIOUdtDebugExitWithError();
    return;
}       
        
            
            
globus_result_t
globus_l_xio_udt_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{               
    globus_l_handle_t *                 handle;
    globus_l_server_t *                 server;
    globus_l_attr_t *                   server_attr;
    globus_xio_attr_t                   attr = NULL;
    globus_result_t                     result;
    int                                 res;    
    globus_l_xio_udt_handshake_t *    handshake;
    int                                 handshake_size;
    globus_xio_contact_t                my_contact_info;
    char *                              cs;
    GlobusXIOName(globus_l_xio_udt_server_init);
    
    GlobusXIOUdtDebugEnter();
    server_attr = (globus_l_attr_t *) 
        (driver_attr ? driver_attr : &globus_l_xio_udt_attr_default);
    
    result = globus_xio_attr_init(&attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_xio_attr_cntl(
                attr,
                globus_l_xio_udt_server_udp_driver,
                GLOBUS_XIO_UDP_SET_PORT,
                server_attr->listener_port);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_attr_cntl;
    }

    result = globus_xio_attr_cntl(
        attr,
        globus_l_xio_udt_server_udp_driver,
        GLOBUS_XIO_UDP_SET_NO_IPV6,
        GLOBUS_TRUE);

    if (result != GLOBUS_SUCCESS)
    {
        goto error_attr_cntl;
    }

    server = (globus_l_server_t *) globus_malloc(sizeof(globus_l_server_t));
    if(!server)
    {
        result = GlobusXIOErrorMemory("server");
        goto error_server;
    }
    result = globus_xio_handle_create(
                &server->xio_handle,
                globus_l_xio_udt_server_stack);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_handle_init;
    }

    result = globus_xio_open(
                server->xio_handle,
                NULL,
                attr);

    if (result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }

    result = globus_xio_data_descriptor_init(
        &server->read_data_desc,
        server->xio_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_read_dd_init;
    }

    result = globus_xio_data_descriptor_init(
        &server->data_desc,
        server->xio_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_dd_init;
    }
    res = globus_hashtable_init(
        &server->clients_hashtable,
        GLOBUS_L_XIO_UDT_SERVER_HASHTABLE_SIZE,
        globus_hashtable_string_hash, 
        globus_hashtable_string_keyeq);
    if (res != 0)
    {
        result = GlobusXIOErrorMemory("clients_hashtable");
        goto error_hashtable;
    }
    res = globus_priority_q_init(
        &server->clients_priority_q,
        globus_l_xio_udt_priority_q_cmp_func);
    if (res != 0)
    {   
        result = GlobusXIOErrorMemory("clients_priority_q");
        goto error_priority_q;
    }
    res = globus_fifo_init(
        &server->handshake_write_q);
    if (res != 0)
    {
        result = GlobusXIOErrorMemory("handshake_write_q");
        goto error_handshake_write_q;
    }
    server->write_pending = GLOBUS_FALSE;
    server->op = NULL;
    globus_mutex_init(&server->mutex, NULL);
    globus_mutex_init(&server->write_mutex, NULL);
    handle = (globus_l_handle_t*) globus_malloc (sizeof(globus_l_handle_t));
    if (!handle)
    {   
        result = GlobusXIOErrorMemory("handle");
        goto error_handle;     
    }
    handle->server = server;
    handle->attr = server_attr;
    handshake_size = sizeof(globus_l_xio_udt_handshake_t);
    handshake = (globus_l_xio_udt_handshake_t*)
        globus_malloc(handshake_size);
    if (!handshake)
    {
        result = GlobusXIOErrorMemory("handshake");
        goto error_handshake;
    }

    result = globus_xio_handle_cntl(
        server->xio_handle,
        globus_l_xio_udt_server_udp_driver,
        GLOBUS_XIO_UDP_GET_CONTACT,
        &cs);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_read;
    }
    globus_xio_contact_parse(&my_contact_info, cs);
        
    result = globus_xio_register_read(
                server->xio_handle,
                (globus_byte_t*)handshake,
                handshake_size,
                handshake_size,
                server->read_data_desc,
                globus_l_xio_udt_server_read_cb,
                handle);
    if (result != GLOBUS_SUCCESS)
        goto error_read;

    result = globus_xio_driver_pass_server_init(
        op, &my_contact_info, server);
    globus_xio_contact_destroy(&my_contact_info);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_read;
    }

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error_read:
    globus_free(handshake);

error_handshake:
    globus_free(handle);

error_handle:
    globus_fifo_destroy(&server->handshake_write_q);

error_handshake_write_q:
    globus_priority_q_destroy(&server->clients_priority_q);

error_priority_q:
    globus_hashtable_destroy(&server->clients_hashtable);

error_hashtable:
    globus_xio_data_descriptor_destroy(server->data_desc);

error_dd_init:
    globus_xio_data_descriptor_destroy(server->read_data_desc);

error_read_dd_init:
error_open:
    globus_xio_close(server->xio_handle, NULL);

error_handle_init:
    globus_free(server);
error_server:

error_attr_cntl:
    globus_xio_attr_destroy(attr);

error:
    GlobusXIOUdtDebugExitWithError();
    return result;

}


globus_result_t
globus_l_xio_udt_server_accept(
    void *                                      driver_server,
    globus_xio_operation_t                      op)
{               
    globus_l_server_t *                         server;
    globus_l_handle_t *                         handle;
    globus_l_xio_udt_connection_info_t *        connection_info;
    globus_abstime_t                            current_time;
    globus_abstime_t*                           timestamp;
    globus_reltime_t                            max_ttl;
    GlobusXIOName(globus_l_xio_udt_server_accept);
    
    GlobusXIOUdtDebugEnter();
    
    server = (globus_l_server_t *) driver_server;
    globus_mutex_lock(&server->mutex);
    GlobusTimeAbstimeGetCurrent(current_time);
    GlobusTimeReltimeSet(max_ttl, GLOBUS_L_XIO_UDT_MAX_TTL_SEC,
        GLOBUS_L_XIO_UDT_MAX_TTL_USEC);
    GlobusTimeAbstimeDec(current_time, max_ttl);
    while((timestamp = (globus_abstime_t*)globus_priority_q_first_priority(
        &server->clients_priority_q)) &&
        (globus_abstime_cmp(&current_time, timestamp) > 0))
    {
        connection_info = (globus_l_xio_udt_connection_info_t*)
            globus_priority_q_dequeue(&server->clients_priority_q);
        globus_free(connection_info->handle);
        globus_free(connection_info);
        /* XXX Shouldn't connection_info be removed from hash table? */
    }
    connection_info = NULL;
    
    if (!globus_priority_q_empty(&server->clients_priority_q))
    {   
        connection_info = (globus_l_xio_udt_connection_info_t*)
            globus_priority_q_dequeue(&server->clients_priority_q);
        handle = connection_info->handle;
        handle->state = GLOBUS_L_XIO_UDT_PROCESSING;
    }
    else
    {
        server->op = op;
    }
           
    globus_mutex_unlock(&server->mutex); 
    if (connection_info)
    {
        globus_xio_driver_finished_accept(op, handle, GLOBUS_SUCCESS);
    }        
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
}   

globus_result_t
globus_l_xio_udt_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{   
    globus_l_server_t *                 server;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char **                             out_string;
    globus_xio_system_socket_t *        out_handle;
    GlobusXIOName(globus_l_xio_udt_server_cntl);
    
    GlobusXIOUdtDebugEnter();
    server = (globus_l_server_t *) driver_server;
    
    switch(cmd)
    {
      /* globus_xio_system_socket_t *   handle_out */
      case GLOBUS_XIO_UDT_GET_HANDLE:   
        out_handle = va_arg(ap, globus_xio_system_socket_t *);
        result = globus_xio_data_descriptor_cntl(
            server->data_desc,
            globus_l_xio_udt_server_udp_driver,
            GLOBUS_XIO_UDP_GET_HANDLE,
            out_handle);
/*        *out_handle = GLOBUS_XIO_UDT_INVALID_HANDLE; */
        break;
        
      /* char **                        contact_string_out */
      case GLOBUS_XIO_UDT_GET_LOCAL_NUMERIC_CONTACT:
      case GLOBUS_XIO_GET_LOCAL_NUMERIC_CONTACT:
        out_string = va_arg(ap, char **);
        result = globus_xio_handle_cntl(
            server->xio_handle,
            globus_l_xio_udt_server_udp_driver,
            GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,
            out_string);
        break;
      case GLOBUS_XIO_UDT_GET_LOCAL_CONTACT:
      case GLOBUS_XIO_GET_LOCAL_CONTACT:
        out_string = va_arg(ap, char **);
        result = globus_xio_handle_cntl(
            server->xio_handle,
            globus_l_xio_udt_server_udp_driver,
            GLOBUS_XIO_UDP_GET_CONTACT,
            out_string);
        break;

      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_udt_contact_string", result);
        goto error_contact;
    }

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error_invalid:
error_contact:
    GlobusXIOUdtDebugExitWithError();
    return result;
}

/*
static
void
globus_l_xio_udt_server_hashtable_destroy_cb(
    void *                                      user_arg)
{
    globus_l_xio_udt_connection_info_t *        connection_info;
    GlobusXIOName(globus_l_xio_udt_server_hashtable_destroy_cb);

    GlobusXIOUdtDebugEnter();

    connection_info = (globus_l_xio_udt_connection_info_t *)user_arg;
    globus_free(connection_info->handle->remote_cs);
    globus_free(connection_info);

    GlobusXIOUdtDebugExit();
}

*/


globus_result_t
globus_l_xio_udt_server_destroy(
    void *                              driver_server)
{
/*    globus_l_server_t *                 server; */
    GlobusXIOName(globus_l_xio_udt_server_destroy);

    GlobusXIOUdtDebugEnter();
/*
    server = (globus_l_server_t *) driver_server;

    globus_fifo_destroy(&server->handshake_write_q);
    globus_xio_close(server->xio_handle, NULL);
    globus_priority_q_destroy(&server->clients_priority_q);
    globus_hashtable_destroy_all(
        &server->clients_hashtable,
        globus_l_xio_udt_server_hashtable_destroy_cb);

    globus_free(server);
*/
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_xio_udt_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result;
    int *                               out_int;
    globus_bool_t *                     out_bool;
    int                                 in_int;
    char **                             out_string;
    globus_xio_system_socket_t *        out_handle;

    GlobusXIOName(globus_l_xio_udt_cntl);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t *) driver_specific_handle;

    switch(cmd)
    {
      /* globus_xio_system_socket_t *   handle_out */
      case GLOBUS_XIO_UDT_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_socket_t *);
        *out_handle = handle->attr->handle;
        break;
      
      /* globus_bool_t                  keepalive */
      case GLOBUS_XIO_UDT_SET_KEEPALIVE:
        break;
      
      /* globus_bool_t *                keepalive_out */
      case GLOBUS_XIO_UDT_GET_KEEPALIVE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = handle->attr->keepalive;
        break;
      
      /* globus_bool_t                  linger */
      /* int                            linger_time */
      case GLOBUS_XIO_UDT_SET_LINGER:
        break;
      
      /* globus_bool_t *                linger_out */
      /* int *                          linger_time_out */
      case GLOBUS_XIO_UDT_GET_LINGER:
            out_bool = va_arg(ap, globus_bool_t *);
            out_int = va_arg(ap, int *);
            *out_bool = handle->attr->linger;
            *out_int = handle->attr->linger_time;
        break;
      
      /* globus_bool_t                  oobinline */
      case GLOBUS_XIO_UDT_SET_OOBINLINE:
        break;
      
      /* globus_bool_t *                oobinline_out */
      case GLOBUS_XIO_UDT_GET_OOBINLINE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = handle->attr->oobinline;
        break;

      /* int                            sndbuf */
      case GLOBUS_XIO_UDT_SET_SNDBUF:
        in_int = va_arg(ap, int);
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_SET_SNDBUF,
            in_int);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        break;

      /* int *                          sndbuf_out */
      case GLOBUS_XIO_UDT_GET_SNDBUF:
        out_int = va_arg(ap, int *);
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_SNDBUF,
            out_int);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        break;

      /* int                            rcvbuf */
      case GLOBUS_XIO_UDT_SET_RCVBUF:
        in_int = va_arg(ap, int);
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_SET_RCVBUF,
            in_int);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        break;

      /* int *                          rcvbuf_out */
      case GLOBUS_XIO_UDT_GET_RCVBUF:
        out_int = va_arg(ap, int *);
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_RCVBUF,
            out_int);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        break;

      /* globus_bool_t                  nodelay */
      case GLOBUS_XIO_UDT_SET_NODELAY:
        break;

      /* globus_bool_t *                nodelay_out */
      case GLOBUS_XIO_UDT_GET_NODELAY:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = handle->attr->nodelay;
        break; 
            
      /* char **                        contact_string_out */
      case GLOBUS_XIO_UDT_GET_LOCAL_NUMERIC_CONTACT:
      case GLOBUS_XIO_GET_LOCAL_NUMERIC_CONTACT:
        out_string = va_arg(ap, char **);
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,
            out_string);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;                 
        }
        break;
        
      case GLOBUS_XIO_UDT_GET_LOCAL_CONTACT:
      case GLOBUS_XIO_GET_LOCAL_CONTACT:
        out_string = va_arg(ap, char **);
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_CONTACT,
            out_string);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        break;
        
      case GLOBUS_XIO_UDT_GET_REMOTE_NUMERIC_CONTACT:
      case GLOBUS_XIO_GET_REMOTE_NUMERIC_CONTACT:
      case GLOBUS_XIO_UDT_GET_REMOTE_CONTACT:
      case GLOBUS_XIO_GET_REMOTE_CONTACT:
        out_string = va_arg(ap, char **);
        *out_string = globus_libc_strdup(handle->remote_cs);
        break;
        
      case GLOBUS_XIO_UDT_GET_MSS:
        out_int = va_arg(ap, int*);
        *out_int = handle->handshake->mss;
        break;

      case GLOBUS_XIO_UDT_GET_WND_SIZE: 
        out_int = va_arg(ap, int*);
        *out_int = handle->handshake->max_flow_wnd_size;
        break; 
            
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error;
    }   
        
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
        
error:
    GlobusXIOUdtDebugExitWithError();   
    return result;
}       



globus_result_t
globus_l_xio_udt_link_cntl(
    void *                              driver_link,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char **                             out_string;
    globus_xio_system_socket_t *        out_handle;
    GlobusXIOName(globus_l_xio_udt_link_cntl);

    GlobusXIOUdtDebugEnter();
    handle = (globus_l_handle_t *) driver_link;

    /* XXX not sure how any of these can work.  this function is only called
     * before a link is opened.  In this case, handle->driver_handle is bogus
     */
    switch(cmd)
    {
      /* globus_xio_system_socket_t *   handle_out */
      case GLOBUS_XIO_UDT_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_socket_t *);
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_HANDLE,
            out_handle);
/*        *out_handle = GLOBUS_XIO_UDT_INVALID_HANDLE; */
        break;

      /* char **                        contact_string_out */
      case GLOBUS_XIO_UDT_GET_LOCAL_NUMERIC_CONTACT:
      case GLOBUS_XIO_GET_LOCAL_NUMERIC_CONTACT:
        out_string = va_arg(ap, char **);
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,
            out_string);
        break;
      case GLOBUS_XIO_UDT_GET_LOCAL_CONTACT:
      case GLOBUS_XIO_GET_LOCAL_CONTACT:
        out_string = va_arg(ap, char **);
        result = globus_xio_driver_handle_cntl(
            handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_CONTACT,
            out_string);
        break;
      case GLOBUS_XIO_UDT_GET_REMOTE_NUMERIC_CONTACT:
      case GLOBUS_XIO_GET_REMOTE_NUMERIC_CONTACT:
      case GLOBUS_XIO_UDT_GET_REMOTE_CONTACT:
      case GLOBUS_XIO_GET_REMOTE_CONTACT:
        out_string = va_arg(ap, char **);
        *out_string = globus_libc_strdup(handle->remote_cs);
        break;

      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_udt_contact_string", result);
        goto error_contact;
    }

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error_invalid:
error_contact:
    GlobusXIOUdtDebugExitWithError();
    return result;
}

globus_result_t 
globus_l_xio_udt_link_destroy(
    void *                              driver_link)
{   
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_udt_link_destroy);
        
    GlobusXIOUdtDebugEnter();
            
    handle = (globus_l_handle_t *)driver_link;
    /* XXX need some kind of reference counting on this handle since it can
     * exist as a link, handle, in the connection hash, etc
     */   
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
} 

