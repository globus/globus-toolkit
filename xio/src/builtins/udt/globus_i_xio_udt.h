/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_I_XIO_UDT_H
#define GLOBUS_I_XIO_UDT_H

#include "globus_xio_driver.h"
#include "globus_xio_udt.h"
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

GlobusDebugDeclare(GLOBUS_XIO_UDT);

#define GlobusXIOUdtDebugPrintf(level, message)                            \
    GlobusDebugPrintf(GLOBUS_XIO_UDT, level, message)

#define GlobusXIOUdtDebugEnter()                                           \
    GlobusXIOUdtDebugPrintf(                                               \
        GLOBUS_L_XIO_UDT_DEBUG_TRACE,                                      \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOUdtDebugExit()                                            \
    GlobusXIOUdtDebugPrintf(                                               \
        GLOBUS_L_XIO_UDT_DEBUG_TRACE,                                      \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIOUdtDebugExitWithError()                                   \
    GlobusXIOUdtDebugPrintf(                                               \
        GLOBUS_L_XIO_UDT_DEBUG_TRACE,                                      \
        ("[%s] Exiting with error\n", _xio_name))

enum globus_l_xio_error_levels
{
    GLOBUS_L_XIO_UDT_DEBUG_TRACE                  = 1,
    GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE       = 2
};

GlobusXIODeclareModule(udt);

#define GlobusXIOUdtErrorOpenFailed()                                       \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(udt),                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_UDT_ERROR_OPEN_FAILED,                               \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "udt open failed"))

#define GlobusXIOUdtErrorBrokenConnection()                                 \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(udt),                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_UDT_ERROR_BROKEN_CONNECTION,                         \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Broken connection"))

#define GlobusXIOUdtErrorReadBufferFull()                                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(udt),                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_UDT_ERROR_READ_BUFFER_FULL,                          \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "No space in read buffer for the data received"))

/*
 *  attribute structure 
 */

typedef struct
{
    /* handle/server attrs */
    globus_xio_system_socket_t          handle;
    
    /* server attrs */
    char *                              listener_serv;
    int                                 listener_port;
    int                                 listener_backlog;
    int                                 listener_min_port;
    int                                 listener_max_port;

    /* handle/server attrs */
    char *                              bind_address;
    globus_bool_t                       restrict_port;
    globus_bool_t                       resuseaddr;

    /* handle attrs */
    globus_bool_t                       keepalive;
    globus_bool_t                       linger;
    int                                 linger_time;
    globus_bool_t                       oobinline;
    int                                 sndbuf;
    int                                 rcvbuf;
    globus_bool_t                       nodelay;
    int                                 connector_min_port;
    int                                 connector_max_port;

    /* data descriptor */
    int                                 send_flags;

    int                                 protocolbuf;
    int                                 mss;
    int                                 max_flow_wnd_size;
} globus_l_attr_t;


/*
 * structure that contains the reader control information
 */
typedef struct
{
    globus_abstime_t    last_ack_time;          /* Timestamp of last ACK */
    globus_abstime_t    last_warning_time;      /* Timestamp of last warning */
    globus_abstime_t    time_last_heard;        /* last heard from other end */
    int                 ack_seqno;              /* Last ACK sequence number */
    int                 curr_seqno;             /* Largest seqno. rcvd  */
    int                 exp_interval;
    int                 exp_count;              /* Expiration counter */
    int                 last_ack;               /* All pkts<last_ack are rcvd */    int                 last_ack_ack;           /* last_ack thats been ackd */
    int                 nak_interval;
    int                 next_expect;            /* next expected pkt to rcv */
    int                 user_buf_border;        /* seqno that fills user buf */
    globus_mutex_t      mutex;
    globus_bool_t       next_slot_found;
    
} globus_l_xio_udt_read_cntl_t;
    
    
/*
 * structure that contains the writer control information
 */ 
typedef struct                          
{ 

    double              loss_rate;              /* EWMA loss rate */
    globus_abstime_t    next_write_time;                
    int                 curr_seqno;             /* largest seqno sent */
    int                 dec_count;              /* No. of write rate decrease */
    int                 inter_pkt_interval;     /* Interpkt time in usec */
    int                 last_ack;               /* all pkts<last_ack are rcvd */
    int                 last_dec_seq;           /* seqno last decrease occur */
    int                 local_write;            /* no. pkt sent since lastSYN */
    int                 local_loss;             /* No. pkt loss since lastSYN */
    int                 nak_count;              /* No. NAK rcvd since lastSYN */
    globus_mutex_t      mutex;
    globus_bool_t       freeze;                 /* freeze the data writing */
    globus_bool_t       slow_start;     
                
} globus_l_xio_udt_write_cntl_t;
    
    
/*  
 * udt handshake
 */ 
typedef struct                          
{   
    unsigned int        ip[GLOBUS_L_XIO_UDT_IP_LEN];    /* ip address */
    int                 port;                           /* port number */
    int                 mss;                            /* max segment size */
    int                 max_flow_wnd_size;              /* max flow wnd size */

} globus_l_xio_udt_handshake_t;         
    
    
/*
 * udt writer buffer
 */
struct globus_l_xio_udt_write_data_blk_s
{
    const char*                                 data;
    int                                         length;
    struct globus_l_xio_udt_write_data_blk_s* next;
};  
    
typedef struct globus_l_xio_udt_write_data_blk_s                         
    globus_l_xio_udt_write_data_blk_t;          
    
typedef struct          
{   
    globus_mutex_t                      mutex;   
    globus_l_xio_udt_write_data_blk_t *first_blk, *last_blk,                  
                                        *curr_write_blk, *curr_ack_blk;
    /*
     *  block:            The first block       
     *  last_blk:         The last block
     *  curr_write_blk:   The block that contains the largest seqno sent
     *  curr_ack_blk:     The block contains the last_ack
     */

   int                                  size;
                                        /* Total size of the blocks */
   int                                  curr_buf_size;
                                        /* size of unacknowledged data */
   int                                  curr_write_pnt;
                                        /* pointer to the curr seqno data */
   int                                  curr_ack_pnt;
                                        /* pointer to the last_ack data */
   globus_result_t                      result;
   int                                  nbytes;
   globus_bool_t                        pending_finished_write;

} globus_l_xio_udt_write_buf_t;

/*
 *  i thought of using globus_list (rather globus_fifo) but i gave up coz of
 *  the following reasons - need to have multiple pointers pointing to
 *  different locations in fifo - no builtin functions on fifo support this -
 *  with list atleast there was this search function that returned a list, so
 *  there was a way to have multiple pointers in a round about way - also
 *  needed is function that would return the next or prev element in the list
 *  - no way to do this list/fifo - so i decided to implement my own list
 */



/*
 * udt reader buffer
 */

typedef struct
{
    int                                 iovec_num;
    int                                 iovec_offset;
    int                                 base_ptr;

} globus_l_xio_udt_user_buf_ack_t;


typedef struct
{
    globus_xio_iovec_t*                 user_iovec;
                                        /* pointer to user registered buffer */
    int                                 udt_buf_size;
                                        /* size of the protocol buffer */
    int                                 nbytes;
    int                                 start_pos;                               
                                        /* the head position for protocol buf */
    int                                 last_ack_pos;                            
                                        /* position before this are all ack'd */
    int                                 max_offset;
                                        /* the furthest "dirty" position */
    int                                 user_iovec_count;
    int                                 user_buf_size;
                                        /* size of the user buffer */
    int                                 temp_len;
                                        /* size of the user buffer */
    int                                 wait_for;
    globus_mutex_t                      mutex;
    globus_result_t                     result;
    globus_byte_t*                      udt_buf;
                                        /* pointer to the protocol buffer */
    globus_bool_t                       user_buf;
    globus_bool_t                       into_udt_buf;
    globus_bool_t                       pending_finished_read;
    globus_l_xio_udt_user_buf_ack_t*    user_buf_ack;  
                                        /* last ackd position in user buf */
                                        
} globus_l_xio_udt_read_buf_t;          
   
/* 
 *  thought of using a list for the protocol buffer instead of the static array
 *  used in the original udt implementation -  this way i thought i could
 *  avoid the irregular pkt list - but there are quite few issues - user buffer
 *  registration - when a pkt arrives and if user buffer is available, the data
 *  will be placed directly into the user buffer - note data may arrive out of
 *  order - in that case the position for the out of order data has to be
 *  speculated - coz the seqno is per packet as opposed to tcp (where the seqno
 *  is per byte) - each packet is assumed to be of size (MTU - 32 (28 for ip 
 *  header and 4 for udt header)) - later you might get a irregular pkt with
 *  a seqno less than the largest seqno arrived so far - here we need to do the
 *  compaction. I also thought of an implementation wherein we keep all these
 *  irregular pkt processing but only for the user buffer and the protocol
 *  buffer can be implemented as a list - we need to sort the list to make it
 *  easier for copying from protocol to user buffer - even after that multiple
 *  memory copies might be required to fulfill the user request as each node in
 *  the protocol list will only contain a max of MTU size data - so i decided
 *  to use a static array for the protocol buffer (atleast for the time being)
 */


/*
 * udt writer loss list                 
 */ 
    
typedef struct
{ 

    int                                 start_seq;
    int                                 end_seq;

} globus_l_xio_udt_writer_loss_seq_t;   
                                        
typedef struct                          
{                                       
    
   globus_list_t*                       list; 
                                        /* list of writer_loss_seq */
   int                                  length;
   globus_mutex_t                       mutex;
 
} globus_l_xio_udt_writer_loss_info_t;  
    
                                        
    
/*  
 * udt reader loss list                 
 */ 
                                        
typedef struct                          
{

   globus_abstime_t                     last_feedback_time;
   int                                  start_seq;
   int                                  end_seq;
   int                                  report_count;

} globus_l_xio_udt_reader_loss_seq_t;


typedef struct
{
   globus_list_t*                       list; /* list of reader_loss_seq */
   int                                  length;

} globus_l_xio_udt_reader_loss_info_t;



/*
 * irregular pkt list
 */

typedef struct
{

   int                                  seqno;
   int                                  error_size;

} globus_l_xio_udt_irregular_seq_t;


typedef struct
{
   globus_list_t *                      list;    /* list of irregular seq */
   int                                  length;  /* list length */

} globus_l_xio_udt_irregular_pkt_info_t;



/*
 * udt ack window
 */

typedef struct
{

   globus_abstime_t                     time_stamp;
   int                                  ack_seq;        /* seqno of ack pkt */
   int                                  seq;            /* seqno of data pkt */

} globus_l_xio_udt_ack_record_t;



/*
 * udt reader time window
 */

typedef struct
{

   globus_abstime_t     last_arr_time;
                        /* last packet arrival time */
   globus_abstime_t     curr_arr_time;           
                        /* current packet arrival time */
   globus_abstime_t     probe_time;                  
                        /* arrival time of the first probing packet */

   int                  pkt_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];
                        /* interval betweeen the current and last pkt */
   int                  pkt_window_ptr;
                        /* position pointer of the packet info. window. */
   
   int                  rtt_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];
                        /* RTT history window */
   int                  pct_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];
                        /* PCT (pairwise comparison test) history window */
   int                  pdt_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];          
                        /* PDT (pairwise difference test) history window */
   int                  rtt_window_ptr;
                        /* position pointer to the 3 windows above */

   int                  probe_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];
                        /* record inter-packet time for probing packet pairs */
   int                  probe_window_ptr;
                        /* position pointer to the probing window */
   

} globus_l_xio_udt_read_history_t;



/*
 *  server structure                    
 */
typedef struct
{ 
    globus_hashtable_t                  clients_hashtable;
    globus_priority_q_t                 clients_priority_q;
    globus_xio_handle_t                 xio_handle;
    globus_xio_data_descriptor_t        data_desc;
    globus_xio_data_descriptor_t        read_data_desc;
    globus_xio_data_descriptor_t        write_data_desc;
    globus_fifo_t                       handshake_write_q;
    globus_xio_operation_t              op;
    globus_mutex_t                      mutex;
    globus_mutex_t                      write_mutex;
    globus_bool_t                       write_pending;
   
} globus_l_server_t;                    


/*
 *  handle structure
 */
typedef struct
{
    globus_l_attr_t *                           attr;
    globus_l_server_t *                         server;
    globus_xio_iovec_t                          read_iovec[2];
    globus_xio_iovec_t                          data_write_iovec[2];
    globus_xio_iovec_t *                        cntl_write_iovec;
    int                                         read_header;
    int                                         data_write_header;
    int                                         cntl_write_header;
    globus_callback_handle_t                    cancel_read_handle;
                                        /* cb handle for handshake oneshot */
    globus_callback_handle_t                    write_handle;
                                        /* cb handle for i_write oneshot */
    globus_callback_handle_t                    ack_handle;
    globus_callback_handle_t                    nak_handle;
    globus_callback_handle_t                    exp_handle;
    globus_callback_handle_t                    fin_handle;
    globus_callback_handle_t                    fin_close_handle;

    globus_xio_operation_t                      user_write_op;
    globus_xio_operation_t                      driver_write_op;
    globus_xio_operation_t                      user_read_op;
    globus_xio_operation_t                      driver_read_op;
    globus_xio_operation_t                      open_op;
                                        /* to write handshake during open) */
    globus_xio_operation_t                      close_op;
    globus_xio_driver_handle_t                  driver_handle;
    globus_l_xio_udt_handshake_t *              handshake;
    globus_l_xio_udt_handshake_t *              remote_handshake;
    char *                                      remote_cs;
                                        /* handshake */
    int                                         handshake_count;
                                        /* No. times handshake is written */
    int                                         fin_count;
                                        /* No. times fin is written */
    int                                         payload_size;
                                        /* regular payload size, in bytes */
    int                                         flow_wnd_size;
                                        /* Flow control window size */
    int                                         bandwidth;
                                        /* Estimated bw in pkts per second */
    int                                         rtt;
                                        /* RTT in usec */
    int                                         max_exp_count;
    globus_xio_udt_state_t                      state;
    globus_bool_t                               first_write;
    globus_bool_t                               write_pending;
    globus_bool_t                               pending_write_oneshot;
    globus_fifo_t                               cntl_write_q;
                                        /* status of connection - enum in .h */
    globus_mutex_t                              state_mutex;
    globus_byte_t*                              payload;

    /* writer related data */
    globus_l_xio_udt_write_buf_t*               write_buf;
    globus_l_xio_udt_writer_loss_info_t*        writer_loss_info;
    globus_l_xio_udt_write_cntl_t*              write_cntl;
    globus_mutex_t                              write_mutex;

    /* reader related data */
    globus_l_xio_udt_read_buf_t*                read_buf;
    globus_l_xio_udt_reader_loss_info_t*        reader_loss_info;

    /* irregular pkt is only associated with the reader */
    globus_l_xio_udt_irregular_pkt_info_t*      irregular_pkt_info;
    globus_list_t*                              ack_window;  
                 
                                                /* list of ack records */
    globus_l_xio_udt_read_history_t*            read_history;
    globus_l_xio_udt_read_cntl_t*               read_cntl;
    
} globus_l_handle_t;                    
    
                                        
typedef struct
{   
    globus_l_handle_t *                         handle;
    globus_abstime_t                            timestamp;
    
} globus_l_xio_udt_connection_info_t;     



extern
globus_result_t
globus_l_xio_udt_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op);

extern
globus_result_t
globus_l_xio_udt_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op);

extern
globus_result_t
globus_l_xio_udt_server_accept(
    void *                                      driver_server,
    globus_xio_operation_t                      op);

extern
globus_result_t
globus_l_xio_udt_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap);

extern
globus_result_t
globus_l_xio_udt_server_destroy(
    void *                              driver_server);

extern
globus_result_t
globus_l_xio_udt_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap);

extern
globus_result_t
globus_l_xio_udt_link_cntl(
    void *                              driver_link,
    int                                 cmd,
    va_list                             ap);

extern
globus_result_t
globus_l_xio_udt_link_destroy(
    void *                              driver_link);

extern
globus_result_t
globus_l_xio_udt_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op);

extern
void
globus_l_xio_udt_pass_close(
    void*               	        user_arg);

extern
void
globus_i_xio_udt_read(
    void*                       	user_arg);

extern
globus_bool_t
globus_l_xio_udt_update_read_ack_point(
    globus_l_handle_t*                          handle,
    int                                         len);

extern
int
globus_l_xio_udt_get_first_reader_lost_seq(
    globus_l_xio_udt_reader_loss_info_t*         reader_loss_info);

extern
void
globus_l_xio_udt_reader_loss_list_insert(
    globus_l_xio_udt_reader_loss_info_t*        reader_loss_info,
    int                                         seqno1,
    int                                         seqno2);

extern
void
globus_l_xio_udt_get_reader_loss_array(
    globus_l_xio_udt_reader_loss_info_t*        reader_loss_info,
    int*                                        array,
    int*                                        len,
    int                                         limit,
    int                                         interval_usec);

extern
int
globus_l_xio_udt_get_error_size(
    globus_l_xio_udt_irregular_pkt_info_t*      irregular_pkt_info,
    int                                         seqno);

extern
void
globus_l_xio_udt_remove_irregular_pkts(
    globus_l_xio_udt_irregular_pkt_info_t*      irregular_pkt_info,
    int                                         seqno);

extern
globus_result_t
globus_l_xio_udt_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t*           iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op);

extern
void
globus_l_xio_udt_update_write_ack_point(
    globus_l_handle_t*                          handle,
    int                                         len,
    int                                         payloadsize);

extern
int
globus_l_xio_udt_writer_loss_list_insert(
    globus_l_xio_udt_writer_loss_info_t*        writer_loss_info,
    int                                         seqno1,
    int                                         seqno2);

extern
void
globus_l_xio_udt_writer_loss_list_remove(
    globus_l_xio_udt_writer_loss_info_t*        writer_loss_info,
    int                                         seqno);

extern
void
globus_i_xio_udt_write(
    globus_l_handle_t*          handle);

extern
globus_result_t
globus_l_xio_udt_write(
    void *                                       driver_specific_handle,
    const globus_xio_iovec_t *                   iovec,
    int                                          iovec_count,
    globus_xio_operation_t                       op);

extern
void
globus_l_xio_udt_finish_write(
    void*                       user_arg);

extern
void
globus_l_xio_udt_record_pkt_arrival(
    globus_l_xio_udt_read_history_t*           read_history);

extern
void
globus_l_xio_udt_record_probe2_arrival(
    globus_l_xio_udt_read_history_t*           read_history);

extern
void
globus_l_xio_udt_write_nak(
    globus_l_handle_t *                 handle,
    int                                 start_seq,
    int                                 end_seq);

extern
void
globus_l_xio_udt_write_fin(
    globus_l_handle_t *                 handle);

extern
void
globus_l_xio_udt_process_ack(
    globus_l_handle_t*                  handle);

extern
void
globus_l_xio_udt_process_nak(
    globus_l_handle_t*                  handle);

extern
void
globus_l_xio_udt_process_fin(
    globus_l_handle_t*                  handle);

extern
void
globus_l_xio_udt_process_congestion_warning(
    globus_l_handle_t*                           handle);

extern
void
globus_l_xio_udt_process_ack_ack(
    globus_l_handle_t*                  handle);

extern
void
globus_l_xio_udt_process_fin_ack(
    globus_l_handle_t*                  handle);

extern
void
globus_l_xio_udt_ack(
    void*                       user_arg);

extern
void
globus_l_xio_udt_nak(
    void*                       user_arg);

extern
void
globus_l_xio_udt_exp(
    void*                       user_arg);

extern
void
globus_l_xio_udt_fin_close(
    void*                       user_arg);

extern
globus_result_t
globus_l_xio_udt_attr_init(
    void **                             out_attr);

extern
globus_result_t
globus_l_xio_udt_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap);

extern
globus_result_t
globus_l_xio_udt_attr_copy(
    void **                             dst,
    void *                              src);

extern
globus_result_t
globus_l_xio_udt_attr_destroy(
    void *                              driver_attr);

extern
int
globus_l_xio_udt_min3(
    int                 a,
    int                 b,
    int                 c);

extern
globus_bool_t
globus_l_xio_udt_greater_than(
    int                         seqno1,
    int                         seqno2);

extern
globus_bool_t
globus_l_xio_udt_less_than(
    int                         seqno1,
    int                         seqno2);

extern
globus_bool_t
globus_l_xio_udt_not_less_than(
    int                                 seqno1,
    int                                 seqno2);

extern
globus_bool_t
globus_l_xio_udt_not_greater_than(
    int                                 seqno1,
    int                                 seqno2);

extern
int
globus_l_xio_udt_min_seqno(
    int                         seqno1,
    int                         seqno2);

extern
int
globus_l_xio_udt_max_seqno(
    int                         seqno1,
    int                         seqno2);

extern
int
globus_l_xio_udt_get_length(
    int                         seqno1,
    int                         seqno2);

extern
int
globus_l_xio_udt_inc_seqno(
    int                         seqno);

extern
int
globus_l_xio_udt_dec_seqno(
    int                         seqno);

#endif
