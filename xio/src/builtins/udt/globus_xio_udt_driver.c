#include "globus_i_xio.h"
#include "globus_xio_driver.h"
#include "globus_xio_udt_driver.h"
#include "version.h"
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

GlobusDebugDefine(GLOBUS_XIO_UDT);

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
    GLOBUS_L_XIO_UDT_DEBUG_TRACE     		  = 1,
    GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE       = 2
};

static globus_xio_driver_t globus_l_xio_udt_udp_driver;

static globus_xio_stack_t globus_l_xio_udt_server_stack;
static globus_xio_driver_t globus_l_xio_udt_server_udp_driver;


static
int
globus_l_xio_udt_activate(void);

static
int
globus_l_xio_udt_deactivate(void);

static
void
globus_l_xio_udt_write_handshake_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
void
globus_l_xio_udt_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
void
globus_l_xio_udt_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);


static
void
globus_l_xio_udt_write_data(
    void*				user_arg);

static
void
globus_i_xio_udt_read(
    void*                       user_arg);

static
void
globus_l_xio_udt_pass_close(
    void*                       user_arg);

static
void
globus_l_xio_udt_ack(
    void*               user_arg);

static
void
globus_l_xio_udt_nak(
    void*               user_arg);

static
void
globus_l_xio_udt_exp(
    void*               user_arg);

static
void
globus_l_xio_udt_fin(
    void*               user_arg);

static
void
globus_l_xio_udt_fin_close(
    void*               user_arg);

static globus_module_descriptor_t       globus_i_xio_udt_module =
{
    "globus_xio_udt",
    globus_l_xio_udt_activate,
    globus_l_xio_udt_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


#define GlobusXIOUdtErrorOpenFailed()					    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            &globus_i_xio_udt_module,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_UDT_ERROR_OPEN_FAILED,                               \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,          						    \
            "udt open failed"))       

#define GlobusXIOUdtErrorBrokenConnection()				    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            &globus_i_xio_udt_module,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_UDT_ERROR_BROKEN_CONNECTION,                         \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,          						    \
            "Broken connection")) 

#define GlobusXIOUdtErrorReadBufferFull()                                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            &globus_i_xio_udt_module,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_UDT_ERROR_READ_BUFFER_FULL,                          \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,           					    \
            "No space in read buffer for the data received"))

/*
 *  attribute structure
 */

typedef struct
{
    /* target/server attrs */
    globus_xio_system_handle_t          handle;

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
	
    int					protocolbuf; 
    int 				mss;
    int 				max_flow_wnd_size;	
} globus_l_attr_t;

/* default attr */
static globus_l_attr_t			globus_l_xio_udt_attr_default =
{
    GLOBUS_XIO_UDT_INVALID_HANDLE,    /* handle   */

    GLOBUS_NULL,                        /* listener_serv */
    0,                                  /* listener_port */
    -1,                                 /* listener_backlog (SOMAXCONN) */
    0,                                  /* listener_min_port */
    0,                                  /* listener_max_port */

    GLOBUS_NULL,                        /* bind_address */
    GLOBUS_TRUE,                        /* restrict_port */
    GLOBUS_FALSE,                       /* reuseaddr */

    GLOBUS_FALSE,                       /* keepalive */
    GLOBUS_FALSE,                       /* linger */
    0,                                  /* linger_time */
    GLOBUS_FALSE,                       /* oobinline */
    8388608,                            /* sndbuf */
    8388608,                            /* rcvbuf */
    GLOBUS_FALSE,                       /* nodelay */
    0,                                  /* connector_min_port */
    0,                                  /* connector_max_port */

    0,                                   /* send_flags */

    8388608,				/* protocolbuf */
    1500,				/* mss */			
    25600				/* window size */	
};


/*
 * structure that contains the reader control information
 */
typedef struct
{
    globus_abstime_t 	last_ack_time;		/* Timestamp of last ACK */
    globus_abstime_t 	last_warning_time; 	/* Timestamp of last warning */
    globus_abstime_t 	time_last_heard;	/* last heard from other end */
    int 		ack_seqno;              /* Last ACK sequence number */
    int 		curr_seqno;             /* Largest seqno. rcvd  */
    int 		exp_interval;
    int 		exp_count;              /* Expiration counter */
    int 		last_ack;      	        /* All pkts<last_ack are rcvd */    int 		last_ack_ack;           /* last_ack thats been ackd */
    int 		nak_interval;
    int 		next_expect;            /* next expected pkt to rcv */
    int 		user_buf_border;        /* seqno that fills user buf */
    globus_mutex_t	mutex;
    globus_bool_t 	next_slot_found;

} globus_l_xio_udt_read_cntl_t;


/*
 * structure that contains the writer control information
 */
typedef struct
{

    double 		loss_rate;		/* EWMA loss rate */
    globus_abstime_t 	next_write_time;		
    int 		curr_seqno;             /* largest seqno sent */
    int 		dec_count;              /* No. of write rate decrease */
    int 		inter_pkt_interval;     /* Interpkt time in usec */
    int 		last_ack;               /* all pkts<last_ack are rcvd */
    int 		last_dec_seq;           /* seqno last decrease occur */
    int 		local_write;            /* no. pkt sent since lastSYN */
    int 		local_loss;             /* No. pkt loss since lastSYN */
    int                 nak_count;              /* No. NAK rcvd since lastSYN */
    globus_mutex_t	mutex;	
    globus_bool_t 	freeze;			/* freeze the data writing */
    globus_bool_t 	slow_start;
		
} globus_l_xio_udt_write_cntl_t;


/*
 * udt handshake
 */
typedef struct
{
    unsigned int 	ip[GLOBUS_L_XIO_UDT_IP_LEN]; 	/* ip address */
    int 		port;				/* port number */
    int 		mss;				/* max segment size */
    int 		max_flow_wnd_size;		/* max flow wnd size */

} globus_l_xio_udt_handshake_t;


/*
 * udt writer buffer
 */
struct globus_l_xio_udt_write_data_blk_s
{
    const char* 				data;
    int 					length;
    struct globus_l_xio_udt_write_data_blk_s* next;
};

typedef struct globus_l_xio_udt_write_data_blk_s			 
    globus_l_xio_udt_write_data_blk_t;

typedef struct
{
    globus_mutex_t 			mutex;   
    globus_l_xio_udt_write_data_blk_t *first_blk, *last_blk, 			
					*curr_write_blk, *curr_ack_blk;
    /*
     *  block:   	  The first block
     *  last_blk:	  The last block
     *  curr_write_blk:   The block that contains the largest seqno sent
     *  curr_ack_blk:     The block contains the last_ack 
     */
   
   int 					size;            	        
					/* Total size of the blocks */
   int 					curr_buf_size;			
					/* size of unacknowledged data */
   int 					curr_write_pnt;                  
					/* pointer to the curr seqno data */
   int 					curr_ack_pnt;                    
					/* pointer to the last_ack data */
   globus_result_t			result;
   int					nbytes;	
   globus_bool_t			pending_finished_write;
   
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
    int 				iovec_num;
    int					iovec_offset;
    int 				base_ptr;

} globus_l_xio_udt_user_buf_ack_t;


typedef struct
{
    globus_xio_iovec_t* 		user_iovec;
 					/* pointer to user registered buffer */
    int 				udt_buf_size; 
					/* size of the protocol buffer */
    int					nbytes;	
    int 				start_pos;                		 	
					/* the head position for protocol buf */
    int 				last_ack_pos;          			  	
					/* position before this are all ack'd */
    int 				max_offset;  
 			         	/* the furthest "dirty" position */
    int 				user_iovec_count;
    int 				user_buf_size; 
             				/* size of the user buffer */
    int 				temp_len; 
             				/* size of the user buffer */
    int 				wait_for;
    globus_mutex_t 			mutex;
    globus_result_t			result;
    globus_byte_t* 			udt_buf;                 		
					/* pointer to the protocol buffer */
    globus_bool_t 			user_buf;
    globus_bool_t                       into_udt_buf;
    globus_bool_t			pending_finished_read;
    globus_l_xio_udt_user_buf_ack_t* 	user_buf_ack;  
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
	
    int 				start_seq;
    int 				end_seq;

} globus_l_xio_udt_writer_loss_seq_t; 

typedef struct 
{

   globus_list_t* 			list; 
					/* list of writer_loss_seq */
   int 					length;
   globus_mutex_t 			mutex;

} globus_l_xio_udt_writer_loss_info_t;



/*
 * udt reader loss list
 */

typedef struct
{

   globus_abstime_t 			last_feedback_time;
   int 					start_seq;
   int 					end_seq;
   int 					report_count;

} globus_l_xio_udt_reader_loss_seq_t;


typedef struct  
{
   globus_list_t* 			list; /* list of reader_loss_seq */
   int 					length;

} globus_l_xio_udt_reader_loss_info_t; 



/*
 * irregular pkt list
 */

typedef struct
{

   int 					seqno;
   int					error_size;

} globus_l_xio_udt_irregular_seq_t;


typedef struct
{
   globus_list_t * 			list;    /* list of irregular seq */
   int 					length;  /* list length */

} globus_l_xio_udt_irregular_pkt_info_t;



/*
 * udt ack window
 */

typedef struct
{

   globus_abstime_t 			time_stamp;
   int 					ack_seq;	/* seqno of ack pkt */
   int 					seq;		/* seqno of data pkt */

} globus_l_xio_udt_ack_record_t;



/*
 * udt reader time window
 */

typedef struct  
{

   globus_abstime_t 	last_arr_time;
	     	 	/* last packet arrival time */
   globus_abstime_t 	curr_arr_time;      	 
			/* current packet arrival time */
   globus_abstime_t 	probe_time;        		 
			/* arrival time of the first probing packet */

   int 			pkt_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];
			/* interval betweeen the current and last pkt */
   int 			pkt_window_ptr;
			/* position pointer of the packet info. window. */

   int 			rtt_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];
			/* RTT history window */
   int 			pct_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];
     	 		/* PCT (pairwise comparison test) history window */
   int 			pdt_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];     	 
			/* PDT (pairwise difference test) history window */
   int 			rtt_window_ptr;   		 	 
			/* position pointer to the 3 windows above */

   int 			probe_window[GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE];
   	 		/* record inter-packet time for probing packet pairs */
   int 			probe_window_ptr;
   			/* position pointer to the probing window */


} globus_l_xio_udt_read_history_t;



/*
 *  server structure
 */
typedef struct
{
    globus_hashtable_t			clients_hashtable;
    globus_priority_q_t			clients_priority_q;
    globus_xio_handle_t                 xio_handle;
    globus_xio_data_descriptor_t        data_desc;
    globus_xio_data_descriptor_t        read_data_desc;
    globus_xio_data_descriptor_t        write_data_desc;
    globus_fifo_t			handshake_write_q;
    globus_xio_operation_t		target_op;
    globus_mutex_t			mutex;
    globus_mutex_t			write_mutex;
    globus_bool_t			write_pending;

} globus_l_server_t;


/*
 *  handle structure
 */
typedef struct
{
    globus_l_attr_t * 				attr;
    globus_l_server_t *				server;
    globus_xio_iovec_t 				read_iovec[2];
    globus_xio_iovec_t 				data_write_iovec[2];
    globus_xio_iovec_t * 			cntl_write_iovec;
    int 					read_header;
    int 					data_write_header;
    int 					cntl_write_header;
    globus_callback_handle_t 			cancel_read_handle;
 		 			/* cb handle for handshake oneshot */
    globus_callback_handle_t 			write_handle;
		 	 		/* cb handle for i_write oneshot */
    globus_callback_handle_t 			ack_handle;
    globus_callback_handle_t 			nak_handle;
    globus_callback_handle_t 			exp_handle;
    globus_callback_handle_t 			fin_handle;
    globus_callback_handle_t 			fin_close_handle;

    globus_xio_operation_t 			user_write_op; 
    globus_xio_operation_t 			driver_write_op;	 
    globus_xio_operation_t 			user_read_op;		 
    globus_xio_operation_t 			driver_read_op; 	 
    globus_xio_operation_t 			open_op; 		 
					/* to write handshake during open) */
    globus_xio_operation_t 			close_op;
    globus_xio_driver_handle_t 			driver_handle;
    globus_l_xio_udt_handshake_t * 		handshake;
    globus_l_xio_udt_handshake_t * 		remote_handshake;
    char *					remote_cs;
				 	/* handshake */	 
    int 					handshake_count;	
					/* No. times handshake is written */
    int 					fin_count;	
					/* No. times fin is written */
    int 					payload_size;
  			        	/* regular payload size, in bytes */
    int		 				flow_wnd_size; 
            		        	/* Flow control window size */
    int 					bandwidth;
                      	 	  	/* Estimated bw in pkts per second */
    int 					rtt; 
                      			/* RTT in usec */	
    int						max_exp_count;
    globus_xio_udt_state_t 			state;	
    globus_bool_t				first_write;
    globus_bool_t				write_pending;
    globus_bool_t				pending_write_oneshot;
    globus_fifo_t				cntl_write_q;
					/* status of connection - enum in .h */
    globus_mutex_t 				state_mutex;
    globus_byte_t* 				payload;			

    /* writer related data */
    globus_l_xio_udt_write_buf_t* 		write_buf;
    globus_l_xio_udt_writer_loss_info_t*	writer_loss_info;
    globus_l_xio_udt_write_cntl_t* 		write_cntl; 
    globus_mutex_t 				write_mutex;
  
    /* reader related data */
    globus_l_xio_udt_read_buf_t* 		read_buf;
    globus_l_xio_udt_reader_loss_info_t* 	reader_loss_info;

    /* irregular pkt is only associated with the reader */
    globus_l_xio_udt_irregular_pkt_info_t* 	irregular_pkt_info; 
    globus_list_t*				ack_window;					 
						/* list of ack records */
    globus_l_xio_udt_read_history_t* 		read_history;
    globus_l_xio_udt_read_cntl_t* 		read_cntl;

} globus_l_handle_t;


typedef struct
{
    globus_l_handle_t *				handle;
    globus_abstime_t				timestamp;

} globus_l_xio_udt_connection_info_t;


/*
 *  target structure
 */
typedef struct
{
    globus_l_handle_t *				handle;			

} globus_l_target_t;


static
void
globus_i_xio_udt_write(
    globus_l_handle_t *				handle);


static
void
globus_l_xio_udt_server_write(
    globus_l_handle_t *                          handle);


static
int
globus_l_xio_udt_activate(void)
{
    globus_result_t result;
    GlobusXIOName(globus_l_xio_udt_activate);

    GlobusDebugInit(GLOBUS_XIO_UDT, TRACE);

    GlobusXIOUdtDebugEnter();

    result = globus_module_activate(GLOBUS_XIO_SYSTEM_MODULE);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_activate;
    }
    result = globus_xio_driver_load("udp", &globus_l_xio_udt_udp_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_load_udp_driver;
    }
    result = globus_xio_driver_load("udp", 
	&globus_l_xio_udt_server_udp_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_load_server_udp_driver;
    }
    result = globus_xio_stack_init(&globus_l_xio_udt_server_stack, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_stack_init;
    }
    result = globus_xio_stack_push_driver(globus_l_xio_udt_server_stack, 
	globus_l_xio_udt_server_udp_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_push_driver;
    }

    GlobusXIOUdtDebugExit();
    return result;

error_push_driver:
   globus_xio_stack_destroy(globus_l_xio_udt_server_stack);

error_stack_init:
    globus_xio_driver_unload(globus_l_xio_udt_server_udp_driver);

error_load_server_udp_driver:
    globus_xio_driver_unload(globus_l_xio_udt_udp_driver);

error_load_udp_driver:
    globus_module_deactivate(GLOBUS_XIO_SYSTEM_MODULE);

error_activate:
    GlobusXIOUdtDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_UDT);
    return result;
}

static
int
globus_l_xio_udt_deactivate(void)
{
    globus_result_t result;
    GlobusXIOName(globus_l_xio_udt_deactivate);

    GlobusXIOUdtDebugEnter();

/*    result = globus_xio_stack_destroy(globus_l_xio_udt_server_stack);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_deactivate;
    }
    result = globus_xio_driver_unload(globus_l_xio_udt_server_udp_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_deactivate;
    }
*/
    result = globus_xio_driver_unload(globus_l_xio_udt_udp_driver);
    if (result != GLOBUS_SUCCESS)
    {
	goto error_deactivate;
    }
    result = globus_module_deactivate(GLOBUS_XIO_SYSTEM_MODULE);
    if (result != GLOBUS_SUCCESS)
    {
	goto error_deactivate;
    }

    GlobusXIOUdtDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_UDT);
    return result;

error_deactivate:
    GlobusXIOUdtDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_UDT);
    return result;
}


/* 
 * The following are the functions associated with the write buffer 
 */

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
    globus_l_xio_udt_write_buf_t*	write_buf,
    const char* 			data, 
    int 				len) 
{
    globus_result_t			result;
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
    const char** 			data, 
    int 				len)
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
    globus_l_xio_udt_write_buf_t*             write_buf,
    const char** 				data, 
    int 					offset, 
    int 					len)
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

static
void 
globus_l_xio_udt_update_write_ack_point(
    globus_l_handle_t*				handle,
    int 					len, 
    int 					payloadsize)
{
    int						length;
    int						temp;	
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

/* 
 * The following are the functions associated with read buffer 
 */

      /* 
       *  Functionality:
       *     Find a position in the buffer to receive next packet.
       *  Parameters:
       *     1) [in] read_buf: udt read buffer
       *     2) [in] data: pointer of pointer to the next data position.
       *     3) [in] offset: offset from last ACK point.
       *     4) [in] len: size of data to be written.
       *  Returned value:
       *     GLOBUS_TRUE if found, else GLOBUS_FALSE
       */

static
globus_bool_t 
globus_l_xio_udt_find_read_data_pos(
    globus_l_xio_udt_read_buf_t*	read_buf,
    char** 				data, 
    int 				offset, 
    int 				len)
{

    int ack_ptr = 0;   
    GlobusXIOName(globus_l_xio_udt_find_read_data_pos);

    GlobusXIOUdtDebugEnter();
    
    globus_mutex_lock(&read_buf->mutex);

    if (read_buf->user_buf_size != 0)
    {
        int iovec_offset, src_iovec_num;
	/*
	 * Introduced a new variable iovec_offset in user_buf_ack to avoid
	 * the for loops that i had here and other places like 
	 * add_data_to_read_buf, compact_buf etc
	 */ 
	iovec_offset = read_buf->user_buf_ack->iovec_offset;
        ack_ptr = iovec_offset + read_buf->user_buf_ack->base_ptr;
        if (ack_ptr + offset + len <= read_buf->user_buf_size)
        {
            src_iovec_num = read_buf->user_buf_ack->iovec_num;
            while (ack_ptr + offset > iovec_offset + 
		   read_buf->user_iovec[src_iovec_num].iov_len)
            {
                src_iovec_num++;
                iovec_offset += read_buf->user_iovec[src_iovec_num].iov_len;
            }
	    if (ack_ptr + offset + len <= iovec_offset + 
		read_buf->user_iovec[src_iovec_num].iov_len)
            {  
	        *data = read_buf->user_iovec[src_iovec_num].iov_base + ack_ptr 
			+ offset - iovec_offset;
            }
	    else
            {
                goto error;
            }
        }
        else if (ack_ptr + offset < read_buf->user_buf_size)
        { 
            goto error;
        }
    }		
    /* 
     * this if loop will be entered only if user_buf_size = 0 or (user_buf_size 
     * !=0 and ack_ptr + offset >= user_buf_size) but there no condition to 
     * check if user_buf_size == 0 coz ack_ptr is initialized to 0 and the 
     * condition below would take care of user_buf_size == 0 
     */
    if (ack_ptr + offset >= read_buf->user_buf_size)
    {
	int last_ack_pos = read_buf->last_ack_pos;
        /* 
         * this has to be only if (user_buf_size !=0 and ack_ptr + offset >= 
         * user_buf_size) but it does not harm to do for (user_buf_size==0) 
         */
        offset -= read_buf->user_buf_size - ack_ptr; 

        if (last_ack_pos >= read_buf->start_pos)
        {
	    int udt_buf_size = read_buf->udt_buf_size;
            if (last_ack_pos + offset + len <= udt_buf_size)
            {
                *data = read_buf->udt_buf + last_ack_pos + offset;
            }
            else if ((last_ack_pos + offset > udt_buf_size) 
                      && (offset - (udt_buf_size - last_ack_pos) 
		      + len <= read_buf->start_pos))
            {
                *data = read_buf->udt_buf + offset - 
                        (udt_buf_size - read_buf->last_ack_pos);
            }
        }
        else if (last_ack_pos + offset + len <= read_buf->start_pos)
        {
            *data = read_buf->udt_buf + last_ack_pos + offset;
        } 
        else
        {
	    goto error;
        }
	/* update furtherest dirty point */
        if (offset + len > read_buf->max_offset)
	{
            read_buf->max_offset = offset + len; 
            read_buf->into_udt_buf = GLOBUS_TRUE;
	}
	
    }

    globus_mutex_unlock(&read_buf->mutex);
    GlobusXIOUdtDebugExit();
    return GLOBUS_TRUE;

error:
    globus_mutex_unlock(&read_buf->mutex);
    GlobusXIOUdtDebugExitWithError();
    return GLOBUS_FALSE;

}


      /* 
       *  Functionality:
       *     Write data into the buffer.
       *  Parameters:
       *     1) [in] read_buf: udt read buffer
       *     2) [in] data: pointer to data to be copied.
       *     3) [in] offset: offset from last ACK point.
       *     4) [in] len: size of data to be written.
       *  Returned value:
       *     GLOBUS_SUCCESS if a position that can hold the data is found, 
       *     otherwise a result object with error
       */

static
globus_result_t 
globus_l_xio_udt_add_data_to_read_buf(
    globus_l_xio_udt_read_buf_t*      read_buf,
    char* 				data, 
    int 				offset, 
    int 				len)
{
    int ack_ptr = 0, orig_len;
    int user_buf_size;
    GlobusXIOName(globus_l_xio_udt_add_data_to_read_buf);

    GlobusXIOUdtDebugEnter();

    orig_len = len;
    user_buf_size = read_buf->user_buf_size;
    if (user_buf_size != 0)
    {
        int iovec_offset, src_iovec_num, src_base_offset;
        int rem_iov_len, total, total_temp, data_size;

	iovec_offset = read_buf->user_buf_ack->iovec_offset;
        ack_ptr = iovec_offset + read_buf->user_buf_ack->base_ptr;
        if (ack_ptr + offset < user_buf_size)
        {
            if (ack_ptr + offset + len < user_buf_size)
            {
    	        total = len;
            }
            else 
            {
	        total = user_buf_size - (ack_ptr + offset);
            }
            src_iovec_num = read_buf->user_buf_ack->iovec_num;
            while (ack_ptr + offset > iovec_offset + 
                   read_buf->user_iovec[src_iovec_num].iov_len)
            {
                src_iovec_num++;
                iovec_offset += read_buf->user_iovec[src_iovec_num].iov_len;
            }
            src_base_offset = ack_ptr + offset - iovec_offset;
            total_temp = total;
	    while(total)
	    {
	        rem_iov_len = read_buf->user_iovec[src_iovec_num].iov_len - 
                              src_base_offset;	
                data_size = (rem_iov_len > total) ? total : rem_iov_len;
                memcpy(read_buf->user_iovec[src_iovec_num].iov_base + 
                       src_base_offset, data, data_size);
                src_base_offset = (src_base_offset + data_size) % 
                                   read_buf->user_iovec[src_iovec_num].iov_len;
                if (src_base_offset == 0)
		{
                    src_iovec_num++;
		}
                /* 
		 * even if this exceeds iovec_count no problem, coz in that 
                 * case total will become zero in the next line and the loop 
                 * will get terminated 
                 */
                total -= data_size;  
	    }
	    if (total_temp < len)
            {
		int temp = user_buf_size - (ack_ptr + offset);
		data += temp;
		len -= temp;
	    }	
        }
    }
    /* 
     * this if loop will be entered only if user_buf_size = 0 or (user_buf_size 
     * !=0 and ack_ptr + offset >= user_buf_size) but there no condition to 
     * check if user_buf_size == 0 coz ack_ptr is initialized to 0 and the 
     * condition below would take care of user_buf_size == 0 
     */
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE, 
         ("add data ack_ptr = %d  offset = %d len = %d start_pos = %d 
         last_ack_pos = %d\n", ack_ptr, offset, len, read_buf->start_pos, 
         read_buf->last_ack_pos)); 
    if (ack_ptr + offset + orig_len  >= user_buf_size)
    {
 	int last_ack_pos = read_buf->last_ack_pos;	
        /* 
         * this has to be only if (user_buf_size !=0 and ack_ptr + offset >=
         * user_buf_size) but it does not harm to do for (user_buf_size==0) 
         */
        if (ack_ptr + offset >= user_buf_size)
	{
            offset -= user_buf_size - ack_ptr; 
	}
        else
	{
	    offset = 0;
	}

        /* 
         * size=10 implies that data can be present in locations 0..9, 
         * last_ack_pos + offset indicates start position for the data 
         * (to be written).. if that is equal to size, it means start position 
         * exceeeds the buffer size (we can not write at location 10. Whereas 
         * if last_ack_pos + offset + len == size (i.e, for eg. if last_ack_pos 
         * + offset = 3 and len = 7 then the data is going to occupy the 
         * locations 3,4,5,6,7,8,9) then data doesnot exceed the buffer size 
         */
       
        if (last_ack_pos >= read_buf->start_pos)
        {
	    int udt_buf_size = read_buf->udt_buf_size;
            if (last_ack_pos + offset + len <= udt_buf_size) 
            {
                memcpy(read_buf->udt_buf + last_ack_pos + offset, 
                       data, len);
            }
            else if ((last_ack_pos + offset < 
                      udt_buf_size) && (len - 
                      (udt_buf_size - last_ack_pos - 
                      offset) <= read_buf->start_pos))
            {
                memcpy(read_buf->udt_buf + last_ack_pos + offset, 
		       data, udt_buf_size - 
                       (last_ack_pos + offset));
                memcpy(read_buf->udt_buf, data + udt_buf_size - 
                       last_ack_pos - offset, len - 
                       (udt_buf_size - (last_ack_pos +
                       offset)));
            }
            else if ((last_ack_pos + offset >= 
                      udt_buf_size) && (offset - 
                      (udt_buf_size - last_ack_pos) + 
		      len <= read_buf->start_pos))
            {
                memcpy(read_buf->udt_buf + offset - 
		       (udt_buf_size - last_ack_pos), 
		       data, len);
            }
        }
        else if (last_ack_pos + offset + len <= read_buf->start_pos)
        {
            memcpy(read_buf->udt_buf + last_ack_pos + offset, data,
		   len);
        }
        else
        {
            goto error;
        }
        if (offset + len > read_buf->max_offset)
        {
            read_buf->max_offset = offset + len;
        }
    }

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusXIOUdtDebugExitWithError();
    return GlobusXIOUdtErrorReadBufferFull();

}


/* 
 * This static inline function to find the minimum among 3 numbers 
 */

static inline
int
globus_l_xio_udt_min3(
    int			a,
    int			b,
    int			c)
{
    int min;
    GlobusXIOName(globus_l_xio_udt_min3);
    if (a < b)
    {
	min = a;
    }
    else
    {	
	min = b;
    }	
    if (c < min)
    {	
	min = c;
    }	
    return min;
}

      /*
       * Functionality:
       *     Move part of the data in buffer to the direction of the ACK point 
       *     by some length.
       * Parameters:
       *     1) [in] read_buf: udt read buffer
       *     2) [in] offset: last_ack_pos + offset is the destination 
       *     3) [in] len: last_ack_pos + offset + len is the source i.e, 
       *        starting from this position till the end of buf has to be 
       * 	moved
       * Returned value:
       *     None. 
       */

static
void 
globus_l_xio_udt_compact_read_buf(
    globus_l_xio_udt_read_buf_t*      read_buf,
    int 				offset, 
    int 				len)
{
    int user_buf_size = read_buf->user_buf_size;
    GlobusXIOName(globus_l_xio_udt_compact_read_buf);

    GlobusXIOUdtDebugEnter();

    globus_mutex_lock(&read_buf->mutex);
    if (user_buf_size != 0)
    {
	int iovec_offset, ack_ptr;

	iovec_offset = read_buf->user_buf_ack->iovec_offset;
        ack_ptr = iovec_offset + read_buf->user_buf_ack->base_ptr;
	if (ack_ptr + offset < user_buf_size)
	{ 
	    int src_base_offset, dst_base_offset, temp_user_buf_size;
	    int src_iovec_num, dst_iovec_num;
	    int total, total2 = 0, total3 = 0; 
	    int len1, len2, data_size;
	    int last_ack_pos = read_buf->last_ack_pos;
	    int udt_buf_size = read_buf->udt_buf_size;
	    int max_offset = read_buf->max_offset;
	    char* dst_ptr;

            src_iovec_num = read_buf->user_buf_ack->iovec_num;
	    while (ack_ptr + offset  > iovec_offset + 
                   read_buf->user_iovec[src_iovec_num].iov_len)
	    {
		src_iovec_num++;
		iovec_offset += read_buf->user_iovec[src_iovec_num].iov_len;	
	    }
	    src_base_offset = ack_ptr + offset - iovec_offset;
	    total = user_buf_size - (ack_ptr + offset); 

	    /*
             * this is the total amount of data that needs to be copied 
             * from protocol buf to user buf if ack_ptr + offset + len > 
             * user_buf_size i.e, staring from last_ack_pos + len - total 
             * (this is same as ack_ptr + offset + len), total amount of
	     * data needs to be copied to user buf. In case if max_offset 
             * < len, then starting from last_ack_pos + len - total, 
	     * last_ack_pos + max_offset - (last_ack_pos + len - total) 
             * alone needs to be copied. this amounts to max_offset - len
	     * + total which is same as total - (len - max_offset). The total 
             * is set to this amount in the following if loop  
             */

	    if (max_offset < len)
            {
		total -= len - max_offset; 
            }

	    /* 
             * dst_ptr indicates the location from which the data needs to be 
             * copied from protocol buffer (to user buffer) 
             */	
 	    dst_ptr = read_buf->udt_buf + last_ack_pos + len - 
                      (user_buf_size - (ack_ptr + offset));
	    if (last_ack_pos + len - (user_buf_size - 
		(ack_ptr + offset)) + total > udt_buf_size)
	    {
		total3 = total - (udt_buf_size - 
		         (last_ack_pos + len - 
			 (user_buf_size - (ack_ptr + offset))));
		total = udt_buf_size - (last_ack_pos + 
			len - (user_buf_size - (ack_ptr + offset)));
	    }
	    if (ack_ptr + offset + len < user_buf_size)
	    { 
                dst_iovec_num = src_iovec_num;
                while (ack_ptr + offset + len > iovec_offset + 
		       read_buf->user_iovec[dst_iovec_num].iov_len)
                {
                    dst_iovec_num++;
                    iovec_offset += read_buf->user_iovec[dst_iovec_num].iov_len;
                }
                dst_base_offset = ack_ptr + offset + len - iovec_offset;
                total = user_buf_size - (ack_ptr + offset + len); 
	    }
            /* 
     	     * total is the amount of data that needs to be copied from 
	     * protocol buffer to user buffer for the case "ack_ptr + 
             * offset < user_buf_size && ack_ptr + offset + len > 
	     * user_buf_size". In case if the amount of data to be copied from 
             * protocol buffer exceeds the protocol buffer boundary, then total 
             * indicates only a part amount of data that needs to be copied and 
             * the remaining part is indicated by total3. Also total is the 
             * amount of data that needs to be copied from ack_ptr + offset + 
             * len in protocol buf to ack_ptr + offset in protocol buf for the 
             * case "ack_ptr + offset + len < user_buf_size"
             */
	    while (total)
	    {

	        len1 = read_buf->user_iovec[src_iovec_num].iov_len - 
		       src_base_offset;
	        if (ack_ptr + offset + len < read_buf->user_buf_size)
	        {
	            len2 = read_buf->user_iovec[dst_iovec_num].iov_len - 
			   dst_base_offset;
	            data_size = globus_l_xio_udt_min3(len1, len2, total);
	            memmove(read_buf->user_iovec[src_iovec_num].iov_base + 
			    src_base_offset, 
                            read_buf->user_iovec[dst_iovec_num].iov_base + 
			    dst_base_offset, data_size);
	            dst_base_offset = (dst_base_offset + data_size) % 
				   read_buf->user_iovec[dst_iovec_num].iov_len;
	            if (dst_base_offset == 0)
		    {
		        dst_iovec_num++;
		    }
	        }
	        else	
	        {
	            data_size = (len1 > total) ? total : len1;	
	            memcpy(read_buf->user_iovec[src_iovec_num].iov_base + 
			   src_base_offset, dst_ptr, data_size);
	            dst_ptr += data_size;	
	        } 
	        src_base_offset = (src_base_offset + data_size) % 
				  read_buf->user_iovec[src_iovec_num].iov_len;
	        if (src_base_offset == 0)
		{
		    src_iovec_num++;
		}
  	        total -= data_size;
	    }
	    if (ack_ptr + offset + len < user_buf_size)
	    {
	        total2 = len > max_offset ? max_offset : 
			 len;
       	        if (last_ack_pos + total2 > udt_buf_size)
                {
         	    total3 = total2 - (udt_buf_size - 
			     last_ack_pos);
            	    total2 = udt_buf_size - last_ack_pos;
                }
                temp_user_buf_size = user_buf_size;
                src_iovec_num = read_buf->user_iovec_count - 1;
                while (user_buf_size - len < temp_user_buf_size - 
		       read_buf->user_iovec[src_iovec_num].iov_len)
                {
            	   temp_user_buf_size -= 
			read_buf->user_iovec[src_iovec_num].iov_len;
            	   src_iovec_num--;
                }
       	        src_base_offset = user_buf_size - len - 
		    (temp_user_buf_size - 
		    read_buf->user_iovec[src_iovec_num].iov_len);
                dst_ptr = read_buf->udt_buf + last_ack_pos;
                /*
                 * total is the amount of data that needs to be copied from 
		 * protocol buffer to user buffer for the case "ack_ptr + 
                 * offset + len < user_buf_size. In case if the amount of data 
		 * to be copied from protocol buffer exceeds the protocol 
		 * buffer boundary, then total2 indicates only a part amount of 
		 * data that needs to be copied and the remaining part is 
		 * indicated by total3. total2 does not have anything do with 
		 * the case "ack_ptr + offset < user_buf_size && ack_ptr + 
		 * offset + len > user_buf_size".
                 */
	        while (total2)
                {
                    len1 = read_buf->user_iovec[src_iovec_num].iov_len - 
			   src_base_offset;
                    data_size = (len1 > total2) ? total2 : len1;
                    memcpy(read_buf->user_iovec[src_iovec_num].iov_base + 
			   src_base_offset, dst_ptr, data_size);
                    src_base_offset = (src_base_offset + data_size) % 
				read_buf->user_iovec[src_iovec_num].iov_len;
                    if (src_base_offset == 0)
		    {
                        src_iovec_num++;
		    }
                    total2 -= data_size;
                    dst_ptr += data_size;
                }
	    }	
            dst_ptr = read_buf->udt_buf;
            while (total3)
            {
                len1 = read_buf->user_iovec[src_iovec_num].iov_len - 
		       src_base_offset;
		data_size = (len1 > total3) ? total3 : len1; 
                memcpy(read_buf->user_iovec[src_iovec_num].iov_base + 
		       src_base_offset, dst_ptr, data_size);
                src_base_offset = (src_base_offset + data_size) % 
				  read_buf->user_iovec[src_iovec_num].iov_len;
                if (src_base_offset == 0)
		{
                    src_iovec_num++;
		}
                total3 -= data_size;
                dst_ptr += data_size;
            }
	    offset = 0;
 	}
        else
	{
            /* offset is larger than size of user buffer */
            offset -= user_buf_size - ack_ptr;
	}
    }   

    /* No data to move */
    if (read_buf->max_offset - offset < len)
    {
        read_buf->max_offset = offset; 
        /* 
         * if there was data to move then max_offset would be set to max_offset 
	 * - len here since there is not data to move you set max_offset = 
	 * offset 
         */
    }
    else
    {
	int last_ack_pos = read_buf->last_ack_pos;
	int udt_buf_size = read_buf->udt_buf_size;
	int max_offset = read_buf->max_offset;

        /* Oops, memory move is too complicated. */
        if (last_ack_pos + max_offset <= udt_buf_size)
        {
            memmove(read_buf->udt_buf + last_ack_pos + offset, 
		    read_buf->udt_buf + last_ack_pos + offset + 
                    len, max_offset - (offset + len));
        }
        else if (last_ack_pos + offset > udt_buf_size)
        {
            memmove(read_buf->udt_buf + (last_ack_pos + offset) % 
	      udt_buf_size, read_buf->udt_buf + 
              (last_ack_pos + offset + len) % 
	      udt_buf_size, max_offset - (offset + len));
        }
        else if (last_ack_pos + offset + len <= udt_buf_size)
        {
            memmove(read_buf->udt_buf + last_ack_pos + offset, 
		    read_buf->udt_buf + last_ack_pos + offset + 
                    len, udt_buf_size - (last_ack_pos + 
		    offset + len));

            /* 
             * Since we moved data starting from "read_buf->udt_buf + 
	     * read_buf->last_ack_pos + offset + len" till end of protocol 
             * buffer 'len' positions ahead, we need to move 'len' amount 
	     * data from the start of buffer to the end 
             */

            memmove(read_buf->udt_buf + (udt_buf_size - len), 
		    read_buf->udt_buf, len);
            memmove(read_buf->udt_buf, read_buf->udt_buf + len, 
		    last_ack_pos + max_offset - 
                    udt_buf_size - len);
        }
        else
        {
            memmove(read_buf->udt_buf + last_ack_pos + offset, 
		    read_buf->udt_buf + (last_ack_pos + offset +
                    len - udt_buf_size), udt_buf_size 
		    - (last_ack_pos + offset));
            /* 
             * total shift position is 'len' i.e, the data at 'offset + len' 
	     * needs to be shifted to 'offset'. Till now the shift is done till
	     * the end of protocol buffer. The data that needs to be copied to 
	     * the start of buffer is (should be) in 'start + len' and the 
             * amount of data that needs to be copied is 'last_ack_pos + 
	     * max_offset - len' and the extra '-read_buf->udt_buf_size is 
	     * because last_ack_pos + max_offset exceeds the protocol buffer 
	     * boundary 
             */
            memmove(read_buf->udt_buf, read_buf->udt_buf + len, 
		    last_ack_pos + max_offset - len - udt_buf_size);
        }

        /* Update the offset pointer */
        read_buf->max_offset -= len;
    }   
    globus_mutex_unlock(&read_buf->mutex);
    GlobusXIOUdtDebugExit();
    return;
}


      /* 
       *  Functionality:
       *     Read data from the buffer into user buffer.
       *  Parameters:
       *     1) [in] read_buf: udt read buffer.
       *     2) [in] data: pointer to the user buffer.
       *     3) [in] len: size of data to be read.
       *  Returned value:
       *     Number of bytes copied	    	
       */

static
int
globus_l_xio_udt_copy_data_to_user_buf(
    globus_l_xio_udt_read_buf_t*      	read_buf,
    const globus_xio_iovec_t* 			iovec,
    int						iovec_count, 
    int 					len)
{
    int bytes_copied = 0;
    int start_pos = read_buf->start_pos;
    int last_ack_pos = read_buf->last_ack_pos;	
    GlobusXIOName(globus_l_xio_udt_copy_data_to_user_buf);

    GlobusXIOUdtDebugEnter();

    GlobusXIOUdtDebugPrintf(
	GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
	("inside copy data start_pos is %d\n", read_buf->start_pos));

    if (start_pos + read_buf->wait_for <= last_ack_pos)
    {
        int i = 0;
        int total, data_size;

        total = last_ack_pos - start_pos;
        if (total > len)
        {
	    total = len;
        }
        bytes_copied = total;
        while(total)
        {
	    data_size = (iovec[i].iov_len > total) ? total : 
			iovec[i].iov_len;
	    memcpy(iovec[i].iov_base, read_buf->udt_buf + 
		   read_buf->start_pos, data_size);
	    read_buf->start_pos += data_size;
	    total -= data_size;
	    ++i;
        }
    }
    else if ((last_ack_pos < start_pos)&&
	     (read_buf->wait_for <= (read_buf->udt_buf_size - 
	     start_pos) + last_ack_pos))
    {
        int i = 0;
        int total1, total2 = 0, base_ptr, data_size;

        total1 = read_buf->udt_buf_size - start_pos;
        if (len > total1)
	{
	    total2 = len - total1;
            if (total2 > last_ack_pos)
	    {
		total2 = last_ack_pos;
	    }
        }
        else
	{
            total1 = len;
	}
	bytes_copied = total1 + total2;
	while(total1)
	{
	    data_size = (iovec[i].iov_len > total1) ? total1 : 
			iovec[i].iov_len;
	    memcpy(iovec[i].iov_base, read_buf->udt_buf + 
		   read_buf->start_pos, data_size);
	    read_buf->start_pos += data_size; 
	    total1 -= data_size;
	    ++i;
	}
        read_buf->start_pos = read_buf->start_pos % read_buf->udt_buf_size; 
        if (total2 && data_size < iovec[i-1].iov_len);
        {
            base_ptr = data_size;
            data_size = iovec[i-1].iov_len - base_ptr;
            if (total2 < data_size)
		data_size = total2;
            memcpy(iovec[i-1].iov_base + base_ptr, read_buf->udt_buf, 
		   data_size);
            read_buf->start_pos = data_size;
	    total2 -= data_size;
        }
        while(total2)
        {
            data_size = (iovec[i].iov_len > total2) ? total2 : iovec[i].iov_len;
            memcpy(iovec[i].iov_base, read_buf->udt_buf + 
		   read_buf->start_pos, data_size);
            read_buf->start_pos += data_size; 
            total2 -= data_size;
            ++i;
        }
    }

    GlobusXIOUdtDebugExit();
    return bytes_copied;

}


      /* 
       *  Functionality:
       *     Update the ACK point of the buffer.
       *  Parameters:
       *    1) [in] handle: udt handle
       *    i'm getting the handle here coz i need both read_buf and read_cntl 
       *    2) [in] len: size of data to be acknowledged.
       *  Returned value:
       *     GLOBUS_TRUE if a user buffer is fulfilled, otherwise GLOBUS_FALSE
       */
static
globus_bool_t 
globus_l_xio_udt_update_read_ack_point(
    globus_l_handle_t*  	    		handle,
    int 					len)
{
    globus_bool_t user_read_done = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_udt_update_read_ack_point);

    GlobusXIOUdtDebugEnter();

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE,
      ("update read ack - len = %d, last_ack_pos = %d\n", 
	len, handle->read_buf->last_ack_pos));

    globus_mutex_lock(&handle->read_buf->mutex);
    if (handle->read_buf->user_buf_size == 0)
    {
        /* there is no user buffer */
        handle->read_buf->last_ack_pos += len;
        handle->read_buf->last_ack_pos %= handle->read_buf->udt_buf_size;
        handle->read_buf->max_offset -= len;
    }
    else
    {
	int ack_ptr;

        ack_ptr = handle->read_buf->user_buf_ack->iovec_offset + 
	    handle->read_buf->user_buf_ack->base_ptr;
        if (ack_ptr + len < handle->read_buf->user_buf_size)
        {
            /* update user buffer ACK pointer */
	    while (ack_ptr + len > 
		handle->read_buf->user_buf_ack->iovec_offset + 
		handle->read_buf->user_iovec[
		    handle->read_buf->user_buf_ack->iovec_num].iov_len)
	    {
	      handle->read_buf->user_buf_ack->iovec_offset += 
		handle->read_buf->user_iovec[
		    handle->read_buf->user_buf_ack->iovec_num].iov_len;
	      handle->read_buf->user_buf_ack->iovec_num++;
	    }
            handle->read_buf->user_buf_ack->base_ptr = 
		ack_ptr + len - handle->read_buf->user_buf_ack->iovec_offset;
        }
        else
        {
            /* user buffer is fulfilled */
            /* update protocol ACK pointer */
            handle->read_buf->last_ack_pos += 
		(ack_ptr + len - handle->read_buf->user_buf_size);
            handle->read_buf->last_ack_pos %= handle->read_buf->udt_buf_size;
            handle->read_buf->max_offset -= 
		(ack_ptr + len - handle->read_buf->user_buf_size);
	    handle->read_buf->pending_finished_read = GLOBUS_TRUE;
	    handle->read_buf->result = GLOBUS_SUCCESS;
	    handle->read_buf->nbytes = handle->read_buf->user_buf_size;
	    handle->read_buf->user_buf_size = 0;
            user_read_done = GLOBUS_TRUE; 
        }
    }    

    globus_mutex_unlock(&handle->read_buf->mutex);
    GlobusXIOUdtDebugExit();
    return user_read_done;
}


      /* 
       *  Functionality:
       *     Insert the user buffer into the protocol buffer.
       *  Parameters:
       *    1) [in] read_buf: udt read buffer.
       *    2) [in] iovec: user iovec.
       *    3) [in] iovec_count: user iovec count.
       *    4) [in] len: size of the user buffer.
       *  Returned value:
       *     Size of data that has been received by now.
       */

static
int 
globus_l_xio_udt_register_user_read_buf(
    globus_l_xio_udt_read_buf_t*              read_buf,
    const globus_xio_iovec_t* 			iovec,
    int						iovec_count, 
    int						len)
{
    /* find the furthest "dirty" data that need to be copied */
    int curr_write_pos;
    int temp = read_buf->start_pos; 
    int start_pos = temp;	
    int last_ack_pos = read_buf->last_ack_pos;	
    int udt_buf_size = read_buf->udt_buf_size;	
    int wait_for = read_buf->wait_for;	
    int size; 
    GlobusXIOName(globus_l_xio_udt_register_user_read_buf);
 
    GlobusXIOUdtDebugEnter();
   
    read_buf->user_buf_ack->iovec_num = 0;
    read_buf->user_buf_ack->iovec_offset = 0;
    read_buf->user_buf_ack->base_ptr = 0;
    curr_write_pos = (last_ack_pos + read_buf->max_offset) % 
			 udt_buf_size;
    if (wait_for < len)
    {
	int temp_len;

        if (curr_write_pos < start_pos)
	{
	    temp_len = udt_buf_size - (start_pos - curr_write_pos); 
	}
	else
	{
	    temp_len = curr_write_pos - start_pos;
	}
	if (wait_for > temp_len)
	{
	    len = wait_for;
	}
	else if (len > temp_len)
	{
	    len = temp_len;
	}
    }
    read_buf->user_buf_size = len;

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE, 
	("register_user_buf curr_write_pos = %d\n", curr_write_pos)); 
    /* 
     * copy data from protocol buffer into user buffer - if curr_write_pos == 
     * start_pos, then it is not considered as curr_write_pos has wrapped 
     * around and difference between curr_write_pos and start_pos as 
     * udt_buf_size, but considered as both are equal
     */
    if (start_pos <= curr_write_pos)
    {	
        if (curr_write_pos - start_pos <= len)  
        {
            /* 
	     * there wont be any dirty data after copy is done thats why 
	     * max_offset set to zero below 
	     */
	    int i = 0; 

	    while (temp < curr_write_pos)
	    {	
	        if (temp + iovec[i].iov_len  < curr_write_pos)
	        {
         	    memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, 
			   iovec[i].iov_len);
	            temp += iovec[i].iov_len;
	        }
	        else
	        {
         	    memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, 
			   curr_write_pos - temp);
	 	    temp += curr_write_pos - temp;
	        }	
	        ++i;	
	    } 
            read_buf->max_offset = 0;
        }
        else
        {
	    int i;
	    for (i = 0; i < iovec_count; i++)
	    {
                memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, 
		       iovec[i].iov_len);
	        temp+= iovec[i].iov_len;
	    }
            read_buf->max_offset -= len;
        }
    }
    else
    {
	/* start_pos > curr_pos */
        if (udt_buf_size - (start_pos - curr_write_pos) <= len)	
        { 
            /* 
	     * there wont be any dirty data after copy is done thats why 
	     * max_offset set to zero below 
	     */
	    int i = 0, temp_len;
	    while (temp + iovec[i].iov_len < udt_buf_size)
            {
	        memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, 
		       iovec[i].iov_len);
	        temp += iovec[i].iov_len;
	        ++i;
	    }
            temp_len = udt_buf_size - temp; 
            memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, temp_len);
	    temp = 0;
            /* 
             * the above part copies data from start_pos till the end of 
	     * protocol buf and the below part copies data from beginning
             * of buffer till curr_pos.  
             */
	    if (curr_write_pos >= iovec[i].iov_len - temp_len) 
            {
                /* 
                 * if curr_write_pos == iovec[i].iov_len - temp_len, then 
		 * memcpy below would copy only from read_buf->udt_buf till   
	         * read_buf->udt_buf + curr_write_pos - 1 
                 */ 
   	        memcpy(iovec[i].iov_base + temp_len, read_buf->udt_buf, 
		       iovec[i].iov_len - temp_len);
	        temp += iovec[i].iov_len - temp_len;
	        ++i;
	    }
	    while (temp + iovec[i].iov_len < curr_write_pos) 
            {
                /* 
		 * temp + iovec[i].iov_len >= curr_write_pos is taken care 
		 * below while 
		 */
                memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, 
		       iovec[i].iov_len); 
                /* read_buf->udt_buf is the start of protocol buffer */
	        temp += iovec[i].iov_len;
	        ++i;
	    }
	    memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, 
		   curr_write_pos - temp);
            read_buf->max_offset = 0;
        }
        else
        {
	    int i, data_size;
	    
            if (udt_buf_size - start_pos <= len)
            {
                for (i = 0; i < iovec_count; i++)
                {
                    if (temp + iovec[i].iov_len < udt_buf_size)
                    {
                        /* 
			 * Data does not exceed the physical boundary of the 
			 * buffer 
			 */
                        memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, 
			       iovec[i].iov_len);
                        temp += iovec[i].iov_len;
                    }
                    else
                    {
                        /* 
			 * data length exceeds the physical boundary, read twice
 			 */
			data_size = udt_buf_size - temp;
                        memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, 
			    data_size);
                        memcpy(iovec[i].iov_base + data_size, 
			    read_buf->udt_buf, iovec[i].iov_len - 
                            data_size);
                        temp = iovec[i].iov_len - data_size;
                    }
                }
            }
            else
	    {
	        for (i = 0; i < iovec_count; i++)
	        {	
                    memcpy(iovec[i].iov_base, read_buf->udt_buf + temp, 
			   iovec[i].iov_len);
	            temp += iovec[i].iov_len;
	        }
	    }	
            read_buf->max_offset -= len;
        }
    }
 
    /* 
     * Update the user buffer pointer - we are sure that start_pos + len > 
     * last_ack_pos - otherwise this routine wouldn't have been called 
     * (copy_data_to_user_buf would have been succeeded), so we need to update 
     * the user_buf_ack i.e, last_ack_pos - start_pos amount of ack'd data has 
     * been copied to user buf (total amount of data copied to user bufffer may 
     * be more than this but this much data is ack'd 
     */

    if (start_pos <= last_ack_pos)
    {
        size = last_ack_pos - start_pos;
    }
    else
    {
        size = udt_buf_size - (start_pos - last_ack_pos);
    }
    while (size > read_buf->user_buf_ack->iovec_offset + 
	   read_buf->user_iovec[read_buf->user_buf_ack->iovec_num].iov_len)
    {
          read_buf->user_buf_ack->iovec_offset += 
	      read_buf->user_iovec[read_buf->user_buf_ack->iovec_num].iov_len;
          read_buf->user_buf_ack->iovec_num++;
    }
    read_buf->user_buf_ack->base_ptr = 
	size - read_buf->user_buf_ack->iovec_offset;

    /* 
     * data from start_pos till start_pos + len is now handed over user_buf, 
     * any arriving data that falls between start_pos and start_pos + len will 
     * now be placed directly on the user_buf - so now, the start_pos of 
     * protocol buffer should be changed to start_pos + len. It is like 
     * clearing the protocol buffer so last_ack_pos is also set to start_pos.
     */

    read_buf->start_pos = (start_pos + len) % udt_buf_size; 
    read_buf->last_ack_pos = read_buf->start_pos;
    
    GlobusXIOUdtDebugExit(); 
    return size; 
    /* 
     * this return value is used in calculating the user_buf_border(the seqno 
     * that will fulfill the user buf) size gives largest ack point in user buf,
     * read_cntl->last_ack+(user_buf_size-(ack_ptr + size))/payload_size gives 
     * the user_buf_border 
     */	
} 



/* 
 * the following are the inline functions used in 3 lists (writer_loss, 
 * reader_loss, irregular_pkt) 
 */

/* Definition of >, <, >=, and <= with sequence number wrap */

static inline 
globus_bool_t 
globus_l_xio_udt_greater_than(
    int 			seqno1, 
    int 			seqno2)
{
    GlobusXIOName(globus_l_xio_udt_greater_than);
    if (((seqno1 > seqno2) && (seqno1 - seqno2 < 
	GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)) || (seqno1 < seqno2 - 
	GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)) 
      return GLOBUS_TRUE;

    /* 
     * if (seqno1 < seqno2 - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH), it means 
     * seqno1 crossed MAX_SEQNO but since the difference is less than 
     * GLOBUS_L_XIO_UDT_SEQ_NO_THRESH seqno1 is greater than seqno2 
     */		
    return GLOBUS_FALSE;
}

static inline 
globus_bool_t 
globus_l_xio_udt_less_than(
    int 			seqno1, 
    int 			seqno2)
{
    GlobusXIOName(globus_l_xio_udt_less_than);
    return globus_l_xio_udt_greater_than(seqno2, seqno1);
}

static inline 
globus_bool_t 
globus_l_xio_udt_not_less_than(
    int 				seqno1,
    int 				seqno2)
{
   GlobusXIOName(globus_l_xio_udt_not_less_than);
   if (seqno1 == seqno2)
      return GLOBUS_TRUE;

   return globus_l_xio_udt_greater_than(seqno1, seqno2);
}

static inline 
globus_bool_t 
globus_l_xio_udt_not_greater_than(
    int 				seqno1, 
    int 				seqno2)
{
    GlobusXIOName(globus_l_xio_udt_not_greater_than);
    if (seqno1 == seqno2)
      return GLOBUS_TRUE;

    return globus_l_xio_udt_less_than(seqno1, seqno2);
}

static inline
int
globus_l_xio_udt_min_seqno(
    int				seqno1,
    int				seqno2)
{
    GlobusXIOName(globus_l_xio_udt_min_seqno);
    if (globus_l_xio_udt_less_than(seqno1, seqno2))
	return seqno1;
    return seqno2;
}

static inline
int
globus_l_xio_udt_max_seqno(
    int				seqno1,
    int				seqno2)
{
    GlobusXIOName(globus_l_xio_udt_max_seqno);
    if (globus_l_xio_udt_greater_than(seqno1, seqno2))
	return seqno1;
    return seqno2;
}

static inline 
int 
globus_l_xio_udt_get_length(
    int 			seqno1, 
    int 			seqno2)
{
    int length = 0;
    GlobusXIOName(globus_l_xio_udt_get_length);

    /* 
     * I'm making sure that the difference between the 2 sequence numbers 
     * should not be greater than GLOBUS_L_XIO_UDT_SEQ_NO_THRESH only for 
     * the case seqno2 < seqno1 and not for seqno1 > seqno2 coz in fact such 
     * call like getLength(1, 2^30) should never happen. The parameters of
     * seqno1 and seqno2 are checked(explicity or implicitly) before 
     * getLength() is called. However, such call as getLength(3, 2) can 
     * happen, which is not right. So the condition is checked. (Such call 
     * should return 0) 
     */

    if (seqno2 >= seqno1)
    {
        length = seqno2 - seqno1 + 1;
    }
    else if (seqno2 < seqno1 - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
    {
        length = seqno2 - seqno1 + GLOBUS_L_XIO_UDT_MAX_SEQ_NO + 1;
    }
    return length;
}

/*Definition of ++, and -- with sequence number wrap */

static inline 
int 
globus_l_xio_udt_inc_seqno(
    int 			seqno)
{
    GlobusXIOName(globus_l_xio_udt_inc_seqno);
    return (seqno + 1) % GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
}

static inline 
int 
globus_l_xio_udt_dec_seqno(
    int 			seqno)
{
    GlobusXIOName(globus_l_xio_udt_dec_seqno);
    return (seqno - 1 + GLOBUS_L_XIO_UDT_MAX_SEQ_NO) % 
	    GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
}

/* the following are the functions associated with the write loss list */

static
int
globus_l_xio_udt_writer_loss_list_insert_predicate(
    void*				datum,
    void*				user_arg)
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

static
int 
globus_l_xio_udt_writer_loss_list_insert(
    globus_l_xio_udt_writer_loss_info_t* 	writer_loss_info,
    int 					seqno1, 
    int 					seqno2)
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
    void*				datum,
    void*				user_arg)
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

static
void 
globus_l_xio_udt_writer_loss_list_remove(
    globus_l_xio_udt_writer_loss_info_t*	writer_loss_info,
    int 					seqno)
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
    void* 			low_datum, 
    void* 			high_datum, 
    void* 			args)
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
    globus_l_xio_udt_writer_loss_info_t*	 writer_loss_info)
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
 *  The following are the functions associated with reader loss list 
 */

      /* 
       *  Functionality:
       *     Insert a series of loss seq. no. between "seqno1" and "seqno2" 
       *     into reader's loss list.
       *  Parameters:
       *     1) [in] reader_loss_info: reader loss information
       *     2) [in] seqno1: sequence number starts.
       *     3) [in] seqno2: seqeunce number ends.
       *  Returned value:
       *     None. 
       */

static
void 
globus_l_xio_udt_reader_loss_list_insert(
    globus_l_xio_udt_reader_loss_info_t* 	reader_loss_info,
    int 					seqno1, 
    int 					seqno2)
{
    globus_l_xio_udt_reader_loss_seq_t* lost_seq;
    GlobusXIOName(globus_l_xio_udt_reader_loss_list_insert);

    GlobusXIOUdtDebugEnter();
    /* 
     * Any seq wont be reported more than once so no need to the check for 
     * duplicates 
     */

    lost_seq = (globus_l_xio_udt_reader_loss_seq_t*) 
		globus_malloc(sizeof(globus_l_xio_udt_reader_loss_seq_t));
    lost_seq->start_seq = seqno1;
    lost_seq->end_seq = seqno2;
    GlobusTimeAbstimeGetCurrent(lost_seq->last_feedback_time); 
    lost_seq->report_count = 2;
    globus_list_insert(&reader_loss_info->list, lost_seq);

    /* 
     * length is inclusive of seqno1 and seqno2 and get_length calculates the 
     * inclusive length 
     */
    
    reader_loss_info->length += globus_l_xio_udt_get_length(seqno1, seqno2); 

    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE, 
	("reader_loss_list_insert seqno1 = %d seqno2 = %d length = %d\n", 
	seqno1, seqno2, reader_loss_info->length)); 

    /* 
     * I'm not doing the coalescing with prior node, e.g., [2, 5], [6, 7] 
     * becomes [2, 7]  
     */
   
    GlobusXIOUdtDebugExit();
    return;
}


        /*
         *  Functionality:
         *    Predicate for globus_l_xio_udt_reader_loss_list_remove. i.e, 
	 *    globus_l_xio_udt_reader_loss_list_remove uses this routine to i
         *    check if there is anything to remove in the reader loss list
         *  Parameters:
         *    1) [in] datum: data present in the write loss list
         *    2) [in] user_arg: user provided argument (seqno)
         *  Returned value:
         *    1 if datum <= user_arg else 0 
         */

static
int
globus_l_xio_udt_reader_loss_list_remove_predicate(
    void*                               datum,
    void*                               user_arg)
{

    globus_l_xio_udt_reader_loss_seq_t * data = 
	(globus_l_xio_udt_reader_loss_seq_t *) datum;
    int* seqno = (int*) user_arg; 
    GlobusXIOName(globus_l_xio_udt_reader_loss_list_remove_predicate);

    if ((globus_l_xio_udt_not_less_than(*seqno, data->start_seq)) && 
	(globus_l_xio_udt_not_greater_than(*seqno, data->end_seq)))
    {
        return 1;
    }
    return 0;
}
 

     /* 
      *   Functionality:
      *      Remove a loss seq. no. from the reader's loss list.
      *   Parameters:
      *	    1) [in] reader_loss_info: reader loss information
      *     2) [in] seqno: sequence number.
      *   Returned value:
      *      None. 
      */

static
void 
globus_l_xio_udt_reader_loss_list_remove(
    globus_l_xio_udt_reader_loss_info_t*      reader_loss_info,
    int 					seqno)
{
    GlobusXIOName(globus_l_xio_udt_reader_loss_list_remove);

    GlobusXIOUdtDebugEnter();

    if (reader_loss_info->length > 0)
    {
	globus_list_t* list = reader_loss_info->list;
	globus_list_t* temp_list;
	globus_l_xio_udt_reader_loss_seq_t* temp_seq;

        if ((temp_list = globus_list_search_pred(list, 
	     globus_l_xio_udt_reader_loss_list_remove_predicate, &seqno)) 
	     != NULL)
        {
	    temp_seq = globus_list_first(temp_list);
	    if (temp_seq->start_seq == temp_seq->end_seq)
            {
                globus_list_remove(&reader_loss_info->list, temp_list);
	        globus_free(temp_seq);
	    }
	    else if (temp_seq->start_seq == seqno)
	    {
	        temp_seq->start_seq = globus_l_xio_udt_inc_seqno(
					temp_seq->start_seq);
	    }
	    else if (temp_seq->end_seq == seqno)
	    {
	        temp_seq->end_seq = globus_l_xio_udt_dec_seqno(
					temp_seq->end_seq);
	    }
	    else /* split */
	    {
	        globus_l_xio_udt_reader_loss_seq_t* new_seq = 
		    (globus_l_xio_udt_reader_loss_seq_t*) 
                    globus_malloc(sizeof(globus_l_xio_udt_reader_loss_seq_t));
	        new_seq->start_seq = globus_l_xio_udt_inc_seqno(seqno);
	        new_seq->end_seq = temp_seq->end_seq;
	        GlobusTimeAbstimeCopy(new_seq->last_feedback_time, 
		    temp_seq->last_feedback_time);
	        new_seq->report_count = temp_seq->report_count;
	        temp_seq->end_seq = globus_l_xio_udt_dec_seqno(seqno);
		globus_list_insert(&reader_loss_info->list, new_seq);
	    }
	    reader_loss_info->length--;
         }
    }

    GlobusXIOUdtDebugExit();
    return;
}



// better make use of priority queue here

      /*
       *  Functionality:
       *     This is a relation function used to find the minimum element in a 
       *     list. This used by the globus_list_min function (see the 
       *     globus_l_xio_udt_get_first_reader_lost_seq(..) function below) 
       *     and globus_list_sort_destructive(..) (see 
       *     globus_l_xio_udt_get_reader_loss_array(..) below)
       *  Parameters:
       *     1) low_datum: a data in the list
       *     2) high_datum: another data in the list
       *     3) args: NULL
       *  Returned value:
       *     1 if low_datum is less than high_datum 0 otherwise
       */

static
int
globus_l_xio_udt_reader_loss_list_relation(
    void*                       low_datum,
    void*                       high_datum,
    void*                       args)
{

    globus_l_xio_udt_reader_loss_seq_t * data1 = 
	(globus_l_xio_udt_reader_loss_seq_t *) low_datum;
    globus_l_xio_udt_reader_loss_seq_t * data2 = 
	(globus_l_xio_udt_reader_loss_seq_t *) high_datum;
    GlobusXIOName(globus_l_xio_udt_reader_loss_list_relation);

    if (globus_l_xio_udt_less_than(data1->start_seq, data2->start_seq))
    {
        return 1;
    }
    return 0;

}


      /* 
       *  Functionality:
       *     Read the first (smallest) seq. no. in the list.
       *  Parameters:
       *     None.
       *  Returned value:
       *     the sequence number or -1 if the list is empty. 
       */

static
int 
globus_l_xio_udt_get_first_reader_lost_seq(
    globus_l_xio_udt_reader_loss_info_t*         reader_loss_info)
{
    int first_lost_seq = -1;
    GlobusXIOName(globus_l_xio_udt_get_first_reader_lost_seq);

    GlobusXIOUdtDebugEnter();

    if (reader_loss_info->length > 0)
    {
	globus_list_t* temp_list;
	globus_l_xio_udt_reader_loss_seq_t* temp_seq;

        temp_list = globus_list_min(reader_loss_info->list, 
			globus_l_xio_udt_reader_loss_list_relation, NULL);
        temp_seq = (globus_l_xio_udt_reader_loss_seq_t*) 
			globus_list_first(temp_list);
        first_lost_seq = temp_seq->start_seq;
    }

    GlobusXIOUdtDebugExit();
    return first_lost_seq; 

}


      /*
       *  Functionality:
       *     Get a encoded loss array for NAK report.
       *  Parameters:
       *     1) [in] reader_loss_info: reader loss information
       *     2) [in] array: pointer to the result array.
       *     3) [out] physical length of the result array.
       *     4) [in] limit: maximum length of the array.
       *     5) [in] interval: Time threshold from last NAK report.
       *  Returned value:
       *     None. 
       */

static
void 
globus_l_xio_udt_get_reader_loss_array(
    globus_l_xio_udt_reader_loss_info_t*      reader_loss_info,
    int* 					array, 
    int* 					len, 
    int 					limit, 
    int		 				interval_usec)
{
    globus_list_t* list;
    globus_abstime_t curr_time;
    globus_reltime_t interval; 
    GlobusXIOName(globus_l_xio_udt_get_reader_loss_array);

    GlobusXIOUdtDebugEnter();

    list = globus_list_sort_destructive(reader_loss_info->list, 
		globus_l_xio_udt_reader_loss_list_relation, NULL);
    reader_loss_info->list = list;
    /* represents number of lost packets */
    len[0] = 0; 
    /* represents no. of seqno.s used to represent total no. of lost packets */
    len[1] = 0; 
    GlobusTimeAbstimeGetCurrent(curr_time);
    GlobusTimeReltimeSet(interval, 0, interval_usec);
    while (list && (len[1] < limit - 1))
    {
	globus_l_xio_udt_reader_loss_seq_t* temp_seq;
	globus_reltime_t time_expired;

        temp_seq = globus_list_first(list);
	GlobusTimeAbstimeDiff(time_expired, temp_seq->last_feedback_time, 
	    curr_time);
	GlobusTimeReltimeDivide(time_expired, temp_seq->report_count);
	if (globus_reltime_cmp(&time_expired, &interval) > 0)
	{
	    array[len[1]] = temp_seq->start_seq;
	    if (temp_seq->end_seq != temp_seq->start_seq)
	    {
	        /* there are more than 1 loss in the sequence */
                array[len[1]] |= 0x80000000;
                len[1]++;
                array[len[1]] = temp_seq->end_seq;
	        /* here get_length should return b-a+1 */
                len[0] += globus_l_xio_udt_get_length(temp_seq->start_seq, 
			      temp_seq->end_seq); 
            }
            else
                /* there is only 1 loss in the seqeunce */
                len[0]++;

            len[1]++;
            /* update the timestamp */
	    GlobusTimeAbstimeCopy(temp_seq->last_feedback_time, curr_time);
            /* update report counter */
            temp_seq->report_count++;
        }
        list = globus_list_rest(list);
    }

    GlobusXIOUdtDebugExit();
    return;
} 
	


/* 
 *  The following are the functions associated with the irregular pkt list 
 */

      /*
       *  Functionality:
       *     This is a relation function used to find the minimum element in a 
       *     list. This used by the globus_list_sort_destructive function (see 
       *     the globus_l_xio_udt_get_error_size(..) function below)
       *  Parameters:
       *     1) low_datum: a data in the list
       *     2) high_datum: another data in the list
       *     3) args: not used
       *  Returned value:
       *     1 if low_datum is less than high_datum 0 otherwise
       */

static
int
globus_l_xio_udt_irregular_pkt_list_relation(
    void*    			                   low_datum,
    void*                       		   high_datum,
    void*                       		   args)
{

    globus_l_xio_udt_irregular_seq_t * data1 = 
	(globus_l_xio_udt_irregular_seq_t *) low_datum;
    globus_l_xio_udt_irregular_seq_t * data2 = 
	(globus_l_xio_udt_irregular_seq_t *) high_datum;
    GlobusXIOName(globus_l_xio_udt_irregular_pkt_list_relation);

    if (globus_l_xio_udt_less_than(data1->seqno, data2->seqno))
    {	
        return 1;
    }
    return 0;

}



      /* 
       *  Functionality:
       *     Read the total size error of all the irregular packets prior to 
       *     "seqno".
       *  Parameters:
       *     1) [in] irregular_pkt_info: irregular packet information
       *     2) [in] seqno: sequence number.
       *  Returned value:
       *     the total size error of all the irregular packets prior to "seqno".       */

static
int 
globus_l_xio_udt_get_error_size(
    globus_l_xio_udt_irregular_pkt_info_t* 	irregular_pkt_info,
    int 					seqno)
{
    int error_size = 0;
    GlobusXIOName(globus_l_xio_udt_get_error_size);

    GlobusXIOUdtDebugEnter();

    if (irregular_pkt_info->length > 0)
    {
	globus_list_t* list;
	globus_l_xio_udt_irregular_seq_t* temp_seq;

        list = globus_list_sort_destructive(irregular_pkt_info->list, 
	    globus_l_xio_udt_irregular_pkt_list_relation, NULL);
        irregular_pkt_info->list = list;
        temp_seq = globus_list_first(list);
        while(list && globus_l_xio_udt_less_than(temp_seq->seqno, 
	    seqno))
        {
	    error_size += temp_seq->error_size;
	    list = globus_list_rest(list);
	    if (list)
	    {
	        temp_seq = globus_list_first(list);
	    }
        }
    }

    GlobusXIOUdtDebugExit();
    return error_size;
}



         /* 
          *  Functionality: 
          *    Predicate for globus_l_xio_udt_add_irregular_pkt. i.e, 
	  *    globus_l_xio_udt_add_irregular_pkt uses this routine to 
	  *    check if the packet is already in irregular pkt list
          *  Parameters:
          *    1) [in] datum: data present in the irregular pkt list
          *    2) [in] user_arg: user provided argument (seqno)
          *  Returned value:
          *    1 if datum == user_arg else 0 
          */

static
int
globus_l_xio_udt_irregular_pkt_list_predicate(
    void*						datum,
    void*						user_arg)
{
    GlobusXIOName(globus_l_xio_udt_irregular_pkt_list_predicate);

    globus_l_xio_udt_irregular_seq_t* data  = 
	(globus_l_xio_udt_irregular_seq_t*) datum;
    int* seqno = (int*)user_arg;
    if (data->seqno == *seqno)
    {	
	return 1;
    }
    return 0;

}


      /* 
       *  Functionality:
       *     Insert an irregular packet into the list.
       *  Parameters:
       *     1) [in] irregular_pkt_info: irregular packet information
       *     2) [in] seqno: sequence number.
       *     3) [in] errsize: size error of the current packet.
       *  Returned value:
       *     None 
       */

static
void 
globus_l_xio_udt_add_irregular_pkt(
    globus_l_xio_udt_irregular_pkt_info_t*	irregular_pkt_info,
    int 					seqno, 
    int 					error_size)
{
    globus_l_xio_udt_irregular_seq_t* 	irregular_seq;
    GlobusXIOName(globus_l_xio_udt_add_irregular_pkt);

    GlobusXIOUdtDebugEnter();

    if (globus_list_search_pred(irregular_pkt_info->list, 
	globus_l_xio_udt_irregular_pkt_list_predicate, &seqno) == NULL)
    {
        irregular_seq = (globus_l_xio_udt_irregular_seq_t*) 
	    globus_malloc(sizeof(globus_l_xio_udt_irregular_seq_t));
        irregular_seq->seqno = seqno;
        irregular_seq->error_size = error_size;
        globus_list_insert(&irregular_pkt_info->list, irregular_seq);
        irregular_pkt_info->length++;
    }

    GlobusXIOUdtDebugExit();
    return;
}



      /* 
       *  Functionality:
       *     Remove ALL the packets prior to "seqno".
       *  Parameters:
       *     1) [in] irregular_pkt_info: irregular packet information
       *     2) [in] seqno: sequence number.
       *  Returned value:
       *     None 
       */

static
void 
globus_l_xio_udt_remove_irregular_pkts(
    globus_l_xio_udt_irregular_pkt_info_t*	irregular_pkt_info,
    int 					seqno)
{
    GlobusXIOName(globus_l_xio_udt_remove_irregular_pkts);

    GlobusXIOUdtDebugEnter();

    if (irregular_pkt_info->length > 0)
    {
	globus_l_xio_udt_irregular_seq_t* temp_seq;
	globus_list_t* list = irregular_pkt_info->list;

        temp_seq = globus_list_first(list);
        while(list && globus_l_xio_udt_less_than(temp_seq->seqno, 
	    seqno))
        {
	    irregular_pkt_info->length--;
	    list = globus_list_rest(list);
	    globus_free(temp_seq);
	    if (list)
	    {
	        temp_seq = globus_list_first(list);
	    }
            globus_list_remove(&irregular_pkt_info->list, 
		irregular_pkt_info->list);
        }
    }

    GlobusXIOUdtDebugExit();
    return;
}



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
    globus_l_handle_t*			handle,
    int 				ack_seq, 
    int 				seq)
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
    globus_l_handle_t*					handle,
    int 						ack_seq, 
    int* 						seq)
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
    globus_l_xio_udt_read_history_t*		read_history)
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

static
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
    globus_l_xio_udt_read_history_t*          read_history,
    int 					rtt)
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

static
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
    globus_l_handle_t*			handle)
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
    globus_l_handle_t*			handle,
    int 				read_rate)
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


      /*
       *  Functionality:
       *     initialize driver attribute
       *  Parameters:
       *     1) [out] out_attr: udt driver attribute
       *  Returned value:
       *     GLOBUS_SUCCESS if initialization is successful,  
       *     otherwise a result object with an error
       */

static
globus_result_t
globus_l_xio_udt_attr_init(
    void **                             out_attr)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_attr_init);

    GlobusXIOUdtDebugEnter();

    /*
     *  create a udt attr structure and intialize its values
     */
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    
    memcpy(attr, &globus_l_xio_udt_attr_default, sizeof(globus_l_attr_t));
    *out_attr = attr;

    GlobusXIOUdtDebugExit();    
    return GLOBUS_SUCCESS;

error_attr:
    GlobusXIOUdtDebugExitWithError();    
    return result;
}



      /*
       *  Functionality:
       *     modify/read driver attribute structure
       *  Parameters:
       *     1) [in] driver_attr: udt driver attribute
       *     2) [in] cmd: specifies what to do  
       *     3) [in/out] depends on the value of cmd
       *  Returned value:
       *     GLOBUS_SUCCESS if there is no error, otherwise a result
       *     object with an error
       */

static
globus_result_t
globus_l_xio_udt_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_attr_t *                   attr;
    globus_xio_system_handle_t *        out_handle;
    char **                             out_string;
    int *                               out_int;
    globus_bool_t *                     out_bool;
    globus_result_t			result;
    GlobusXIOName(globus_l_xio_udt_attr_cntl);

    GlobusXIOUdtDebugEnter();
    attr = (globus_l_attr_t *) driver_attr;
    switch(cmd)
    {
      /**
       *  target/server attrs
       */
      /* globus_xio_system_handle_t     handle */
      case GLOBUS_XIO_UDT_SET_HANDLE:
        attr->handle = va_arg(ap, globus_xio_system_handle_t);
        break;

      /* globus_xio_system_handle_t *   handle_out */
      case GLOBUS_XIO_UDT_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        *out_handle = attr->handle;
        break;
       
      /**
       *  server attrs
       */
      /* char *                         service_name */
      case GLOBUS_XIO_UDT_SET_SERVICE:
        if(attr->listener_serv)         
        {
            globus_free(attr->listener_serv);
        }
        
        attr->listener_serv = va_arg(ap, char *);
        if(attr->listener_serv)
        {
            attr->listener_serv = globus_libc_strdup(attr->listener_serv);
            if(!attr->listener_serv)
            {
                result = GlobusXIOErrorMemory("listener_serv");
                goto error_memory;
            }
        }
        break;


      /* char **                        service_name_out */
      case GLOBUS_XIO_UDT_GET_SERVICE:
        out_string = va_arg(ap, char **);
        if(attr->listener_serv)
        {   
            *out_string = globus_libc_strdup(attr->listener_serv);
            if(!*out_string)
            {   
                result = GlobusXIOErrorMemory("listener_serv_out");
                goto error_memory;
            }
        }
        else
        {   
            *out_string = GLOBUS_NULL;
        }
        break;
      
      /* int                            listener_port */
      case GLOBUS_XIO_UDT_SET_PORT:
        attr->listener_port = va_arg(ap, int);
        break;
      
      /* int *                          listener_port_out */
      case GLOBUS_XIO_UDT_GET_PORT:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_port;
        break;
      
      /* int                            listener_backlog */
      case GLOBUS_XIO_UDT_SET_BACKLOG:
        attr->listener_backlog = va_arg(ap, int);
        break;
      
      /* int *                          listener_backlog_out */
      case GLOBUS_XIO_UDT_GET_BACKLOG:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_backlog;
        break;
      
      /* int                            listener_min_port */
      /* int                            listener_max_port */
      case GLOBUS_XIO_UDT_SET_LISTEN_RANGE:
        attr->listener_min_port = va_arg(ap, int);
        attr->listener_max_port = va_arg(ap, int);
        break;
      
      /* int *                          listener_min_port_out */
      /* int *                          listener_max_port_out */
      case GLOBUS_XIO_UDT_GET_LISTEN_RANGE:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_min_port;
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_max_port;
        break;
        

      /**
       *  handle/server attrs
       */
      /* char *                         interface */
      case GLOBUS_XIO_UDT_SET_INTERFACE:
        if(attr->bind_address)
        {
            globus_free(attr->bind_address);
        }

        attr->bind_address = va_arg(ap, char *);
        if(attr->bind_address)
        {
            attr->bind_address = globus_libc_strdup(attr->bind_address);
            if(!attr->bind_address)
            {
                result = GlobusXIOErrorMemory("bind_address");
                goto error_memory;
            }
        }
        break;

      /* char **                        interface_out */
      case GLOBUS_XIO_UDT_GET_INTERFACE:
        out_string = va_arg(ap, char **);
        if(attr->bind_address)
        {
            *out_string = globus_libc_strdup(attr->bind_address);
            if(!*out_string)
            {
                result = GlobusXIOErrorMemory("bind_address_out");
                goto error_memory;
            }
        }
        else
        {
            *out_string = GLOBUS_NULL;
        }
        break;

      /* globus_bool_t                  restrict_port */
      case GLOBUS_XIO_UDT_SET_RESTRICT_PORT:
        attr->restrict_port = va_arg(ap, globus_bool_t);
        break;

      /* globus_bool_t *                restrict_port_out */
      case GLOBUS_XIO_UDT_GET_RESTRICT_PORT:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->restrict_port;
        break;

      /* globus_bool_t                  resuseaddr */
      case GLOBUS_XIO_UDT_SET_REUSEADDR:
        attr->resuseaddr = va_arg(ap, globus_bool_t);
        break;

        
      /* globus_bool_t *                resuseaddr_out */
      case GLOBUS_XIO_UDT_GET_REUSEADDR:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->resuseaddr;
        break;
        
      /**
       *  handle attrs
       */   
      /* globus_bool_t                  keepalive */
      case GLOBUS_XIO_UDT_SET_KEEPALIVE:
        attr->keepalive = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                keepalive_out */
      case GLOBUS_XIO_UDT_GET_KEEPALIVE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->keepalive;
        break;  
            
      /* globus_bool_t                  linger */
      /* int                            linger_time */
      case GLOBUS_XIO_UDT_SET_LINGER:
        attr->linger = va_arg(ap, globus_bool_t);
        attr->linger_time = va_arg(ap, int);
        break;
        
      /* globus_bool_t *                linger_out */
      /* int *                          linger_time_out */
      case GLOBUS_XIO_UDT_GET_LINGER:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->linger;
        out_int = va_arg(ap, int *);
        *out_int = attr->linger_time;
        break;
        
      /* globus_bool_t                  oobinline */
      case GLOBUS_XIO_UDT_SET_OOBINLINE:
        attr->oobinline = va_arg(ap, globus_bool_t);
        break;

      /* globus_bool_t *                oobinline_out */
      case GLOBUS_XIO_UDT_GET_OOBINLINE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->oobinline;
        break;
         
      /* int                            sndbuf */
      case GLOBUS_XIO_UDT_SET_SNDBUF:
        attr->sndbuf = va_arg(ap, int);
        break;

      /* int *                          sndbuf_out */
      case GLOBUS_XIO_UDT_GET_SNDBUF:
        out_int = va_arg(ap, int *);
        *out_int = attr->sndbuf;
        break;


      /* int                            rcvbuf */
      case GLOBUS_XIO_UDT_SET_RCVBUF:
        attr->rcvbuf = va_arg(ap, int);
        break;

      /* int *                          rcvbuf_out */
      case GLOBUS_XIO_UDT_GET_RCVBUF:
        out_int = va_arg(ap, int *);
        *out_int = attr->rcvbuf;
        break;

      /* globus_bool_t                  nodelay */
      case GLOBUS_XIO_UDT_SET_NODELAY:
        attr->nodelay = va_arg(ap, globus_bool_t);
        break;

      /* globus_bool_t *                nodelay_out */
      case GLOBUS_XIO_UDT_GET_NODELAY:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->nodelay;
        break;

      /* int                            connector_min_port */
      /* int                            connector_max_port */
      case GLOBUS_XIO_UDT_SET_CONNECT_RANGE:
        attr->connector_min_port = va_arg(ap, int);
        attr->connector_max_port = va_arg(ap, int);
        break;

      /* int *                          connector_min_port_out */
      /* int *                          connector_max_port_out */
      case GLOBUS_XIO_UDT_GET_CONNECT_RANGE:
        out_int = va_arg(ap, int *);
        *out_int = attr->connector_min_port;
        out_int = va_arg(ap, int *);
        *out_int = attr->connector_max_port;
        break;

      /**
       * data descriptors
       */
      /* int                            send_flags */
      case GLOBUS_XIO_UDT_SET_SEND_FLAGS:
        attr->send_flags = va_arg(ap, int);
        break;

      /* int *                          send_flags_out */
      case GLOBUS_XIO_UDT_GET_SEND_FLAGS:
        out_int = va_arg(ap, int *);
        *out_int = attr->send_flags;
        break;
         
      /* int                              udt buf */
      case GLOBUS_XIO_UDT_SET_PROTOCOL_BUF:
	attr->protocolbuf = va_arg(ap, int);
	break;

      /* int *                            udt buf_out */
      case GLOBUS_XIO_UDT_GET_PROTOCOL_BUF:
	out_int = va_arg(ap, int*);
	*out_int = attr->protocolbuf;
	break;

      /* int                              max_segment_size */
      case GLOBUS_XIO_UDT_SET_MSS:
	attr->mss = va_arg(ap, int);
	break;

      /* int *                            max_segment_size_out */
      case GLOBUS_XIO_UDT_GET_MSS:
	out_int = va_arg(ap, int*);
	*out_int = attr->mss;
	break;	

      /* int                              window_size */
      case GLOBUS_XIO_UDT_SET_WND_SIZE:
	attr->max_flow_wnd_size = va_arg(ap, int);
	break;

      /* int *                            window_size_out */
      case GLOBUS_XIO_UDT_GET_WND_SIZE:
	out_int = va_arg(ap, int*);
	*out_int = attr->max_flow_wnd_size;
	break;

      case placeholder1:	
      case placeholder2:	
	break;

      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error_memory:
error_invalid:
    GlobusXIOUdtDebugExitWithError();
    return result;
}



      /*
       *  Functionality:
       *     copy attribute structure
       *  Parameters:
       *     1) [out] dst: target attribute structure
       *     2) [in] src: source attribute structure
       *  Returned value:
       *     GLOBUS_SUCCESS if there is no error, otherwise a result object
       *     with an error
       */

static
globus_result_t
globus_l_xio_udt_attr_copy(
    void **                             dst,
    void *                              src)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_attr_copy);

    GlobusXIOUdtDebugEnter();

    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }

    memcpy(attr, src, sizeof(globus_l_attr_t));

    /* 
     * if there is any ptr in the attr structure do attr->xptr = 
     * globus_libc_strdup(attr->xptr) and do if (!attr->xptr) { result = 
     * GlobusXIOErrorMemory("xptr"); goto error_xptr; }  
     */

    *dst = attr;

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error_attr:
    GlobusXIOUdtDebugExitWithError();
    return result;
}



      /*
       *  Functionality:
       *     destroy driver attribute structure
       *  Parameters:
       *     1) [in] driver_attr: udt driver attribute
       *  Returned value:
       *     GLOBUS_SUCCESS
       */

static
globus_result_t
globus_l_xio_udt_attr_destroy(
    void *                              driver_attr)
{
    globus_l_attr_t *                   attr;
    GlobusXIOName(globus_l_xio_udt_attr_destroy);

    GlobusXIOUdtDebugEnter();

    attr = (globus_l_attr_t *) driver_attr;
    globus_free(attr);

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
}



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
    int				       res;		
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
       *     destroy driver handle
       *  Parameters:
       *     1) [in] handle: udt driver handle
       *  Returned value:
       *     None.
       */

static
void
globus_l_xio_udt_handle_destroy(
    globus_l_handle_t *                handle)
{
    GlobusXIOName(globus_l_xio_udt_handle_destroy);

    GlobusXIOUdtDebugEnter();

    globus_mutex_destroy(&handle->state_mutex);
    globus_mutex_destroy(&handle->write_mutex);
    globus_mutex_destroy(&handle->write_cntl->mutex);
    globus_mutex_destroy(&handle->read_cntl->mutex);
    globus_mutex_destroy(&handle->read_buf->mutex);
    globus_mutex_destroy(&handle->writer_loss_info->mutex);
    globus_mutex_destroy(&handle->write_buf->mutex);

    globus_free(handle->read_buf);
    globus_free(handle->reader_loss_info);
    globus_free(handle->read_history);
    globus_free(handle->irregular_pkt_info);
    globus_free(handle->read_cntl);
    globus_free(handle->write_buf);
    globus_free(handle->writer_loss_info);
    globus_free(handle->write_cntl);
    globus_free(handle->payload);
    globus_fifo_destroy(&handle->cntl_write_q);	
    /* all the above variables were allocated in handle_init */
    globus_free(handle->cntl_write_iovec);	
    globus_free(handle->attr);		/* allocated in open */
    globus_free(handle->handshake);		/* allocated in open */
    globus_free(handle);

    GlobusXIOUdtDebugExit();
}




static
void
globus_l_xio_udt_write_handshake(
    globus_l_handle_t*		handle)
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


static
void
globus_l_xio_udt_write_ack(
    globus_l_handle_t *			handle)
{

    globus_xio_iovec_t*                 iovec;
    int                                 ack = 0;
    int					last_ack; 
    int					last_ack_ack;
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
	("inside ack read_cntl->last_ack is %d curr_seqno is %d 
	reader_loss_length is %d\n", 
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
         * If there is loss, ACK is the smallest sequence number in the reader i	 * loss list.
         */
	ack = globus_l_xio_udt_get_first_reader_lost_seq(
	    handle->reader_loss_info) - last_ack;
	if (ack > GLOBUS_L_XIO_UDT_SEQ_NO_THRESH) 
	{
	  GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE, 		("difference between smallest seqno in reader loss list and 
	    handle->read_cntl->last_ack is greater than 
	    GLOBUS_L_XIO_UDT_SEQ_NO_THRESH"));
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
     * Send out the ACK only if has not been received by the writer before 
     */
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
    globus_l_handle_t *                		 handle)
{
    globus_xio_iovec_t*             		 iovec;
    int						 num_seq;
    int						 length[2];
    int*					 data;	

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


static
void
globus_l_xio_udt_write_nak(
    globus_l_handle_t *                 handle,
    int					start_seq,
    int					end_seq)
{
    globus_xio_iovec_t*                 iovec;
    int					loss_length;
    int*				loss_data;	

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

static
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
    int					ack_seqno)
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
    globus_l_handle_t *               		  handle)
{
    globus_xio_iovec_t*        		          iovec;
       
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


static
void
globus_l_xio_udt_process_ack(
    globus_l_handle_t*                  handle)
{
    int                                 ack_seqno;
    int                                 last_ack;
    int					prev_last_ack;
    int					payload_size;	
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


static
void
globus_l_xio_udt_process_nak(
    globus_l_handle_t*                  handle)
{
    int*                                losslist;
    int                                 i;
    int                                 m;
    int                                 lost_seq;
    int					last_dec_seq;
    int					local_loss = 0;
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


static
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

static
void
globus_l_xio_udt_process_congestion_warning(
    globus_l_handle_t*                 		 handle)
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

static
void
globus_l_xio_udt_process_ack_ack(
    globus_l_handle_t*                  handle)
{
    int                                 rtt;
    int                                 last_ack_ack;
    int					prev_last_ack_ack;
    GlobusXIOName(globus_l_xio_udt_process_ack_ack);
    GlobusXIOUdtDebugEnter();

    /* update RTT */
    rtt = globus_l_xio_udt_calculate_rtt_and_last_ack_ack(handle, 
	    (*(int*)handle->read_iovec[0].iov_base) & 0x0000FFFF, 
	    &last_ack_ack);

    if (rtt > 0)
    {
	globus_abstime_t                    curr_time;
	globus_reltime_t		    warning_interval;
	int				    warning_interval_usec;

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


static
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
    globus_xio_operation_t		op,
    globus_result_t			result,
    void *                              user_arg)
{
    globus_l_handle_t*                  handle;
    globus_result_t			res;
    GlobusXIOName(globus_l_xio_udt_open_failed);
    GlobusXIOUdtDebugEnter();
    
    handle = (globus_l_handle_t*) user_arg;
    res = GlobusXIOUdtErrorOpenFailed();
    globus_xio_driver_finished_open(handle->driver_handle, handle, op, 
	res);
    globus_free(handle->read_iovec[1].iov_base);
    globus_free(handle->cntl_write_iovec);
    globus_free(handle->attr);
    globus_free(handle->handshake);
    globus_free(handle);

    GlobusXIOUdtDebugExit();
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
    void*				user_arg)
{
    globus_l_handle_t*			handle;
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
    void*				user_arg)
{
    globus_l_handle_t*			handle;
    globus_result_t			result;
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
    globus_xio_driver_finished_open(handle->driver_handle, handle, 
	handle->open_op, GLOBUS_SUCCESS); 

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
    globus_size_t			nbytes,
    void *                              user_arg)
{
    globus_l_handle_t*			handle;
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
    void*                       user_arg)
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
    globus_l_handle_t *			handle;
    globus_xio_iovec_t 			iovec;
    int 				wait_for;
    int					handshake_size;	
    globus_reltime_t 			timeout;
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
    globus_l_handle_t *			handle;
    globus_l_server_t *			server;	
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
    globus_l_handle_t *				handle)
{
    globus_l_xio_udt_handshake_t *		handshake;
    int						length;	
    globus_l_server_t *				server;
    globus_result_t				result;	
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
    globus_l_handle_t *				handle)
{
    globus_l_server_t *				server;
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
    char *				cs;
    char *				port;
    unsigned char			ip[GLOBUS_L_XIO_UDT_IP_LEN];
    int					i;
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
    globus_xio_operation_t		op,
    const globus_l_attr_t *		attr)
{
    globus_result_t			result;	
    globus_l_attr_t *   	        default_attr;
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
       *     1) [in] driver_target: udt driver target structure
       *     2) [in] driver_attr: udt driver attribute structure
       *     3) [in] op: xio operation
       *  Returned value:
       *     None.
       */

static
globus_result_t
globus_l_xio_udt_open(
    void *                              driver_target,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_l_target_t *                 target;
    const globus_l_attr_t *             attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_open);

    GlobusXIOUdtDebugEnter();

    target = (globus_l_target_t *) driver_target;  
    handle = target->handle; 	
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
    result = globus_xio_driver_pass_open(
	&handle->driver_handle, 
	op,
	globus_l_xio_udt_open_cb, 
	handle);
    
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
    GlobusXIOUdtDebugExitWithError();
    return result;
}


static
void
globus_i_xio_udt_read(
    void*                       user_arg)
{

    globus_l_handle_t* handle = (globus_l_handle_t*) user_arg;
    GlobusXIOName(globus_i_xio_udt_read);

    GlobusXIOUdtDebugEnter();
   
    if (handle->state != GLOBUS_L_XIO_UDT_CLOSED)
    { 
	int offset;
	int last_ack = handle->read_cntl->last_ack;
	int payload_size = handle->payload_size;

	globus_mutex_lock(&handle->read_cntl->mutex);
	/* Look for a slot for the speculated data. */
	offset = handle->read_cntl->next_expect - last_ack;
	if (offset < -GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
	{
	    offset += GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
	}

	handle->read_cntl->next_slot_found = 
	    globus_l_xio_udt_find_read_data_pos(
		handle->read_buf, 
		(char**)&handle->read_iovec[1].iov_base, 
		offset * payload_size - 
		globus_l_xio_udt_get_error_size(
		    handle->irregular_pkt_info, offset + last_ack), 
		payload_size);
	if (handle->read_cntl->next_slot_found == GLOBUS_FALSE)
	{
	    handle->read_iovec[1].iov_base = handle->payload;
	}
	handle->read_iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
	handle->read_iovec[1].iov_len = payload_size;
	if (globus_xio_driver_pass_read(
		handle->driver_read_op, 
		handle->read_iovec, 
		2, 
		GLOBUS_L_XIO_UDT_HEADER_SIZE,
		globus_l_xio_udt_read_cb, 
		handle) != GLOBUS_SUCCESS) 
	{
            GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE, 
		("pass read failed\n"));
            goto error;
	}
    }

    globus_mutex_unlock(&handle->read_cntl->mutex);
    GlobusXIOUdtDebugExit();
    return;

error:
    globus_mutex_unlock(&handle->read_cntl->mutex);
    GlobusXIOUdtDebugExitWithError();
    return;

}


static
void
globus_l_xio_udt_finish_write(
    void*			user_arg)
{
    globus_l_handle_t*		handle;
    GlobusXIOName(globus_l_xio_udt_finish_write);
    
    GlobusXIOUdtDebugEnter();
       
    handle = (globus_l_handle_t*) user_arg; 
    globus_xio_driver_finished_write(handle->user_write_op, 
	handle->write_buf->result, handle->write_buf->nbytes);

    GlobusXIOUdtDebugExit();
}



static
void
globus_l_xio_udt_ack(
    void*			user_arg)
{
    globus_l_handle_t*		handle;
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



static
void
globus_l_xio_udt_nak(
    void*			user_arg)
{
    globus_l_handle_t*		handle;
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


static
void
globus_l_xio_udt_exp(
    void*			user_arg)
{
    globus_l_handle_t*		handle;
    GlobusXIOName(globus_l_xio_udt_exp);
	
    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    if (handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
    {
	globus_abstime_t		curr_time;	
	globus_reltime_t		diff;
	int				diff_usec;
	int				writer_loss_length;

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
    void*			user_arg)
{
    globus_l_handle_t*		handle;
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


static
void
globus_l_xio_udt_fin_close(
    void*			user_arg)
{
    globus_l_handle_t*		handle;
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


static
globus_result_t
globus_l_xio_udt_process_data(
    globus_l_handle_t*         	 handle)
{
    int				 seqno;
    int				 offset;	
    int				 payload_size;

    GlobusXIOName(globus_l_xio_udt_process_data);
    GlobusXIOUdtDebugEnter();

    /* update time/delay information */
    globus_l_xio_udt_record_pkt_arrival(handle->read_history);
    seqno = *(int*)handle->read_iovec[0].iov_base;
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_TRACE, 
	("seqno received = %d\n", seqno));

    /* check if it is probing packet pair */
    if ((seqno % GLOBUS_L_XIO_UDT_PROBE_INTERVAL) < 2)
    {	
	/* 
	 * Should definitely need { } for the if below coz 
	 * GlobusTimeAbstimeCopy is #define with {..} and 
	 * presence of ; terminates if else 
	 */
	if ((seqno % GLOBUS_L_XIO_UDT_PROBE_INTERVAL) == 0)
	{
	    GlobusTimeAbstimeGetCurrent(handle->read_history->probe_time);
	} 
	else
	{ 
	    globus_l_xio_udt_record_probe2_arrival(
		handle->read_history);
	}
    }
    /* actual offset of the received data */
    offset = seqno - handle->read_cntl->last_ack;  
    if (offset < -GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)
    {
	offset += GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
    }

    payload_size = handle->payload_size;
    if ((offset >= 0) && (offset < handle->handshake->max_flow_wnd_size))
    {
	int curr_seqno = handle->read_cntl->curr_seqno;
	/* Oops, the speculation is wrong */
	if ((seqno != handle->read_cntl->next_expect) || 
	    (handle->read_cntl->next_slot_found == GLOBUS_FALSE))
	{
	    /* 
	     * Put the received data explicitly into the right slot.
	     */
	    if (globus_l_xio_udt_add_data_to_read_buf(
		    handle->read_buf, 
		    handle->read_iovec[1].iov_base, 
		    offset * payload_size - 
		    globus_l_xio_udt_get_error_size(
		    handle->irregular_pkt_info, seqno), 
		    handle->read_iovec[1].iov_len) 
		    != GLOBUS_SUCCESS)   
	    {
		goto error_no_space;
	    }
	    else
	    {
		/* Loss detection. */
		if (((seqno > curr_seqno + 1) && (seqno - curr_seqno < 
		    GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)) || 
		    (seqno < curr_seqno - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
		{
		    globus_l_xio_udt_write_nak(handle, 
			curr_seqno + 1, seqno - 1);
		}   
	    }   
	}
	else
	{
	    if (handle->read_buf->into_udt_buf)
	    {
		handle->read_buf->max_offset -=
		    (payload_size - handle->read_iovec[1].iov_len);
	    }
	}
	/* This is not a regular fixed size packet */
	if (handle->read_iovec[1].iov_len != payload_size)
	{	
	     globus_l_xio_udt_add_irregular_pkt(
		 handle->irregular_pkt_info, seqno, 
		 payload_size - handle->read_iovec[1].iov_len);
	}

	if (((seqno > curr_seqno) && 
	    (seqno - curr_seqno < GLOBUS_L_XIO_UDT_SEQ_NO_THRESH)) || 
	    (seqno < curr_seqno - GLOBUS_L_XIO_UDT_SEQ_NO_THRESH))
	{
	    /* 
	     * The packet that has been received now is new and is not a 
	     * retransmitted one. So update the current largest seqno 
	     */
	    handle->read_cntl->curr_seqno = seqno;

	    /* Speculate next packet. */
	    handle->read_cntl->next_expect = 
		(seqno + 1) % GLOBUS_L_XIO_UDT_MAX_SEQ_NO;
	}
	else
	{
	    /* 
	     * It is a retransmitted packet, remove it from reader 
	     * loss list. 
	     */
	    globus_l_xio_udt_reader_loss_list_remove(
		handle->reader_loss_info, seqno);
	    if (handle->read_iovec[1].iov_len < payload_size)
	    { 
		globus_l_xio_udt_compact_read_buf(
		    handle->read_buf, (offset + 1) * payload_size - 
		    globus_l_xio_udt_get_error_size(
		        handle->irregular_pkt_info, seqno), 
		    payload_size - handle->read_iovec[1].iov_len);
	    }
	}
    }
    else
    {
	/* 
	 * Data is too old, discard it! 
	 */
	if (handle->read_buf->into_udt_buf)
	{
	    handle->read_buf->max_offset -= payload_size;
	}
    
    }
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error_no_space:
    GlobusXIOUdtDebugExitWithError();
    return GlobusXIOUdtErrorReadBufferFull();

}

static
void
globus_l_xio_udt_process_user_buf(
    globus_l_handle_t*         		 handle)
{
    globus_result_t			 read_result = GLOBUS_SUCCESS;
    int                         	 bytes_copied = -1;
    int					 temp_len;

    GlobusXIOName(globus_l_xio_udt_process_user_buf);
    GlobusXIOUdtDebugEnter();

    temp_len = handle->read_buf->temp_len;	
    if (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT)
    {
	int last_ack_pos = handle->read_buf->last_ack_pos;
	int start_pos = handle->read_buf->start_pos;

	if (last_ack_pos >= start_pos)
	{
	    handle->read_buf->wait_for = last_ack_pos - start_pos;
	}
	else
	{
	    handle->read_buf->wait_for =
		handle->read_buf->udt_buf_size + last_ack_pos - start_pos;
	}
	if (handle->read_buf->wait_for <= temp_len)
	{
	    read_result = GlobusXIOErrorEOF();
	}
	else
	{
	    handle->read_buf->wait_for = temp_len;
	}
    }
    bytes_copied = globus_l_xio_udt_copy_data_to_user_buf(
	handle->read_buf,  handle->read_buf->user_iovec,
	handle->read_buf->user_iovec_count, temp_len);


    handle->read_buf->user_buf = GLOBUS_FALSE;

    GlobusXIOUdtDebugPrintf(
	GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
	("bytes_copied = %d\n", bytes_copied));

    /* Still no?! Register the application buffer. */
    if (bytes_copied < handle->read_buf->wait_for)
    {
	int offset;
	offset = globus_l_xio_udt_register_user_read_buf(
	    handle->read_buf, handle->read_buf->user_iovec,
	    handle->read_buf->user_iovec_count, temp_len);
	handle->read_cntl->user_buf_border =
	    handle->read_cntl->last_ack +
	    (int)ceil((double)(handle->read_buf->user_buf_size
	     - offset) / handle->payload_size);
	GlobusXIOUdtDebugPrintf(
	    GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
	    ("user_buf_size = %d\n",
	    handle->read_buf->user_buf_size));
    }
    else
    {   
	handle->read_buf->pending_finished_read = GLOBUS_TRUE;
	handle->read_buf->result = read_result;
	handle->read_buf->nbytes = bytes_copied;
	handle->read_buf->user_buf_size = 0;
    }

    GlobusXIOUdtDebugExit();
    return;

}
   

      /*
       *  Functionality:
       *     read callback - do pass_read and take appropriate action depending 
       *     on the info read (info read may be control or data),
       *     it also checks various timers and take appropriate action
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
globus_l_xio_udt_read_cb(
    globus_xio_operation_t		op, 
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_handle_t*			handle;
    globus_abstime_t			curr_time;
    GlobusXIOName(globus_l_xio_udt_read_cb);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    GlobusTimeAbstimeGetCurrent(curr_time);
   
    /* Below is the packet receiving/processing part. */
    if ((handle->state != GLOBUS_L_XIO_UDT_PEER_DEAD) &&
	(handle->state != GLOBUS_L_XIO_UDT_CLOSED))
    {
	globus_mutex_lock(&handle->read_cntl->mutex);
	if ((result == GLOBUS_SUCCESS) || (nbytes >= 4))
	{
	    handle->read_iovec[0].iov_len = GLOBUS_L_XIO_UDT_HEADER_SIZE;
	    handle->read_iovec[1].iov_len = nbytes - 
		GLOBUS_L_XIO_UDT_HEADER_SIZE;
	    /* Just heard from the peer, reset the expiration count. */
	    handle->read_cntl->exp_count = 0;
            if (((handle->write_cntl->curr_seqno + 1) % 
		GLOBUS_L_XIO_UDT_MAX_SEQ_NO) 
		== handle->write_cntl->last_ack)
	    {
                GlobusTimeAbstimeCopy(handle->read_cntl->time_last_heard,
			curr_time);
	    }
	    /* But this is control packet, process it! */
	    if ((*(int*)handle->read_iovec[0].iov_base) >> 31)
	    {
		int pkt_type = ((*(int*)handle->read_iovec[0].iov_base) >> 28) 
				& 0x00000007;
		switch (pkt_type)
		{
		/*000 - Unused */
		case GLOBUS_L_XIO_UDT_UNUSED:
		    break;

		/*001 - Keep-alive */
		case GLOBUS_L_XIO_UDT_KEEPALIVE:
		    /*
		     * The only purpose of keep-alive packet is to tell the 
		     * peer is still alive nothing need to be done.
		     */
		    break;
		/* 
		 * pkt_type 2,3 and 4 alone can tell a writer that reader has 
		 * received new data or not. Keepalive can be sent even 
		 * there is no packet writing/receiving. 
		 */

		/*010 - Acknowledgement */
		case GLOBUS_L_XIO_UDT_ACK:
		    GlobusTimeAbstimeCopy(
			handle->read_cntl->time_last_heard, curr_time);
		    globus_l_xio_udt_process_ack(handle);
		    break;

		/*011 - Loss Report */
		case GLOBUS_L_XIO_UDT_NAK:
		    GlobusTimeAbstimeCopy(
			handle->read_cntl->time_last_heard, curr_time);
		    globus_l_xio_udt_process_nak(handle);
		    break;

		/*100 - Delay Warning */
		case GLOBUS_L_XIO_UDT_CONGESTION_WARNING:
		    GlobusTimeAbstimeCopy(
			handle->read_cntl->time_last_heard, curr_time);
		    globus_l_xio_udt_process_congestion_warning(handle);
		    break;

		/*101 - Unused */
		case GLOBUS_L_XIO_UDT_FIN:
		    globus_l_xio_udt_process_fin(handle);
		    break;

		/*110 - Acknowledgement of Acknowledgement */
		case GLOBUS_L_XIO_UDT_ACK_ACK:
		    globus_l_xio_udt_process_ack_ack(handle);
		    break;

		/*111 - Reserved for future use */
		case GLOBUS_L_XIO_UDT_FIN_ACK:
		    globus_l_xio_udt_process_fin_ack(handle);
		    break;

		default:
		    break;
		}
                if (handle->read_buf->into_udt_buf)
                {
                    handle->read_buf->max_offset -= handle->payload_size;
                }
	    }
	    else if ((handle->state == GLOBUS_L_XIO_UDT_CONNECTED) ||
		     (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT))	
	    {
		if (globus_l_xio_udt_process_data(handle)
			!= GLOBUS_SUCCESS)
		{
		    goto error;
		}
	    }
	}
        else        
        {           
            if (handle->read_buf->into_udt_buf)
            {   
                handle->read_buf->max_offset -= handle->payload_size;
            }       
        } 
              
	globus_mutex_lock(&handle->read_buf->mutex);
        if (((handle->state == GLOBUS_L_XIO_UDT_CONNECTED) ||
            (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT)) &&
            (handle->read_buf->user_buf == GLOBUS_TRUE))
        {
	    globus_l_xio_udt_process_user_buf(handle);

        }       
	globus_mutex_unlock(&handle->read_buf->mutex);

        handle->read_buf->into_udt_buf = GLOBUS_FALSE;
	globus_callback_register_oneshot(NULL, NULL, 
	    globus_i_xio_udt_read, handle); 
	globus_mutex_unlock(&handle->read_cntl->mutex);
    }
    if (handle->write_buf->pending_finished_write)
    {
	handle->write_buf->pending_finished_write = GLOBUS_FALSE;
        globus_callback_register_oneshot(NULL, NULL,
            globus_l_xio_udt_finish_write, handle);
    }		
    globus_mutex_lock(&handle->read_buf->mutex);
    if (handle->read_buf->pending_finished_read)
    {
       GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE, 
	("read finished nbytes = %d\n", 
	handle->read_buf->nbytes));
	handle->read_buf->pending_finished_read = GLOBUS_FALSE;
	globus_mutex_unlock(&handle->read_buf->mutex);
	globus_xio_driver_finished_read(handle->user_read_op, 
	    handle->read_buf->result, handle->read_buf->nbytes);
    }
    else
    {		
	globus_mutex_unlock(&handle->read_buf->mutex);
    }

    GlobusXIOUdtDebugExit();
    return;

error:
    globus_mutex_unlock(&handle->read_cntl->mutex);
    GlobusXIOUdtDebugExitWithError();
    return;
}



      /*
       *  Functionality:
       *     This gets called when user calls globus_xio_read. if enough data 
       *     is already read into the protocol buffer, it just copies that data 
       *     to user buf, else it registers the user buffer so that the later 
       *     arriving data could directly be placed into the user buf 
       *  Parameters:
       *     1) [in] driver_handle: udt driver handle
       *     2) [in] iovec: user's vector
       *     3) [in] iovec_count: vector count
       *     4) [in] op: xio operation 
       *  Returned value:
       *     GLOBUS_SUCCESS
       */

static
globus_result_t
globus_l_xio_udt_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t* 	        iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_result_t		 	result = GLOBUS_SUCCESS;

    GlobusXIOName(globus_l_xio_udt_read);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t *) driver_specific_handle;
    if ((handle->state == GLOBUS_L_XIO_UDT_CONNECTED) ||
	(handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT))
    {
	int len = 0;
	int i;
	globus_result_t	read_result = GLOBUS_SUCCESS;
	int bytes_copied;

	/* Check if there is enough data now. */
	for (i = iovec_count - 1; i >= 0; --i)
	{
	    len += iovec[i].iov_len;
	}
        globus_mutex_lock(&handle->read_buf->mutex);
        handle->read_buf->user_iovec = (globus_xio_iovec_t*)iovec;
        handle->read_buf->temp_len = len;
        handle->read_buf->user_iovec_count = iovec_count;
	handle->user_read_op = op;
	handle->read_buf->wait_for =
	    GlobusXIOOperationGetWaitFor(handle->user_read_op);
	GlobusXIOUdtDebugPrintf(
	    GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
	    ("inside read wait_for = %d len = %d\n",
	    handle->read_buf->wait_for, len));
	if (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT)
	{
	    int last_ack_pos = handle->read_buf->last_ack_pos;	
	    int start_pos = handle->read_buf->start_pos;	
	    int temp_len = handle->read_buf->temp_len;
	
	    if (last_ack_pos >= start_pos)
	    {   
		handle->read_buf->wait_for = last_ack_pos - start_pos;
	    }
	    else
	    {
		handle->read_buf->wait_for =
		    handle->read_buf->udt_buf_size + last_ack_pos - start_pos;
	    }
	    if (handle->read_buf->wait_for <= temp_len)
	    {
		read_result = GlobusXIOErrorEOF();
	    }
	    else
	    {
		handle->read_buf->wait_for = temp_len;
	    }
	}
	bytes_copied = globus_l_xio_udt_copy_data_to_user_buf(
	    handle->read_buf,  handle->read_buf->user_iovec,
	    handle->read_buf->user_iovec_count,
	    handle->read_buf->temp_len);

        if (bytes_copied >= handle->read_buf->wait_for)
	{
	    globus_mutex_unlock(&handle->read_buf->mutex);
	    globus_xio_driver_finished_read(op,
		read_result, bytes_copied);
	}
	else
	{
	    handle->read_buf->user_buf = GLOBUS_TRUE;
	    globus_mutex_unlock(&handle->read_buf->mutex);
	}
    }
    else
    {
        result = GlobusXIOUdtErrorBrokenConnection();
    }

    GlobusXIOUdtDebugExit();
    return result;
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
    globus_l_handle_t* 			handle;
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
    globus_reltime_t 		inter_pkt_interval;
    int 			i;
    int				payload_size;	
    globus_result_t 		result;

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
    globus_l_handle_t*          		handle,
    int						seqno)
{
    int                   		        payload_size;
    int						offset;	

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
	    ("Retransmit failed. seqno is [%d],
	    write_cntl->last_ack is [%d]\n", seqno,
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
    globus_l_handle_t*		handle)
{
    int				payload_size;	
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

static
void
globus_i_xio_udt_write(
    globus_l_handle_t*		handle)
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
    void*			user_arg)
{
    globus_l_handle_t*		handle;
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

static
globus_result_t
globus_l_xio_udt_write(
    void *                           		 driver_specific_handle,
    const globus_xio_iovec_t *         		 iovec,
    int                              		 iovec_count,
    globus_xio_operation_t             		 op)
{

    globus_l_handle_t*                		 handle;
    globus_result_t				 result = GLOBUS_SUCCESS; 
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



/*
 *  close a udt connection
 */

static
void
globus_l_xio_udt_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_handle_t*                  handle;
    GlobusXIOName(globus_l_xio_udt_close_cb);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t *) user_arg;
    globus_xio_driver_finished_close(op, result);
    globus_xio_driver_handle_close(handle->driver_handle);
    globus_l_xio_udt_handle_destroy(handle);

    GlobusXIOUdtDebugExit();
    return;
}


static
void
globus_i_xio_udt_pass_close(
    void*                                       user_arg)
{
    globus_l_handle_t*				handle;
    GlobusXIOName(globus_i_xio_udt_pass_close);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    globus_xio_driver_pass_close(handle->close_op, globus_l_xio_udt_close_cb, 
	handle);

    GlobusXIOUdtDebugExit();
}


static
globus_result_t
globus_l_xio_udt_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_driver_handle_t          driver_handle,
    globus_xio_operation_t              op)
{
    globus_l_handle_t*                  handle;
    GlobusXIOName(globus_l_xio_udt_close);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t *) driver_specific_handle;
    globus_mutex_lock(&handle->state_mutex);
    if (handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
    {
	handle->state = GLOBUS_L_XIO_UDT_FIN_WAIT1;
	globus_l_xio_udt_write_fin(handle);
    }
    else if (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT)
    {
	globus_reltime_t timeout;
	handle->state = GLOBUS_L_XIO_UDT_LAST_ACK;
	globus_l_xio_udt_write_fin(handle);
	GlobusTimeReltimeSet(timeout, 0, 
	    2 * GLOBUS_L_XIO_UDT_CLOSE_TIMEOUT);
	globus_callback_register_oneshot(&handle->fin_close_handle, 
	    &timeout, globus_l_xio_udt_fin_close, handle);
    }
    else if (handle->state == GLOBUS_L_XIO_UDT_PEER_DEAD)
    {
	globus_l_xio_udt_pass_close(handle);
    }
    handle->close_op = op;
    globus_mutex_unlock(&handle->state_mutex);
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_udt_pass_close(
    void*			user_arg)
{
    globus_l_handle_t*		handle;	
    globus_result_t		result;
    GlobusXIOName(globus_l_xio_udt_pass_close);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*)user_arg;
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
	("handle state is %d\n", handle->state));
    handle->state = GLOBUS_L_XIO_UDT_CLOSED;	
    globus_xio_driver_operation_cancel(handle->driver_handle, 
	handle->driver_write_op);
    globus_xio_driver_operation_cancel(handle->driver_handle, 
	handle->driver_read_op);
/*    globus_callback_unregister(handle->exp_handle, NULL, NULL, NULL);	
    globus_callback_unregister(handle->nak_handle, NULL, NULL, NULL);	
    globus_callback_unregister(handle->ack_handle, NULL, NULL, NULL);	
    globus_callback_unregister(handle->fin_handle, NULL, NULL, NULL);	*/
    result = globus_callback_unregister(handle->write_handle, 
	globus_i_xio_udt_pass_close, handle, NULL);
    if (result != GLOBUS_SUCCESS)
    {
	globus_xio_driver_pass_close(handle->close_op, 
	    globus_l_xio_udt_close_cb, handle);
    }
    GlobusXIOUdtDebugExit();
}



static
globus_result_t
globus_l_xio_udt_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_handle_t *                 handle;
    globus_result_t			result;
    int *                               out_int;
    globus_bool_t *                     out_bool;
    int                                 in_int;
    char **                             out_string;
    globus_xio_system_handle_t *        out_handle;

    GlobusXIOName(globus_l_xio_udt_cntl);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t *) driver_specific_handle;

    switch(cmd)
    {
      /* globus_xio_system_handle_t *   handle_out */
      case GLOBUS_XIO_UDT_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
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
      case GLOBUS_XIO_UDT_GET_REMOTE_CONTACT:
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


static
globus_result_t
globus_l_xio_udt_push_driver(
    globus_xio_driver_t                 driver,
    globus_xio_stack_t                  stack)
{
    globus_result_t			result;
    GlobusXIOName(globus_l_xio_udt_push_driver);

    GlobusXIOUdtDebugEnter();

    result = globus_xio_stack_push_driver(stack, globus_l_xio_udt_udp_driver);
    if (result == GLOBUS_SUCCESS)
    {
        result = globus_xio_stack_push_driver(stack, driver);
    }	

    GlobusXIOUdtDebugExit();
    return result;
}


static
int
globus_l_xio_udt_priority_q_cmp_func(
    void *				priority_1,
    void *				priority_2)
{
    globus_abstime_t *			timestamp_1;				
    globus_abstime_t *			timestamp_2;				
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
    globus_xio_handle_t			    xio_handle,
    globus_result_t			    result,
    globus_byte_t *			    buffer,
    globus_size_t			    len,
    globus_size_t			    nbytes,
    globus_xio_data_descriptor_t	    data_desc,
    void *				    user_arg)
{
    globus_l_server_t *			    server;
    globus_l_handle_t *			    handle;
    globus_l_xio_udt_handshake_t *	    handshake;
    globus_l_xio_udt_connection_info_t *  connection_info;	
    globus_xio_contact_t		    contact_info;
    globus_l_target_t *			    target;	
    globus_xio_operation_t		    op;
    unsigned char                      	    ipnum[GLOBUS_L_XIO_UDT_IP_LEN];
    char                                    ipstr[GLOBUS_L_XIO_UDT_IP_LEN];
    char                                    port[GLOBUS_L_XIO_UDT_IP_LEN];
    char *                                  cs;
    char *				    contact=NULL;		
    int					    i;
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
	if (server->target_op)
	{
	    op = server->target_op;	
	    server->target_op = NULL;	
	    target = (globus_l_target_t*)globus_malloc
		(sizeof(globus_l_target_t));
	    target->handle = handle;
	    handle->state = GLOBUS_L_XIO_UDT_PROCESSING;
	    memset(&contact_info, 0, sizeof(globus_xio_contact_t));
	    contact_info.host = ipstr;
	    contact_info.port = port;
	    result = globus_xio_driver_client_target_pass(op, &contact_info);
	    if (result != GLOBUS_SUCCESS)
	    {
		goto error;
	    }	
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
    if (op)	
    {	
        globus_xio_driver_finished_accept(op, target, GLOBUS_SUCCESS);
    }	
    GlobusXIOUdtDebugExit(); 
    return;

error_dd_destroy:
error_dd_init:
error:
    GlobusXIOUdtDebugExitWithError(); 
    return;
}



static
globus_result_t
globus_l_xio_udt_server_init(
    void **                             out_ds_server,
    void *                              driver_attr)
{
    globus_l_handle_t *			handle;
    globus_l_server_t *                 server;
    globus_l_attr_t *                   server_attr;
    globus_xio_target_t			target;
    globus_xio_attr_t			attr = NULL;
    globus_result_t                     result;
    int					res;	
    globus_l_xio_udt_handshake_t *    handshake;
    int					handshake_size;
    char*				cs;	
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
    result = globus_xio_target_init(
		&target, 
		NULL, 
		NULL, 
		globus_l_xio_udt_server_stack);
    if (result != GLOBUS_SUCCESS)
    {
	goto error_target_init;
    }	
    server = (globus_l_server_t *) globus_malloc(sizeof(globus_l_server_t));
    if(!server)
    {
        result = GlobusXIOErrorMemory("server");
        goto error_server;
    }
    result = globus_xio_open(
		&server->xio_handle, 
		attr, 
		target);

    if (result != GLOBUS_SUCCESS)
    {
	goto error_open;
    }
    	
    result = globus_xio_handle_cntl(
		server->xio_handle,
		globus_l_xio_udt_server_udp_driver,
		GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,
		&cs);
    fprintf(stderr, "%s\n", cs);
    globus_free(cs);	
    if (result != GLOBUS_SUCCESS)	
    {
	goto error_handle_cntl;
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
    server->target_op = NULL;
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
	
    *out_ds_server = server;
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
    globus_xio_close(server->xio_handle, NULL);

error_handle_cntl:
error_open:
    globus_free(server);

error_server:
    globus_xio_target_destroy(target);

error_target_init:
error_attr_cntl:
    globus_xio_attr_destroy(attr);

error:
    GlobusXIOUdtDebugExitWithError();
    return result;	

}


static
globus_result_t
globus_l_xio_udt_server_accept(
    void *					driver_server,
    void *					driver_attr,
    globus_xio_operation_t			target_op)
{
    globus_l_server_t *				server;
    globus_l_target_t *				target;
    globus_result_t				result;
    globus_l_xio_udt_connection_info_t *   	connection_info;
    char *					cs;
    globus_xio_contact_t			contact_info;
    globus_abstime_t				current_time;	
    globus_abstime_t*				timestamp;	
    globus_reltime_t				max_ttl;	
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
    }
    connection_info = NULL;
    
    if (!globus_priority_q_empty(&server->clients_priority_q))
    {	
	connection_info = (globus_l_xio_udt_connection_info_t*)
	    globus_priority_q_dequeue(&server->clients_priority_q);
	target = (globus_l_target_t*)globus_malloc(sizeof(globus_l_target_t));
	target->handle = connection_info->handle;
	memset(&contact_info, 0, sizeof(globus_xio_contact_t));
	cs = globus_libc_strdup(connection_info->handle->remote_cs);
	contact_info.host = cs;
	contact_info.port = strrchr(cs, ':');
	*contact_info.port = 0;
	contact_info.port++;
	result = globus_xio_driver_client_target_pass(
	    target_op, &contact_info);
	if (result != GLOBUS_SUCCESS)
	{
	    goto error;
	}
	connection_info->handle->state = GLOBUS_L_XIO_UDT_PROCESSING;
    }
    else
    {
	server->target_op = target_op;
    }
			
    globus_mutex_unlock(&server->mutex);
    if (connection_info)
    {
	globus_xio_driver_finished_accept(target_op, target,
	    GLOBUS_SUCCESS);
    }			
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;	

error:
    GlobusXIOUdtDebugExit();
    return result;	
}



static
globus_result_t
globus_l_xio_udt_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_server_t *                 server;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char **                             out_string;
    globus_xio_system_handle_t *        out_handle;
    GlobusXIOName(globus_l_xio_udt_server_cntl);

    GlobusXIOUdtDebugEnter();
    server = (globus_l_server_t *) driver_server;

    switch(cmd)
    {
      /* globus_xio_system_handle_t *   handle_out */
      case GLOBUS_XIO_UDT_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        result = globus_xio_data_descriptor_cntl(
            server->data_desc,
            globus_l_xio_udt_server_udp_driver,
            GLOBUS_XIO_UDP_GET_HANDLE,
            out_handle);
//        *out_handle = GLOBUS_XIO_UDT_INVALID_HANDLE;
        break;

      /* char **                        contact_string_out */
      case GLOBUS_XIO_UDT_GET_LOCAL_NUMERIC_CONTACT:
        out_string = va_arg(ap, char **);
	result = globus_xio_handle_cntl(
	    server->xio_handle,
	    globus_l_xio_udt_server_udp_driver,
	    GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,
	    out_string);
	break;
      case GLOBUS_XIO_UDT_GET_LOCAL_CONTACT:
        out_string = va_arg(ap, char **);
        result = globus_xio_handle_cntl(
            server->xio_handle,
            globus_l_xio_udt_server_udp_driver,
            GLOBUS_XIO_UDP_GET_CONTACT,
            out_string);
	break;
      case GLOBUS_XIO_UDT_GET_REMOTE_NUMERIC_CONTACT:
        out_string = va_arg(ap, char **);
	result = globus_xio_data_descriptor_cntl(
	    server->data_desc,
	    globus_l_xio_udt_server_udp_driver,
	    GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,
	    out_string);
	break;
      case GLOBUS_XIO_UDT_GET_REMOTE_CONTACT:
        out_string = va_arg(ap, char **);
	result = globus_xio_data_descriptor_cntl(
	    server->data_desc,
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
    void *					user_arg)
{
    globus_l_xio_udt_connection_info_t *	connection_info;
    GlobusXIOName(globus_l_xio_udt_server_hashtable_destroy_cb);
    
    GlobusXIOUdtDebugEnter();
    
    connection_info = (globus_l_xio_udt_connection_info_t *)user_arg;
    globus_free(connection_info->handle->remote_cs);
    globus_free(connection_info);

    GlobusXIOUdtDebugExit();
}

*/


static
globus_result_t
globus_l_xio_udt_server_destroy(
    void *                              driver_server)
{
//    globus_l_server_t *                 server;
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


/*
 *  initialize target structure
 */
static
globus_result_t
globus_l_xio_udt_target_init(
    void **					out_driver_target,
    globus_xio_operation_t                 	target_op,
    const globus_xio_contact_t *            	contact_info,
    void *                                  	driver_attr)
{
    globus_l_target_t * 	                target;
    globus_l_handle_t *				handle;	
    globus_result_t             	        result;
    GlobusXIOName(globus_l_xio_udt_target_init);

    GlobusXIOUdtDebugEnter();

    target = (globus_l_target_t *) globus_malloc(sizeof(globus_l_target_t));
    if (!target)
    {
        result = GlobusXIOErrorMemory("target");
        goto error_target;
    }
    handle = (globus_l_handle_t *) globus_malloc(sizeof(globus_l_handle_t));
    if (!handle)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error_handle;
    }
    handle->server = NULL;
    target->handle = handle;
    *out_driver_target = target;
    globus_xio_driver_client_target_pass(target_op, contact_info);

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error_handle:
    globus_free(target);

error_target:
    GlobusXIOUdtDebugExitWithError();
    return result;
}


static
globus_result_t
globus_l_xio_udt_target_cntl(
    void *                              driver_target,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_target_t *                 target;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char **                             out_string;
    globus_xio_system_handle_t *        out_handle;
    GlobusXIOName(globus_l_xio_udt_target_cntl);

    GlobusXIOUdtDebugEnter();
    target = (globus_l_target_t *) driver_target;

    switch(cmd)
    {
      /* globus_xio_system_handle_t *   handle_out */
      case GLOBUS_XIO_UDT_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        result = globus_xio_driver_handle_cntl(
            target->handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_HANDLE,
            out_handle);
//        *out_handle = GLOBUS_XIO_UDT_INVALID_HANDLE;
        break;

      /* char **                        contact_string_out */
      case GLOBUS_XIO_UDT_GET_LOCAL_NUMERIC_CONTACT:
        out_string = va_arg(ap, char **);
        result = globus_xio_driver_handle_cntl(
            target->handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,
            out_string);
        break;
      case GLOBUS_XIO_UDT_GET_LOCAL_CONTACT:
        out_string = va_arg(ap, char **);
        result = globus_xio_driver_handle_cntl(
            target->handle->driver_handle,
            globus_l_xio_udt_udp_driver,
            GLOBUS_XIO_UDP_GET_CONTACT,
            out_string);
        break;
      case GLOBUS_XIO_UDT_GET_REMOTE_NUMERIC_CONTACT:
      case GLOBUS_XIO_UDT_GET_REMOTE_CONTACT:
        out_string = va_arg(ap, char **);
	*out_string = globus_libc_strdup(target->handle->remote_cs);
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
 *  destroy the target structure
 */
static
globus_result_t
globus_l_xio_udt_target_destroy(
    void *                              driver_target)
{
    globus_l_target_t *                 target;
    GlobusXIOName(globus_l_xio_udt_target_destroy);

    GlobusXIOUdtDebugEnter();

    target = (globus_l_target_t *)driver_target;
    globus_free(target);

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
}


static
globus_result_t
globus_l_xio_udt_init(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_init);

    GlobusXIOUdtDebugEnter();

    /* I dont support any driver options, so I'll ignore the ap */

    result = globus_xio_driver_init(&driver, "udt", GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_driver_init", result);
        goto error_init;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_udt_open,
        globus_l_xio_udt_close,
        globus_l_xio_udt_read,
        globus_l_xio_udt_write,
        globus_l_xio_udt_cntl,
	globus_l_xio_udt_push_driver);

    globus_xio_driver_set_client(
        driver,
        globus_l_xio_udt_target_init,
	globus_l_xio_udt_target_cntl,
        globus_l_xio_udt_target_destroy);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_udt_server_init,
        globus_l_xio_udt_server_accept,
        globus_l_xio_udt_server_destroy,
        globus_l_xio_udt_server_cntl,
        globus_l_xio_udt_target_destroy);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_udt_attr_init,
        globus_l_xio_udt_attr_copy,
        globus_l_xio_udt_attr_cntl,
        globus_l_xio_udt_attr_destroy);

    *out_driver = driver;

    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;

error_init:
    GlobusXIOUdtDebugExitWithError();
    return result;
}

static
void
globus_l_xio_udt_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}


GlobusXIODefineDriver(
    udt,
    &globus_i_xio_udt_module,
    globus_l_xio_udt_init,
    globus_l_xio_udt_destroy);

