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

#ifndef GLOBUS_XIO_UDT_DRIVER_INCLUDE
#define GLOBUS_XIO_UDT_DRIVER_INCLUDE

#include "globus_xio_system.h"
#include "globus_xio_udp_driver.h"
#include "globus_xio_tcp_driver.h"

/* udt constants */

#define GLOBUS_L_XIO_UDT_SYN_INTERVAL 		10000
#define GLOBUS_L_XIO_UDT_CLOSE_TIMEOUT 		300000
#define GLOBUS_L_XIO_UDT_READ_CANCEL_INTERVAL	30000
#define GLOBUS_L_XIO_UDT_MAX_SEQ_NO 		1073741824  /* 1<<30 */
#define GLOBUS_L_XIO_UDT_SEQ_NO_THRESH		536870912   /* 1<<29 */
#define GLOBUS_L_XIO_UDT_MAX_ACK_SEQ_NO 	65536	    /* 1<<16 */
#define GLOBUS_L_XIO_UDT_PROBE_INTERVAL	 	16 
#define GLOBUS_L_XIO_UDT_LOSS_RATE_LIMIT 	0.01
#define GLOBUS_L_XIO_UDT_WEIGHT 		0.125
#define MAX_COUNT				50
#define GLOBUS_L_XIO_UDT_RTT		 	200000

#define GLOBUS_L_XIO_UDT_MAX_TTL_SEC		2
#define GLOBUS_L_XIO_UDT_MAX_TTL_USEC		50000
#define GLOBUS_L_XIO_UDT_SERVER_HASHTABLE_SIZE	128
#define GLOBUS_L_XIO_UDT_READ_HISTORY_SIZE 	16
#define GLOBUS_L_XIO_UDT_HEADER_SIZE 		4
#define GLOBUS_L_XIO_UDT_MAX_HS_COUNT 		10
#define GLOBUS_L_XIO_UDT_MAX_FIN_COUNT 		10
#define GLOBUS_L_XIO_UDT_MAX_EXP_COUNT 		25
#define GLOBUS_L_XIO_UDT_IP_LEN 		16

#define GLOBUS_XIO_UDT_INVALID_HANDLE GLOBUS_XIO_SYSTEM_INVALID_SOCKET

typedef enum
{

    GLOBUS_XIO_UDT_ERROR_OPEN_FAILED,
    GLOBUS_XIO_UDT_ERROR_BROKEN_CONNECTION,
    GLOBUS_XIO_UDT_ERROR_READ_BUFFER_FULL

} globus_xio_udt_error_type_t;


typedef enum
{
    /**
     *  server attrs 
     */
    /* const char *                     service_name */
    GLOBUS_XIO_UDT_SET_SERVICE = GLOBUS_XIO_TCP_SET_SERVICE,         
    /* char **                          service_name_out */
    GLOBUS_XIO_UDT_GET_SERVICE = GLOBUS_XIO_TCP_GET_SERVICE,         
    /* int                              listener_port */
    GLOBUS_XIO_UDT_SET_PORT = GLOBUS_XIO_TCP_SET_PORT,            
    /* int *                            listener_port_out */
    GLOBUS_XIO_UDT_GET_PORT = GLOBUS_XIO_TCP_GET_PORT,            
    /* int                              listener_backlog */
    GLOBUS_XIO_UDT_SET_BACKLOG = GLOBUS_XIO_TCP_SET_BACKLOG,         
    /* int *                            listener_backlog_out */
    GLOBUS_XIO_UDT_GET_BACKLOG = GLOBUS_XIO_TCP_GET_BACKLOG,         
    /* int                              listener_min_port */
    /* int                              listener_max_port */
    GLOBUS_XIO_UDT_SET_LISTEN_RANGE = GLOBUS_XIO_TCP_SET_LISTEN_RANGE,
    /* int *                            listener_min_port_out */
    /* int *                            listener_max_port_out */
    GLOBUS_XIO_UDT_GET_LISTEN_RANGE = GLOBUS_XIO_TCP_GET_LISTEN_RANGE,

    /**
     *  handle/server attrs, handle cntl
     */
    /* globus_xio_system_socket_t *     handle_out */
    GLOBUS_XIO_UDT_GET_HANDLE = GLOBUS_XIO_TCP_GET_HANDLE,

    /**
     *  handle/server attrs
     */
    /* globus_xio_system_socket_t       handle */
    GLOBUS_XIO_UDT_SET_HANDLE = GLOBUS_XIO_TCP_SET_HANDLE,
    /* const char *                     interface */
    GLOBUS_XIO_UDT_SET_INTERFACE = GLOBUS_XIO_TCP_SET_INTERFACE,       
    /* char **                          interface_out */
    GLOBUS_XIO_UDT_GET_INTERFACE = GLOBUS_XIO_TCP_GET_INTERFACE,
    /* globus_bool_t                    restrict_port */
    GLOBUS_XIO_UDT_SET_RESTRICT_PORT = GLOBUS_XIO_TCP_SET_RESTRICT_PORT,
    /* globus_bool_t *                  restrict_port_out */
    GLOBUS_XIO_UDT_GET_RESTRICT_PORT = GLOBUS_XIO_TCP_GET_RESTRICT_PORT,
    /* globus_bool_t                    resuseaddr */
    GLOBUS_XIO_UDT_SET_REUSEADDR = GLOBUS_XIO_TCP_SET_REUSEADDR,
    /* globus_bool_t *                  resuseaddr_out */
    GLOBUS_XIO_UDT_GET_REUSEADDR = GLOBUS_XIO_TCP_GET_REUSEADDR,
    /* globus_bool_t                    no_ipv6 */
    GLOBUS_XIO_UDT_SET_NO_IPV6 = GLOBUS_XIO_TCP_SET_NO_IPV6,
    /* globus_bool_t *                  no_ipv6_out */
    GLOBUS_XIO_UDT_GET_NO_IPV6 = GLOBUS_XIO_TCP_GET_NO_IPV6,

    /**
     *  handle attrs
     */
    /* int                              connector_min_port */
    /* int                              connector_max_port */
    GLOBUS_XIO_UDT_SET_CONNECT_RANGE = GLOBUS_XIO_TCP_SET_CONNECT_RANGE,
    /* int *                            connector_min_port_out */
    /* int *                            connector_max_port_out */
    GLOBUS_XIO_UDT_GET_CONNECT_RANGE = GLOBUS_XIO_TCP_GET_CONNECT_RANGE,

    /**
     *  handle attrs/cntls
     */
    /* globus_bool_t                    keepalive */
    GLOBUS_XIO_UDT_SET_KEEPALIVE = GLOBUS_XIO_TCP_SET_KEEPALIVE,
    /* globus_bool_t *                  keepalive_out */
    GLOBUS_XIO_UDT_GET_KEEPALIVE = GLOBUS_XIO_TCP_GET_KEEPALIVE,
    /* globus_bool_t                    linger */
    /* int                              linger_time */
    GLOBUS_XIO_UDT_SET_LINGER = GLOBUS_XIO_TCP_SET_LINGER,
    /* globus_bool_t *                  linger_out */
    /* int *                            linger_time_out */
    GLOBUS_XIO_UDT_GET_LINGER = GLOBUS_XIO_TCP_GET_LINGER,
    /* globus_bool_t                    oobinline */
    GLOBUS_XIO_UDT_SET_OOBINLINE = GLOBUS_XIO_TCP_SET_OOBINLINE,
    /* globus_bool_t *                  oobinline_out */
    GLOBUS_XIO_UDT_GET_OOBINLINE = GLOBUS_XIO_TCP_GET_OOBINLINE,
    /* int                              sndbuf */
    GLOBUS_XIO_UDT_SET_SNDBUF = GLOBUS_XIO_TCP_SET_SNDBUF,
    /* int *                            sndbuf_out */
    GLOBUS_XIO_UDT_GET_SNDBUF = GLOBUS_XIO_TCP_GET_SNDBUF,
    /* int                              rcvbuf */
    GLOBUS_XIO_UDT_SET_RCVBUF = GLOBUS_XIO_TCP_SET_RCVBUF,
    /* int *                            rcvbuf_out */
    GLOBUS_XIO_UDT_GET_RCVBUF = GLOBUS_XIO_TCP_GET_RCVBUF,
    /* globus_bool_t                    nodelay */
    GLOBUS_XIO_UDT_SET_NODELAY = GLOBUS_XIO_TCP_SET_NODELAY,
    /* globus_bool_t *                  nodelay_out */
    GLOBUS_XIO_UDT_GET_NODELAY = GLOBUS_XIO_TCP_GET_NODELAY,

    /**
     * data descriptors
     */
    /* int                              send_flags */
    GLOBUS_XIO_UDT_SET_SEND_FLAGS = GLOBUS_XIO_TCP_SET_SEND_FLAGS,
    /* int *                            send_flags_out */
    GLOBUS_XIO_UDT_GET_SEND_FLAGS = GLOBUS_XIO_TCP_GET_SEND_FLAGS,

    /**
     * handle/server/target cntls
     */
    /* char **                          contact_string_out */
    GLOBUS_XIO_UDT_GET_LOCAL_CONTACT = GLOBUS_XIO_TCP_GET_LOCAL_CONTACT,
    /* char **                          contact_string_out */
    GLOBUS_XIO_UDT_GET_LOCAL_NUMERIC_CONTACT = 
	GLOBUS_XIO_TCP_GET_LOCAL_NUMERIC_CONTACT,
    /* char **                          contact_string_out */
    GLOBUS_XIO_UDT_GET_REMOTE_CONTACT = GLOBUS_XIO_TCP_GET_REMOTE_CONTACT,
    /* char **                          contact_string_out */
    GLOBUS_XIO_UDT_GET_REMOTE_NUMERIC_CONTACT = 
	GLOBUS_XIO_TCP_GET_REMOTE_NUMERIC_CONTACT,

    /* int                              udt buf */
    GLOBUS_XIO_UDT_SET_PROTOCOL_BUF,
    /* int *                            udt buf_out */
    GLOBUS_XIO_UDT_GET_PROTOCOL_BUF,
    /* int                              max_segment_size */
    GLOBUS_XIO_UDT_SET_MSS,
    /* int *                            max_segment_size_out */
    GLOBUS_XIO_UDT_GET_MSS,
    /* int                              window_size */
    GLOBUS_XIO_UDT_SET_WND_SIZE,

    /* int *                            window_size_out */
    GLOBUS_XIO_UDT_GET_WND_SIZE

} globus_xio_udt_cmd_t;


typedef enum 
{
    GLOBUS_L_XIO_UDT_QUEUED,
    GLOBUS_L_XIO_UDT_PROCESSING,     	
    GLOBUS_L_XIO_UDT_CONNECTED,  	/* connection established */
    GLOBUS_L_XIO_UDT_FIN_WAIT1,		/* associated with close state m/c */ 
    GLOBUS_L_XIO_UDT_FIN_WAIT2,		/*  	-- do --	*/
    GLOBUS_L_XIO_UDT_CLOSING,     	/*      -- do --        */
    GLOBUS_L_XIO_UDT_TIME_WAIT,		/*      -- do --        */ 
    GLOBUS_L_XIO_UDT_CLOSE_WAIT,	/*      -- do --        */ 
    GLOBUS_L_XIO_UDT_LAST_ACK,     	/*      -- do --        */
    GLOBUS_L_XIO_UDT_CLOSED,     	/*      -- do --        */
    GLOBUS_L_XIO_UDT_PEER_DEAD     	/* No message from peer for long time */
} globus_xio_udt_state_t;

typedef enum
{
    GLOBUS_L_XIO_UDT_UNUSED,
    GLOBUS_L_XIO_UDT_KEEPALIVE,
    GLOBUS_L_XIO_UDT_ACK,
    GLOBUS_L_XIO_UDT_NAK,
    GLOBUS_L_XIO_UDT_CONGESTION_WARNING,
    GLOBUS_L_XIO_UDT_FIN,
    GLOBUS_L_XIO_UDT_ACK_ACK,
    GLOBUS_L_XIO_UDT_FIN_ACK
} globus_xio_udt_cntl_pkt_type_t; 
	
#endif
