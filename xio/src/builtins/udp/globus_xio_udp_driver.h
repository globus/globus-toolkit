#ifndef GLOBUS_XIO_UDP_DRIVER_INCLUDE
#define GLOBUS_XIO_UDP_DRIVER_INCLUDE

#include "globus_xio_system.h"

/**
 *  possible commands for attr cntl
 */

#define GLOBUS_XIO_UDP_INVALID_HANDLE GLOBUS_XIO_SYSTEM_INVALID_HANDLE

typedef enum
{
    GLOBUS_XIO_UDP_ERROR_NO_ADDRS
} globus_xio_udp_error_type_t;

typedef enum
{
    /**
     *  target attrs
     */
    /* globus_xio_system_handle_t       handle */
    GLOBUS_XIO_UDP_SET_HANDLE,
    /* globus_xio_system_handle_t *     handle_out */
    GLOBUS_XIO_UDP_GET_HANDLE,
    
    /**
     *  handle attrs
     */
    /* const char *                     service_name */
    GLOBUS_XIO_UDP_SET_SERVICE,
    /* char **                          service_name_out */
    GLOBUS_XIO_UDP_GET_SERVICE,
    /* int                              listener_port */
    GLOBUS_XIO_UDP_SET_PORT,
    /* int *                            listener_port_out */
    GLOBUS_XIO_UDP_GET_PORT,
    /* int                              listener_min_port */
    /* int                              listener_max_port */
    GLOBUS_XIO_UDP_SET_LISTEN_RANGE,
    /* int *                            listener_min_port_out */
    /* int *                            listener_max_port_out */
    GLOBUS_XIO_UDP_GET_LISTEN_RANGE,
    /* const char *                     interface */
    GLOBUS_XIO_UDP_SET_INTERFACE,
    /* char **                          interface_out */
    GLOBUS_XIO_UDP_GET_INTERFACE,
    /* globus_bool_t                    restrict_port */
    GLOBUS_XIO_UDP_SET_RESTRICT_PORT,
    /* globus_bool_t *                  restrict_port_out */
    GLOBUS_XIO_UDP_GET_RESTRICT_PORT,
    /* globus_bool_t                    resuseaddr */
    GLOBUS_XIO_UDP_SET_REUSEADDR,
    /* globus_bool_t *                  resuseaddr_out */
    GLOBUS_XIO_UDP_GET_REUSEADDR,
    
    /**
     *  handle attrs/cntls
     */
    /* int                              sndbuf */
    GLOBUS_XIO_UDP_SET_SNDBUF,
    /* int *                            sndbuf_out */
    GLOBUS_XIO_UDP_GET_SNDBUF,
    /* int                              rcvbuf */
    GLOBUS_XIO_UDP_SET_RCVBUF,
    /* int *                            rcvbuf_out */
    GLOBUS_XIO_UDP_GET_RCVBUF,
    
    /**
     * handle cntls
     */
    /* char **                          contact_string_out */
    GLOBUS_XIO_UDP_GET_CONTACT,
    /* char **                          contact_string_out */
    GLOBUS_XIO_UDP_GET_NUMERIC_CONTACT,

    /* globus_sockaddr_t *              sock_name_out */
    GLOBUS_XIO_UDP_GET_LOCAL_ADDRESS
    
} globus_xio_udp_cmd_t;

#endif
