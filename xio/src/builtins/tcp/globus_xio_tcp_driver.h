#ifndef GLOBUS_XIO_TCP_DRIVER_INCLUDE
#define GLOBUS_XIO_TCP_DRIVER_INCLUDE

#include "globus_xio_system.h"

/**
 *  possible commands for attr cntl
 */

#define GLOBUS_XIO_TCP_INVALID_HANDLE GLOBUS_XIO_SYSTEM_INVALID_HANDLE

typedef enum
{
    /* handle attrs */
    
    /* handle/server attrs */
    GLOBUS_XIO_TCP_SET_INTERFACE,
    GLOBUS_XIO_TCP_SET_INTERFACE,
    GLOBUS_XIO_TCP_SET_RESTRICT_PORT,
    GLOBUS_XIO_TCP_GET_RESTRICT_PORT,
    GLOBUS_XIO_TCP_SET_RESTRICT_RANGE,
    GLOBUS_XIO_TCP_SET_RESTRICT_RANGE,
    
    /* server attrs */
    GLOBUS_XIO_TCP_SET_SERVICE,
    GLOBUS_XIO_TCP_GET_SERVICE,
    GLOBUS_XIO_TCP_SET_PORT,
    GLOBUS_XIO_TCP_GET_PORT,
    GLOBUS_XIO_TCP_SET_BACKLOG,
    GLOBUS_XIO_TCP_GET_BACKLOG,
    
    /* target/server attrs */
    GLOBUS_XIO_TCP_SET_HANDLE,
    GLOBUS_XIO_TCP_GET_HANDLE
} globus_xio_tcp_attr_cmd_t;

#endif
