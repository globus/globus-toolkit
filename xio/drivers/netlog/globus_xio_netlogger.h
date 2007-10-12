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

#ifndef GLOBUS_XIO_NETLOGGER_H
#define GLOBUS_XIO_NETLOGGER_H 1

typedef enum globus_xio_netlogger_log_event_e
{
    GLOBUS_XIO_NETLOGGER_LOG_OPEN = 0x1,
    GLOBUS_XIO_NETLOGGER_LOG_CLOSE = 0x2,
    GLOBUS_XIO_NETLOGGER_LOG_READ = 0x4,
    GLOBUS_XIO_NETLOGGER_LOG_WRITE = 0x8,
    GLOBUS_XIO_NETLOGGER_LOG_ACCEPT = 0x10
} globus_xio_netlogger_log_event_t;

typedef enum globus_xio_netlogger_log_cntl_e
{
    GLOBUS_XIO_NETLOGGER_CNTL_EVENT_ON = 1,
    GLOBUS_XIO_NETLOGGER_CNTL_EVENT_OFF,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_FD,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_TRANSFER_ID,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_ID,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_FILENAME,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_MASK,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_TYPE,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_SUM_TYPES,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_STRING_SUM_TYPES,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_HANDLE,
    GLOBUS_XIO_NETLOGGER_CNTL_SET_SUMM,
    GLOBUS_XIO_NETLOGGER_CNTL_STRING_IN_OUT = 1024
} globus_xio_netlogger_log_cntl_t;


#endif
