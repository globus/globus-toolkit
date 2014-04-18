/*
 * Copyright 1999-2014 University of Chicago
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
    GLOBUS_XIO_NETLOGGER_CNTL_INTERVAL,
    GLOBUS_XIO_NETLOGGER_CNTL_LEVEL,
    GLOBUS_XIO_NETLOGGER_CNTL_STRING_IN_OUT = 1024
} globus_xio_netlogger_log_cntl_t;


#endif
