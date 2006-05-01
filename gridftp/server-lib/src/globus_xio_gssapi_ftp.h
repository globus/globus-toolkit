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

#if !defined GLOBUS_XIO_DRIVER_GSSAPI_FTP_H
#define GLOBUS_XIO_DRIVER_GSSAPI_FTP_H 1

#include "globus_common.h"
#include "globus_error_gssapi.h"

typedef enum
{
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUBJECT,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_START_STATE,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_ENCRYPT,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_ALLOW_CLEAR,
    GLOBUS_XIO_GSSAPI_ATTR_TYPE_FORCE_SERVER
} globus_xio_gssapi_attr_type_t;

typedef enum globus_xio_gssapi_handle_cntl_type_e
{
    GLOBUS_XIO_DRIVER_GSSAPI_FTP_GET_AUTH
} globus_xio_gssapi_handle_cntl_type_t;

enum
{
    GLOBUS_XIO_GSSAPI_FTP_BAD_PARAMETER,
    GLOBUS_XIO_GSSAPI_FTP_OUTSTANDING_OP,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ENCODING,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_ALLOC,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_AUTH,
    GLOBUS_XIO_GSSAPI_FTP_ERROR_QUIT
};

enum
{
    GLOBUS_XIO_GSSAPI_FTP_SECURE,
    GLOBUS_XIO_GSSAPI_FTP_CLEAR,
    GLOBUS_XIO_GSSAPI_FTP_NONE
};

#endif
