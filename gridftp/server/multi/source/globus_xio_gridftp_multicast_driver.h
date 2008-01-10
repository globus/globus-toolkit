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

#ifndef GLOBUS_XIO_GRIDFTP_MULTICAST_DRIVER_INCLUDE
#define GLOBUS_XIO_GRIDFTP_MULTICAST_DRIVER_INCLUDE

#include "globus_xio_system.h"
#include "globus_common.h"

typedef enum
{
    GLOBUS_XIO_GRIDFTP_MULTICAST_ERROR_NOOP,
    GLOBUS_XIO_GRIDFTP_MULTICAST_ERROR_TRANSFER_FAILURES
} globus_xio_gridftp_multicast_error_type_t;

enum
{
    GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_PARALLEL = 1,
    GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_TCPBS,
    GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_URLS,
    GLOBUS_XIO_GRIDFTP_MULTICAST_ATTR_LOCAL_WRITE
};

#endif
