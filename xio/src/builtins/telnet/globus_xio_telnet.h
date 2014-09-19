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

/**
 * @file globus_xio_telnet.h
 * @brief XIO Telnet Driver
 */

#if !defined GLOBUS_XIO_TELNET_H
#define GLOBUS_XIO_TELNET_H 1

#include "globus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum globus_xio_telnet_attr_type_e
{
    GLOBUS_XIO_TELNET_FORCE_SERVER,
    GLOBUS_XIO_TELNET_BUFFER
} globus_xio_telnet_attr_type_t;

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_XIO_TELNET_H */
