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

/******************************************************************************
globus_gass_server_ez.h
 
Description:
    Simple wrappers around globus_gass_server API for server functionality.
    Implements the following:
        Write access to local files, with optional line buffering
	Write access to stdout and stderr
	Shutdown callback, so client can stop the server
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_SIMPLE_SERVER_H_
#define _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_SIMPLE_SERVER_H_

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_gass_transfer.h"

EXTERN_C_BEGIN

#define GLOBUS_GASS_SERVER_EZ_LINE_BUFFER              1UL 
#define GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND             2UL
#define GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND        4UL
#define GLOBUS_GASS_SERVER_EZ_READ_ENABLE              8UL
#define GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE             16UL
#define GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE            32UL
#define GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE            64UL
#define GLOBUS_GASS_SERVER_EZ_CLIENT_SHUTDOWN_ENABLE   128UL

#if (GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND != GLOBUS_TILDE_EXPAND)
#error "Inconsistant definition of GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND and GLOBUS_TILDE_EXPAND"
#endif
#if (GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND != GLOBUS_TILDE_USER_EXPAND)
#error "Inconsistant definition of GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND and GLOBUS_TILDE_USER_EXPAND"
#endif

typedef void (*globus_gass_server_ez_client_shutdown_t) (void);
/*
typedef globus_object_t globus_gass_transfer_listener_t;
typedef globus_object_t globus_gass_transfer_listenerattr_t;
typedef globus_object_t globus_gass_transfer_requestattr_t;
*/


int
globus_gass_server_ez_init(globus_gass_transfer_listener_t * listener,
                           globus_gass_transfer_listenerattr_t * attr,
                           char * scheme,
                           globus_gass_transfer_requestattr_t * reqattr,
                           unsigned long options,
                           globus_gass_server_ez_client_shutdown_t callback);

int
globus_gass_server_ez_shutdown(globus_gass_transfer_listener_t listener);

#define globus_gass_server_ez_poll() globus_poll()
/******************************************************************************
 *                    Module Definition
 *****************************************************************************/

extern globus_module_descriptor_t globus_i_gass_server_ez_module;

#define GLOBUS_GASS_SERVER_EZ_MODULE (&globus_i_gass_server_ez_module)

EXTERN_C_END

#endif
