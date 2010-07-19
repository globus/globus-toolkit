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

#ifndef GLOBUS_GSI_AUTHZ_H
#define GLOBUS_GSI_AUTHZ_H 1

#include "globus_common.h"
#include "gssapi.h"

EXTERN_C_BEGIN

#define GLOBUS_GSI_AUTHZ_MODULE         (&globus_i_gsi_authz_module)

extern
globus_module_descriptor_t    globus_i_gsi_authz_module;

/** @defgroup globus_gsi_authz GSI Authorization API
 */


typedef struct globus_i_gsi_authz_handle_s *
    globus_gsi_authz_handle_t;

typedef void (* globus_gsi_authz_cb_t)(
    void *                              callback_arg,
    globus_gsi_authz_handle_t           handle,
    globus_result_t                     result); 

globus_result_t
globus_gsi_authz_handle_init(
    globus_gsi_authz_handle_t *         handle,
    const char *                        service_name,
    const gss_ctx_id_t                  context,
    globus_gsi_authz_cb_t               callback,
    void *                              callback_arg);

globus_result_t
globus_gsi_authorize(
    globus_gsi_authz_handle_t           handle,
    const void *                        action,
    const void *                        object,
    globus_gsi_authz_cb_t               callback,
    void *                              callback_arg);

globus_result_t
globus_gsi_cancel_authz(
    globus_gsi_authz_handle_t           handle);

globus_result_t
globus_gsi_authz_handle_destroy(
    globus_gsi_authz_handle_t           handle,
    globus_gsi_authz_cb_t               callback,
    void *                              callback_arg);

EXTERN_C_END

#endif /* GLOBUS_GSI_AUTHZ_H */
