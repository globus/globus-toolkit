/*
 * Copyright 1999-2015 University of Chicago
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
 * @file gssapi_working.c
 * @details
 * All the unimplemented GSSAPI functions. These return failure
 * As these are needed by Globus, they will be implemented
 * @see http://www.rfc-editor.org/rfc/rfc2744.txt
 */

#include "gssapi.h"

OM_uint32 GSS_CALLCONV gss_process_context_token
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 const gss_buffer_t        token_buffer 
 ) { return GSS_S_FAILURE ; }

#if WIN32 || !LINK_WITH_INTERNAL_OPENSSL_API
OM_uint32 
GSS_CALLCONV gss_import_sec_context(
    OM_uint32 *                         minor_status ,
    const gss_buffer_t                  interprocess_token,
    gss_ctx_id_t *                      context_handle_P)
{
    *minor_status = GLOBUS_FAILURE;
    
    return GSS_S_UNAVAILABLE;
}

OM_uint32 
GSS_CALLCONV gss_export_sec_context(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t *                      context_handle_P,
    gss_buffer_t                        interprocess_token) 
{
    *minor_status = GLOBUS_FAILURE;

    return GSS_S_UNAVAILABLE;
}
#endif

OM_uint32 GSS_CALLCONV gss_add_cred 
(OM_uint32 *              minor_status ,
 const gss_cred_id_t      input_cred_handle ,
 const gss_name_t         desired_name ,
 const gss_OID            desired_mech ,
 gss_cred_usage_t         cred_usage ,
 OM_uint32                initiator_time_req ,
 OM_uint32                acceptor_time_req ,
 gss_cred_id_t *          output_cred_handle ,
 gss_OID_set *            actual_mechs ,
 OM_uint32 *              initiator_time_rec ,
 OM_uint32 *               acceptor_time_rec 
 ) { return GSS_S_FAILURE ; }

OM_uint32 GSS_CALLCONV gss_inquire_cred_by_mech 
(OM_uint32 *              minor_status ,
 const gss_cred_id_t      cred_handle ,
 const gss_OID            mech_type ,
 gss_name_t *             name ,
 OM_uint32 *              initiator_lifetime ,
 OM_uint32 *              acceptor_lifetime ,
 gss_cred_usage_t *        cred_usage 
 ) { return GSS_S_FAILURE ; }

OM_uint32 GSS_CALLCONV gss_inquire_mechs_for_name
(OM_uint32 *              minor_status ,
 const gss_name_t         input_name ,
 gss_OID_set *             mech_types 
 ) { return GSS_S_FAILURE ; }

OM_uint32 GSS_CALLCONV gss_canonicalize_name
(OM_uint32 *              minor_status ,
 const gss_name_t         input_name ,
 const gss_OID            mech_type ,
 gss_name_t *              output_name 
 ) { return GSS_S_FAILURE ; }
