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

#include "globus_gss_ext_compat.h"
#include <stdio.h>

static const gss_OID_desc GSS_DISALLOW_ENCRYPTION_OID =
   {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x03\x01"}; 
const gss_OID_desc * const GSS_DISALLOW_ENCRYPTION =
   &GSS_DISALLOW_ENCRYPTION_OID;

static const gss_OID_desc GSS_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION_OID =
   {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x03\x02"}; 
const gss_OID_desc * const GSS_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION =
   &GSS_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION_OID;

static const gss_OID_desc GSS_APPLICATION_WILL_HANDLE_EXTENSIONS_OID =
   {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x03\x03"}; 
const gss_OID_desc * const GSS_APPLICATION_WILL_HANDLE_EXTENSIONS =
   &GSS_APPLICATION_WILL_HANDLE_EXTENSIONS_OID;

OM_uint32 
GSS_CALLCONV gss_create_empty_buffer_set(
    OM_uint32 *                         minor_status,
    gss_buffer_set_t *                  buffer_set)
{ 
#ifdef DEBUG
    fprintf(stderr,"GSS_COMPATABILITY_EXTENSIONS: create_empty_buffer_set:\n");
#endif /* DEBUG */
    return GSS_S_EXT_COMPAT; 
}

OM_uint32
GSS_CALLCONV gss_add_buffer_set_member(
    OM_uint32 *                         minor_status,
    const gss_buffer_t                  member_buffer,
    gss_buffer_set_t *                  buffer_set)
{
#ifdef DEBUG
    fprintf(stderr,"GSS_COMPATABILITY_EXTENSIONS: add_buffer_set_member:\n");
#endif /* DEBUG */
    return GSS_S_EXT_COMPAT; 
}


OM_uint32
GSS_CALLCONV gss_release_buffer_set(
    OM_uint32 *                         minor_status,
    gss_buffer_set_t *                  buffer_set)
{ 
#ifdef DEBUG
    fprintf(stderr, "GSS_COMPATABILITY_EXTENSIONS: release_buffer_set:\n") ;
#endif /* DEBUG */
    return GSS_S_EXT_COMPAT; 
}


OM_uint32
GSS_CALLCONV gss_import_cred(
    OM_uint32 *                         minor_status,
    gss_cred_id_t *                     cred_handle,
    const gss_OID                       desired_mech,
    OM_uint32                           option_req,
    gss_buffer_t                        output_token,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec)
{ 
#ifdef DEBUG
    fprintf(stderr, "GSS_COMPATABILITY_EXTENSIONS: import_cred:\n") ;
#endif /* DEBUG */

    return GSS_S_EXT_COMPAT; 
}


OM_uint32
GSS_CALLCONV gss_export_cred(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    OM_uint32                           option_req,
    gss_buffer_t                        output_token)
{ 

#ifdef DEBUG
    fprintf(stderr, "GSS_COMPATABILITY_EXTENSIONS: export_cred:\n") ;
#endif /* DEBUG */
    return GSS_S_EXT_COMPAT; 
}

OM_uint32
GSS_CALLCONV gss_init_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    const gss_OID_set                   extension_oids,
    const gss_buffer_set_t              extension_buffers,
    const gss_buffer_t                  input_token,
    OM_uint32                           req_flags,
    OM_uint32                           time_req,
    gss_buffer_t                        output_token)
{ 
#ifdef DEBUG
    fprintf(stderr, "GSS_COMPATABILITY_EXTENSIONS: init_delegation:\n") ;
#endif /* DEBUG */

    return GSS_S_EXT_COMPAT; 
}

OM_uint32
GSS_CALLCONV gss_accept_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_OID_set                   extension_oids,
    const gss_buffer_set_t              extension_buffers,
    const gss_buffer_t                  input_token,
    OM_uint32                           req_flags,    
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec,
    gss_cred_id_t *                     cred_handle,
    gss_OID *                           desired_mech,
    gss_buffer_t                        output_token)
{ 

#ifdef DEBUG
    fprintf(stderr, "GSS_COMPATABILITY_EXTENSIONS: accept_delegation:\n") ;
#endif /* DEBUG */
    return GSS_S_EXT_COMPAT; 
}


OM_uint32
GSS_CALLCONV gss_inquire_sec_context_by_oid(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_OID                       oid,
    gss_buffer_set_t *                  buf_set)
{ 
#ifdef DEBUG
    fprintf(stderr, "GSS_COMPATABILITY_EXTENSIONS: inquire_sec_context_by_oid:\n") ;
#endif /* DEBUG */

    return GSS_S_EXT_COMPAT; 
}


OM_uint32
GSS_CALLCONV gss_inquire_cred_by_oid(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       oid,
    gss_buffer_set_t *                  buf_set)
{ 
#ifdef DEBUG
    fprintf(stderr, "GSS_COMPATABILITY_EXTENSIONS: inquire_cred_by_oid:\n") ;
#endif /* DEBUG */

    return GSS_S_EXT_COMPAT; 
}


OM_uint32
GSS_CALLCONV gss_set_sec_context_option(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t *                      context_handle,
    const gss_OID                       option,
    const gss_buffer_t                  value)
{ 
#ifdef DEBUG
    fprintf(stderr, "GSS_COMPATABILITY_EXTENSIONS: set_sec_context_option:\n") ;
#endif /* DEBUG */

    return GSS_S_EXT_COMPAT; 
}

OM_uint32 
GSS_CALLCONV gss_set_group(
    OM_uint32 *                         minor_status,
    gss_name_t                          name,
    const gss_buffer_set_t              group,
    const gss_OID_set                   group_types)
{
#ifdef DEBUG
    fprintf(stderr,"GSS_COMPATABILITY_EXTENSIONS: set_group:\n");
#endif /* DEBUG */

    return GSS_S_EXT_COMPAT; 
}

OM_uint32 
GSS_CALLCONV gss_get_group(
    OM_uint32 *                         minor_status,
    const gss_name_t                    name,
    gss_buffer_set_t *                  group,
    gss_OID_set *                       group_types)
{
#ifdef DEBUG
    fprintf(stderr,"GSS_COMPATABILITY_EXTENSIONS: get_group:\n");
#endif /* DEBUG */

    return GSS_S_EXT_COMPAT; 
}
