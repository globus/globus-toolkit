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

/* File to test gssapi interface, blank functions. */

#include "gssapi.h"

OM_uint32 gss_acquire_cred
(OM_uint32 *               minor_status ,
 const gss_name_t         desired_name ,
 OM_uint32              time_req ,
 const gss_OID_set        desired_mechs ,
 gss_cred_usage_t        cred_usage ,
 gss_cred_id_t *          output_cred_handle ,
 gss_OID_set *           actual_mechs ,
 OM_uint32 *               time_rec 
 ) {}

OM_uint32 gss_release_cred
(OM_uint32 *              minor_status ,
 gss_cred_id_t *           cred_handle 
) {}

OM_uint32 gss_init_sec_context
(OM_uint32 *              minor_status ,
 const gss_cred_id_t     initiator_cred_handle ,
 gss_ctx_id_t *           context_handle ,
 const gss_name_t        target_name ,
 const gss_OID           mech_type ,
 OM_uint32                req_flags ,
 OM_uint32                time_req ,
 const gss_channel_bindings_t  input_chan_bindings ,
 const gss_buffer_t       input_token ,
 gss_OID *                actual_mech_type ,
 gss_buffer_t             output_token ,
 OM_uint32 *              ret_flags ,
 OM_uint32 *               time_rec 
 ) {}

OM_uint32 gss_accept_sec_context
(OM_uint32 *              minor_status ,
 gss_ctx_id_t *           context_handle ,
 const gss_cred_id_t      acceptor_cred_handle ,
 const gss_buffer_t       input_token_buffer ,
 const gss_channel_bindings_t  input_chan_bindings ,
 gss_name_t *             src_name ,
 gss_OID *                mech_type ,
 gss_buffer_t             output_token ,
 OM_uint32 *              ret_flags ,
 OM_uint32 *              time_rec ,
 gss_cred_id_t *           delegated_cred_handle 
   ) {}

OM_uint32 gss_process_context_token
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 const gss_buffer_t        token_buffer 
 ) {}

OM_uint32 gss_delete_sec_context
(OM_uint32 *              minor_status ,
 gss_ctx_id_t *           context_handle ,
 gss_buffer_t              output_token 
 ) {}

OM_uint32 gss_context_time
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 OM_uint32 *               time_rec 
 ) {}

OM_uint32 gss_get_mic
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 gss_qop_t                qop_req ,
 const gss_buffer_t       message_buffer ,
 gss_buffer_t              message_token 
 ) {}

OM_uint32 gss_verify_mic
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 const gss_buffer_t       message_buffer ,
 const gss_buffer_t       token_buffer ,
 gss_qop_t *               qop_state 
 ) {}

OM_uint32 gss_wrap
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 int                      conf_req_flag ,
 gss_qop_t                qop_req ,
 const gss_buffer_t       input_message_buffer ,
 int *                    conf_state ,
 gss_buffer_t              output_message_buffer 
 ) {}

OM_uint32 gss_unwrap
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 const gss_buffer_t       input_message_buffer ,
 gss_buffer_t             output_message_buffer ,
 int *                    conf_state ,
 gss_qop_t *               qop_state 
 ) {}

OM_uint32 gss_display_status
(OM_uint32 *              minor_status ,
 OM_uint32                status_value ,
 int                      status_type ,
 const gss_OID            mech_type ,
 OM_uint32 *              message_context ,
 gss_buffer_t              status_string 
 ) {}

OM_uint32 gss_indicate_mechs
(OM_uint32 *              minor_status ,
 gss_OID_set *             mech_set 
 ) {}

OM_uint32 gss_compare_name
(OM_uint32 *              minor_status ,
 const gss_name_t         name1 ,
 const gss_name_t         name2 ,
 int *                     name_equal 
 ) {}

OM_uint32 gss_display_name
(OM_uint32 *              minor_status ,
 const gss_name_t         input_name ,
 gss_buffer_t             output_name_buffer ,
 gss_OID *                 output_name_type 
 ) {}

OM_uint32 gss_import_name
(OM_uint32 *              minor_status ,
 const gss_buffer_t       input_name_buffer ,
 const gss_OID            input_name_type ,
 gss_name_t *              output_name 
 ) {}

OM_uint32 gss_export_name
(OM_uint32  *             minor_status ,
 const gss_name_t         input_name ,
 gss_buffer_t              exported_name 
 ) {}

OM_uint32 gss_release_name
(OM_uint32 *              minor_status ,
 gss_name_t *              input_name 
 ) {}

OM_uint32 gss_release_buffer
(OM_uint32 *              minor_status ,
 gss_buffer_t              buffer 
 ) {}

OM_uint32 gss_release_oid_set
(OM_uint32 *              minor_status ,
 gss_OID_set *             set 
 ) {}

OM_uint32 gss_inquire_cred
(OM_uint32 *              minor_status ,
 const gss_cred_id_t      cred_handle ,
 gss_name_t *             name ,
 OM_uint32 *              lifetime ,
 gss_cred_usage_t *       cred_usage ,
 gss_OID_set *             mechanisms 
 ) {}

OM_uint32 gss_inquire_context 
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 gss_name_t *             src_name ,
 gss_name_t *             targ_name ,
 OM_uint32 *              lifetime_rec ,
 gss_OID *                mech_type ,
 OM_uint32 *              ctx_flags ,
 int *                    locally_initiated ,
 int *                     open 
 ) {}

OM_uint32 gss_wrap_size_limit 
(OM_uint32 *              minor_status ,
 const gss_ctx_id_t       context_handle ,
 int                      conf_req_flag ,
 gss_qop_t                qop_req ,
 OM_uint32                req_output_size ,
 OM_uint32 *               max_input_size 
 ) {}

OM_uint32 gss_add_cred 
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
 ) {}

OM_uint32 gss_inquire_cred_by_mech 
(OM_uint32 *              minor_status ,
 const gss_cred_id_t      cred_handle ,
 const gss_OID            mech_type ,
 gss_name_t *             name ,
 OM_uint32 *              initiator_lifetime ,
 OM_uint32 *              acceptor_lifetime ,
 gss_cred_usage_t *        cred_usage 
 ) {}

OM_uint32 gss_export_sec_context
(OM_uint32 *              minor_status ,
 gss_ctx_id_t *           context_handle ,
 gss_buffer_t              interprocess_token 
 ) {}

OM_uint32 gss_import_sec_context 
(OM_uint32 *              minor_status ,
 const gss_buffer_t       interprocess_token ,
 gss_ctx_id_t *            context_handle 
 ) {}

OM_uint32 gss_create_empty_oid_set
(OM_uint32 *              minor_status ,
 gss_OID_set *             oid_set 
 ) {}

OM_uint32 gss_add_oid_set_member
(OM_uint32 *              minor_status ,
 const gss_OID            member_oid ,
 gss_OID_set *             oid_set 
 ) {}

OM_uint32 gss_test_oid_set_member
(OM_uint32 *              minor_status ,
 const gss_OID            member ,
 const gss_OID_set        set ,
 int *                     present 
 ) {}

OM_uint32 gss_inquire_names_for_mech
(OM_uint32 *              minor_status ,
 const gss_OID            mechanism ,
 gss_OID_set *             name_types 
 ) {}

OM_uint32 gss_inquire_mechs_for_name
(OM_uint32 *              minor_status ,
 const gss_name_t         input_name ,
 gss_OID_set *             mech_types 
 ) {}

OM_uint32 gss_canonicalize_name
(OM_uint32 *              minor_status ,
 const gss_name_t         input_name ,
 const gss_OID            mech_type ,
 gss_name_t *              output_name 
 ) {}

OM_uint32 gss_duplicate_name
(OM_uint32 *              minor_status ,
 const gss_name_t         src_name ,
 gss_name_t *              dest_name 
 ) {}
