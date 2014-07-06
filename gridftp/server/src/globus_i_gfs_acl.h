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

#ifndef GLOBUS_I_GFS_ACL_H
#define GLOBUS_I_GFS_ACL_H

struct globus_i_gfs_acl_handle_s;

typedef enum globus_l_gfs_acl_type_e
{
    GLOBUS_L_GFS_ACL_TYPE_INIT,
    GLOBUS_L_GFS_ACL_TYPE_AUTHORIZE
} globus_i_gfs_acl_type_t;

typedef void
(*globus_gfs_acl_cb_t)(
    globus_gfs_acl_object_desc_t *      object,
    globus_gfs_acl_action_t             action,
    void *                              user_arg,
    globus_result_t                     result);

void
globus_gfs_acl_add_module(
    globus_gfs_acl_module_t *           module);
    
int
globus_gfs_acl_authorize(
    struct globus_i_gfs_acl_handle_s *  acl_handle,
    globus_gfs_acl_action_t             action,
    globus_gfs_acl_object_desc_t *      object,
    globus_result_t *                   out_res,
    globus_gfs_acl_cb_t                 cb,
    void *                              user_arg);

int
globus_i_gfs_acl_init(
    struct globus_i_gfs_acl_handle_s *  acl_handle,
    const gss_ctx_id_t                  context,
    const char *                        subject,
    const char *                        username,
    const char *                        password,
    const char *                        ipaddr,
    globus_result_t *                   out_res,
    globus_gfs_acl_cb_t                 cb,
    void *                              user_arg);

void
globus_i_gfs_acl_destroy(
    struct globus_i_gfs_acl_handle_s *  acl_handle);

void
globus_gfs_acl_audit(
    struct globus_i_gfs_acl_handle_s *  acl_handle,
    globus_gfs_acl_action_t             action,
    globus_gfs_acl_object_desc_t *      object,
    const char *                        msg);

typedef struct globus_i_gfs_acl_handle_s
{
    char *                              password;
    char *                              ipaddr;
    globus_i_gfs_acl_type_t             type;
    char *                              subject;
    char *                              username;
    char *                              hostname;
    globus_gfs_acl_cb_t                 cb;
    void *                              user_arg;
    globus_list_t *                     module_list;
    globus_list_t *                     current_list;
    globus_result_t                     cached_res;
    gss_ctx_id_t                        context;
    globus_gfs_acl_action_t             auth_action;
    globus_gfs_acl_object_desc_t        auth_object;
    globus_gfs_acl_info_t               acl_info;
} globus_i_gfs_acl_handle_t;



#endif
