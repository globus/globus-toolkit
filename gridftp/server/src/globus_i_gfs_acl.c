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

#include "globus_i_gridftp_server.h"
#include "globus_i_gfs_acl.h"

static globus_list_t *                  globus_l_acl_module_list;

typedef struct globus_l_gfs_acl_request_s
{
    void *                              user_handle;
    globus_gfs_acl_module_t *           module;
} globus_l_gfs_acl_request_t;


static int
globus_l_gfs_acl_next(
    globus_i_gfs_acl_handle_t *         acl_handle,
    globus_result_t *                   out_res)
{
    int                                 rc = GLOBUS_GFS_ACL_COMPLETE;
    globus_l_gfs_acl_request_t *        acl_request;
    GlobusGFSName(globus_l_gfs_acl_next);
    GlobusGFSDebugEnter();

    *out_res = GLOBUS_SUCCESS;

    while(rc == GLOBUS_GFS_ACL_COMPLETE &&
        *out_res == GLOBUS_SUCCESS &&
        !globus_list_empty(acl_handle->current_list))
    {
        acl_request = (globus_l_gfs_acl_request_t *) globus_list_remove(
            &acl_handle->current_list, acl_handle->current_list);
        globus_assert(acl_request->module != NULL);

        switch(acl_handle->type)
        {
            case GLOBUS_L_GFS_ACL_TYPE_INIT:
                rc = acl_request->module->init_func(
                    &acl_request->user_handle,
                    (const struct passwd *) &acl_handle->pwent,
                    (const char *)acl_handle->given_pw,
                    (const char *)acl_handle->auth_action,
                    acl_handle,
                    out_res);
                break;

            case GLOBUS_L_GFS_ACL_TYPE_AUTHORIZE:
                rc = acl_request->module->authorize_func(
                    acl_request->user_handle,
                    acl_handle->auth_action, 
                    acl_handle->auth_object,
                    acl_handle, 
                    out_res);
                break;

            default:
                globus_assert(0 && "possible memory corruption");
                break;
        }
    } 

    GlobusGFSDebugExit();
    return rc;
}

static void
globus_l_gfs_acl_kickout(
    void *                              user_arg)
{
    int                                 rc;
    globus_i_gfs_acl_handle_t *         acl_handle;
    GlobusGFSName(globus_l_gfs_acl_kickout);
    GlobusGFSDebugEnter();

    acl_handle = (globus_i_gfs_acl_handle_t *) user_arg;

    /* if done call the user callback */
    if(globus_list_empty(acl_handle->current_list))
    {
        acl_handle->cb(
            acl_handle->auth_action,
            acl_handle->user_arg,
            acl_handle->cached_res);
    }
    else
    {
        rc = globus_l_gfs_acl_next(acl_handle, &acl_handle->cached_res);
        if(rc == GLOBUS_GFS_ACL_COMPLETE)
        {
            acl_handle->cb(
                acl_handle->auth_action,
                acl_handle->user_arg,
                acl_handle->cached_res);
        }
    }
    
    GlobusGFSDebugExit();
}

int
globus_i_gfs_acl_init(
    struct globus_i_gfs_acl_handle_s *  acl_handle,
    const gss_ctx_id_t                  context,
    const struct passwd *               pwent,
    const struct group *                grpent,
    const char *                        given_pw,
    const char *                        ipaddr,
    const char *                        resource_id,
    globus_result_t *                   out_res,
    globus_gfs_acl_cb_t                 cb,
    void *                              user_arg)
{
    globus_l_gfs_acl_request_t *        acl_request;
    globus_list_t *                     list;
    int                                 rc;
    int                                 ctr;
    GlobusGFSName(globus_i_gfs_acl_init);
    GlobusGFSDebugEnter();

    memset(acl_handle, '\0', sizeof(struct globus_i_gfs_acl_handle_s));
    acl_handle->type = GLOBUS_L_GFS_ACL_TYPE_INIT;
    acl_handle->cb = cb;
    acl_handle->user_arg = user_arg;
    acl_handle->context = context;
    acl_handle->hostname = globus_i_gfs_config_string("fqdn");

    acl_handle->auth_action = strdup(resource_id);
    if(acl_handle->auth_action == NULL)
    {
        goto err;
    }
    memset(&acl_handle->pwent, '\0', sizeof(struct passwd));
    memset(&acl_handle->grpent, '\0', sizeof(struct group));

    /* copy the pwent info */
    if(pwent->pw_name)
    {
        acl_handle->pwent.pw_name = strdup(pwent->pw_name);
        if(acl_handle->pwent.pw_name == NULL)
        {
            goto alloc_error;
        }
    }
    if(pwent->pw_passwd)
    {
        acl_handle->pwent.pw_passwd = strdup(pwent->pw_passwd);
        if(acl_handle->pwent.pw_passwd == NULL)
        {
            goto alloc_error;
        }
    }
    if(pwent->pw_dir)
    {
        acl_handle->pwent.pw_dir = strdup(pwent->pw_dir);
        if(acl_handle->pwent.pw_dir == NULL)
        {
            goto alloc_error;
        }
    }
    if(pwent->pw_shell)
    {
        acl_handle->pwent.pw_shell = strdup(pwent->pw_shell);
        if(acl_handle->pwent.pw_shell == NULL)
        {
            goto alloc_error;
        }
    }
    acl_handle->pwent.pw_uid = pwent->pw_uid;
    acl_handle->pwent.pw_gid = pwent->pw_gid;

    /* copy the group info */
    if(grpent->gr_name)
    {
        acl_handle->grpent.gr_name = strdup(grpent->gr_name);
        if(acl_handle->grpent.gr_name == NULL)
        {
            goto alloc_error;
        }
    }
    if(grpent->gr_passwd)
    {
        acl_handle->grpent.gr_passwd = strdup(grpent->gr_passwd);
        if(acl_handle->grpent.gr_passwd == NULL)
        {
            goto alloc_error;
        }
    }
    acl_handle->grpent.gr_gid = grpent->gr_gid;
    for(ctr = 0; grpent->gr_mem[ctr] != NULL; ctr++)
    {
    }
    acl_handle->grpent.gr_mem = globus_calloc(1, sizeof(char *) * (ctr+1));
    if(acl_handle->grpent.gr_mem == NULL)
    {
            goto alloc_error;
    }
    for(ctr = 0; grpent->gr_mem[ctr] != NULL; ctr++)
    {
        acl_handle->grpent.gr_mem[ctr] = strdup(grpent->gr_mem[ctr]);
        if(acl_handle->grpent.gr_mem[ctr] == NULL)
        {
            goto alloc_error;
        }
    }
    if(ipaddr != NULL)
    {
        acl_handle->ipaddr = strdup(ipaddr);
        if(acl_handle->ipaddr == NULL)
        {
            goto alloc_error;
        }
    }
    if(given_pw != NULL)
    {
        acl_handle->given_pw = strdup(given_pw);
        if(acl_handle->given_pw == NULL)
        {
            goto alloc_error;
        }
    }

    /* needed memory for each module 'cause of handle back, only on init */
    for(list = globus_l_acl_module_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        acl_request = (globus_l_gfs_acl_request_t *)
            globus_calloc(sizeof(globus_l_gfs_acl_request_t), 1);
        if(acl_request == NULL)
        {
            goto err;
        }
        acl_request->module = globus_list_first(list);
        globus_list_insert(&acl_handle->module_list, acl_request);
    }
    acl_handle->current_list = globus_list_copy(acl_handle->module_list);

    rc = globus_l_gfs_acl_next(acl_handle, out_res);

    GlobusGFSDebugExit();
    return rc;

alloc_error:
err:
    globus_i_gfs_acl_destroy(acl_handle);

    GlobusGFSDebugExitWithError();
    return -1;
}

void
globus_i_gfs_acl_destroy(
    struct globus_i_gfs_acl_handle_s *  acl_handle)
{
    int                                 ctr;
    globus_l_gfs_acl_request_t *        acl_request;
    GlobusGFSName(globus_i_gfs_acl_destroy);
    GlobusGFSDebugEnter();

    while(!globus_list_empty(acl_handle->module_list))
    {
        acl_request = (globus_l_gfs_acl_request_t *) globus_list_remove(
            &acl_handle->module_list, acl_handle->module_list);
        acl_request->module->destroy_func(acl_request->user_handle);
        globus_free(acl_request);
    }
    if(acl_handle->auth_action != NULL)
    {
        globus_free(acl_handle->auth_action);
    }
    /* copy the pwent info */
    if(acl_handle->pwent.pw_name)
    {
        globus_free(acl_handle->pwent.pw_name);
    }
    if(acl_handle->pwent.pw_passwd)
    {
        globus_free(acl_handle->pwent.pw_passwd);
    }
    if(acl_handle->pwent.pw_dir)
    {
        globus_free(acl_handle->pwent.pw_dir);
    }
    if(acl_handle->pwent.pw_shell)
    {
        globus_free(acl_handle->pwent.pw_shell);
    }
    if(acl_handle->grpent.gr_name)
    {
        globus_free(acl_handle->grpent.gr_name);
    }
    if(acl_handle->grpent.gr_passwd)
    {
        globus_free(acl_handle->grpent.gr_passwd);
    }
    if(acl_handle->ipaddr)
    {
        globus_free(acl_handle->ipaddr);
    }
    if(acl_handle->given_pw)
    {
        globus_free(acl_handle->given_pw);
    }
    if(acl_handle->grpent.gr_mem)
    {
        for(ctr = 0; acl_handle->grpent.gr_mem[ctr] != NULL; ctr++)
        {
            globus_free(acl_handle->grpent.gr_mem[ctr]);
        }
        globus_free(acl_handle->grpent.gr_mem);
    }
    if(acl_handle->auth_object)
    {
        globus_free(acl_handle->auth_object);
    }

    GlobusGFSDebugExit();
}

int
globus_gfs_acl_authorize(
    struct globus_i_gfs_acl_handle_s *  acl_handle,
    const char *                        action,
    const char *                        object,
    globus_result_t *                   out_res,
    globus_gfs_acl_cb_t                 cb,
    void *                              user_arg)
{
    int                                 rc;
    GlobusGFSName(globus_gfs_acl_authorize);
    GlobusGFSDebugEnter();

    acl_handle->type = GLOBUS_L_GFS_ACL_TYPE_AUTHORIZE;
    acl_handle->cb = cb;
    acl_handle->user_arg = user_arg;

    if(acl_handle->auth_action)
    {
        globus_free(acl_handle->auth_action);
    }
    acl_handle->auth_action = strdup(action);
    if(acl_handle->auth_action == NULL)
    {
        goto err;
    }
    if(acl_handle->auth_object)
    {
        globus_free(acl_handle->auth_object);
    }
    acl_handle->auth_object = strdup(object);
    if(acl_handle->auth_object == NULL)
    {
        goto err;
    }
    acl_handle->current_list = globus_list_copy(acl_handle->module_list);
    rc = globus_l_gfs_acl_next(acl_handle, out_res);

    GlobusGFSDebugExit();
    return rc;

  err:
    GlobusGFSDebugExitWithError();
    return -1;
}

void
globus_gfs_acl_authorized_finished(
    globus_i_gfs_acl_handle_t *         acl_handle,
    globus_result_t                     result)
{
    GlobusGFSName(globus_gfs_acl_authorized_finished);
    GlobusGFSDebugEnter();

    acl_handle->cached_res = result;

    globus_callback_register_oneshot(
        NULL,
        NULL,
        globus_l_gfs_acl_kickout,
        acl_handle);

    GlobusGFSDebugExit();
}

void
globus_gfs_acl_add_module(
    globus_gfs_acl_module_t *           module)
{
    GlobusGFSName(globus_gfs_acl_add_module);
    GlobusGFSDebugEnter();

    globus_list_insert(&globus_l_acl_module_list, module);

    GlobusGFSDebugExit();
}
