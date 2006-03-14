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

/*
 *  user functions.  used by control.c or DSI implementation if it choses.
 */
#include "globus_i_gridftp_server.h"

#define FTP_SERVICE_NAME "file"

static void
globus_gfs_acl_cas_cb(
    void *                              callback_arg,
    globus_gsi_authz_handle_t           handle,
    globus_result_t                     result)
{
    globus_i_gfs_acl_handle_t *         acl_handle;
    GlobusGFSName(globus_gfs_acl_cas_cb);
    GlobusGFSDebugEnter();

    acl_handle = (globus_i_gfs_acl_handle_t *) callback_arg;
    globus_gfs_acl_authorized_finished(acl_handle, result);

    GlobusGFSDebugExit();
}

static
int
globus_gfs_acl_cas_init(
    void **                             out_handle,
    globus_gfs_acl_info_t *             acl_info,
    globus_gfs_acl_handle_t             acl_handle,
    globus_result_t *                   out_res)
{
    globus_gsi_authz_handle_t           cas_handle;
    GlobusGFSName(globus_gfs_acl_cas_init);
    GlobusGFSDebugEnter();

    if(acl_info->context == NULL)
    {
        goto err;
    }
    *out_res = globus_gsi_authz_handle_init(
        &cas_handle,
        FTP_SERVICE_NAME,
        acl_info->context,
        globus_gfs_acl_cas_cb,
        acl_handle);
    if(*out_res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    *out_handle = cas_handle;
    GlobusGFSDebugExit();
    return GLOBUS_GFS_ACL_WOULD_BLOCK;

  err:
    GlobusGFSDebugExitWithError();
    return GLOBUS_GFS_ACL_COMPLETE;
}

static
int
globus_gfs_acl_cas_authorize(
    void *                              out_handle,
    const char *                        action,
    const char *                        object,
    globus_gfs_acl_info_t *             acl_info,
    globus_gfs_acl_handle_t             acl_handle,
    globus_result_t *                   out_res)
{
    globus_gsi_authz_handle_t           cas_handle;
    char *                              full_object;
    GlobusGFSName(globus_gfs_acl_cas_authorize);
    GlobusGFSDebugEnter();

    cas_handle = (globus_gsi_authz_handle_t) out_handle;
    if(acl_info->context == NULL)
    {
        goto err;
    }
    /*
     * If the action is "authz_assert" then the object contains the assertions
     * received over the gridftp control channel - just pass it unmodified to
     * the authz callout
     */
    if (strcmp(action, "authz_assert"))
    {
        full_object = globus_common_create_string(
            "ftp://%s%s", acl_info->hostname, object);
    }
    else
    {
        full_object = globus_libc_strdup(object);
    }    
    *out_res = globus_gsi_authorize(
        cas_handle,
        action,
        full_object,
        globus_gfs_acl_cas_cb,
        acl_handle);
    globus_free(full_object);
    if(*out_res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusGFSDebugExit();
    return GLOBUS_GFS_ACL_WOULD_BLOCK;

  err:
    GlobusGFSDebugExitWithError();
    return GLOBUS_GFS_ACL_COMPLETE;
}

static void
globus_gfs_acl_cas_destroy_cb(
    void *                              callback_arg,
    globus_gsi_authz_handle_t           handle,
    globus_result_t                     result)
{
    GlobusGFSName(globus_gfs_acl_cas_cb);
    GlobusGFSDebugEnter();


    GlobusGFSDebugExit();
}

static void
globus_gfs_acl_cas_destroy(
    void *                              out_handle)
{
    globus_gsi_authz_handle_t           cas_handle;
    GlobusGFSName(globus_gfs_acl_cas_destroy);
    GlobusGFSDebugEnter();

    cas_handle = (globus_gsi_authz_handle_t) out_handle;
    globus_gsi_authz_handle_destroy(
        cas_handle, globus_gfs_acl_cas_destroy_cb, NULL);

    GlobusGFSDebugExit();
}

globus_gfs_acl_module_t                 globus_gfs_acl_cas_module = 
{
    globus_gfs_acl_cas_init,
    globus_gfs_acl_cas_authorize,
    globus_gfs_acl_cas_destroy
};

