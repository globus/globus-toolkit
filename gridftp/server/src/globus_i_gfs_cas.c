/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

/*
 *  user functions.  used by control.c or DSI implementation if it choses.
 */
#include "globus_i_gridftp_server.h"

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
    const struct passwd *               passwd,
    const char *                        given_pw,
    const char *                        resource_id,
    globus_i_gfs_acl_handle_t *         acl_handle,
    globus_result_t *                   out_res)
{
    globus_gsi_authz_handle_t           cas_handle;
    GlobusGFSName(globus_gfs_acl_cas_init);
    GlobusGFSDebugEnter();

    if(acl_handle->context == NULL)
    {
        goto err;
    }
    *out_res = globus_gsi_authz_handle_init(
        &cas_handle,
        resource_id,
        acl_handle->context,
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
    globus_i_gfs_acl_handle_t *         acl_handle,
    globus_result_t *                   out_res)
{
    globus_gsi_authz_handle_t           cas_handle;
    char *                              full_object;
    GlobusGFSName(globus_gfs_acl_cas_authorize);
    GlobusGFSDebugEnter();

    cas_handle = (globus_gsi_authz_handle_t) out_handle;
    if(acl_handle->context == NULL)
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
            "ftp://%s%s", acl_handle->hostname, object);
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

