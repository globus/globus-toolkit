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
#include "globus_i_gfs_acl.h"

#define GlobusACLTestFailure()                                              \
    globus_error_put(                                                       \
    globus_error_construct_error(                                           \
        GLOBUS_NULL,                                                        \
        GLOBUS_NULL,                                                        \
        GLOBUS_GFS_ERROR_MEMORY,                                            \
        __FILE__,                                                           \
        _gfs_name,                                                          \
        __LINE__,                                                           \
        "acl failed"))


static
int
globus_gfs_acl_test_init(
    void **                             out_handle,
    globus_gfs_acl_info_t *             acl_info,
    globus_gfs_acl_handle_t             acl_handle,
    globus_result_t *                   out_res)
{
    char *                              fail_str;
    GlobusGFSName(globus_gfs_acl_test_init);
    GlobusGFSDebugEnter();

    fail_str = globus_i_gfs_config_string("test_acl");
    if(fail_str != NULL && (strstr(fail_str, "ALL") || 
        strstr(fail_str, "init")))
    {
        *out_res = GlobusACLTestFailure();
    }
    else
    {
        *out_res = GLOBUS_SUCCESS;
    }
    if(strstr(fail_str, "BLOCK"))
    {
        globus_gfs_acl_authorized_finished(acl_handle, *out_res);
        GlobusGFSDebugExit();
        return GLOBUS_GFS_ACL_WOULD_BLOCK;
    }
    else
    {
        GlobusGFSDebugExitWithError();
        return GLOBUS_GFS_ACL_COMPLETE;
    }
}

static
int
globus_gfs_acl_test_authorize(
    void *                              out_handle,
    const char *                        action,
    const char *                        object,
    globus_gfs_acl_info_t *             acl_info,
    globus_gfs_acl_handle_t             acl_handle,
    globus_result_t *                   out_res)
{
    char *                              fail_str;
    GlobusGFSName(globus_gfs_acl_test_authorize);
    GlobusGFSDebugEnter();

    fail_str = globus_i_gfs_config_string("test_acl");
    if(fail_str != NULL && (strstr(fail_str, "ALL") || 
        strstr(fail_str, action)))
    {
        *out_res = GlobusACLTestFailure();
    }
    else
    {
        *out_res = GLOBUS_SUCCESS;
    }

    if(strstr(fail_str, "BLOCK"))
    {
        globus_gfs_acl_authorized_finished(acl_handle, *out_res);
        GlobusGFSDebugExit();
        return GLOBUS_GFS_ACL_WOULD_BLOCK;
    }
    else
    {
        GlobusGFSDebugExitWithError();
        return GLOBUS_GFS_ACL_COMPLETE;
    }
}


static void
globus_gfs_acl_test_destroy(
    void *                              out_handle)
{
    GlobusGFSName(globus_gfs_acl_test_destroy);
    GlobusGFSDebugEnter();

    GlobusGFSDebugExit();
}

globus_gfs_acl_module_t                 globus_gfs_acl_test_module = 
{
    globus_gfs_acl_test_init,
    globus_gfs_acl_test_authorize,
    globus_gfs_acl_test_destroy
};

