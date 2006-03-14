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

