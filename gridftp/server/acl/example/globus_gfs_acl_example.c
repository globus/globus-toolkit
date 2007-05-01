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
#include "globus_gridftp_server.h"
#include "globus_common.h"
#include "version.h"

#define GlobusACLExampleFailure(_msg)                                       \
    globus_error_put(                                                       \
    globus_error_construct_error(                                           \
        GLOBUS_NULL,                                                        \
        GLOBUS_NULL,                                                        \
        GLOBUS_GFS_ERROR_GENERIC,                                           \
        __FILE__,                                                           \
        _gfs_name,                                                          \
        __LINE__,                                                           \
        _msg))


typedef struct globus_gfs_acl_example_state_s
{
    globus_gfs_acl_info_t *             acl_info;
    globus_gfs_acl_handle_t             acl_handle;
    
    
    globus_gfs_acl_action_t             action;
    globus_gfs_acl_object_desc_t *      object;
} globus_gfs_acl_example_state_t;


static
void
globus_gfs_acl_example_init_cb(
    void *                              user_arg)
{
    globus_gfs_acl_example_state_t *    state;
    globus_bool_t                       fail;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusGFSName(globus_gfs_acl_example_init_cb);
    GlobusGFSDebugEnter();
    
    state = (globus_gfs_acl_example_state_t *) user_arg;
    fail = random() % 2;
    
    if(fail)
    {
        result = GlobusACLExampleFailure(
            "Initialization failed in callback.");
    }
    
    globus_gfs_acl_authorized_finished(state->acl_handle, result);
    GlobusGFSDebugExit();
}


static
void
globus_gfs_acl_example_authorize_cb(
    void *                              user_arg)
{
    globus_gfs_acl_example_state_t *    state;
    globus_bool_t                       fail;
    char *                              msg;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusGFSName(globus_gfs_acl_example_authorize_cb);
    GlobusGFSDebugEnter();
    
    state = (globus_gfs_acl_example_state_t *) user_arg;
    fail = random() % 2;
    
    if(fail)
    {
        msg = globus_common_create_string(
            "Authorization failed in callback.\n"
            "Action: %s, Object: %s", 
            globus_gfs_acl_action_to_string(state->action),
            state->object->name);
        result = GlobusACLExampleFailure(msg);
        globus_free(msg);
    }
    
    globus_gfs_acl_authorized_finished(state->acl_handle, result);
    GlobusGFSDebugExit();
}


static
int
globus_gfs_acl_example_init(
    void **                             out_handle,
    globus_gfs_acl_info_t *             acl_info,
    globus_gfs_acl_handle_t             acl_handle,
    globus_result_t *                   out_res)
{
    globus_bool_t                       immediate_fail;
    globus_bool_t                       callback;
    globus_gfs_acl_example_state_t *    state;
    int                                 rc;
    GlobusGFSName(globus_gfs_acl_example_init);
    GlobusGFSDebugEnter();

    immediate_fail = (random() % 4 == 0);
    callback = (random() % 4 > 1);

    if(immediate_fail)
    {
        *out_res = GlobusACLExampleFailure(
            "Initialization failed immediately.");
    }
    else
    {
        *out_res = GLOBUS_SUCCESS;
        state = globus_malloc(sizeof(globus_gfs_acl_example_state_t));
        state->acl_info = acl_info;
        state->acl_handle = acl_handle;
        *out_handle = state;
    }

    if(callback && !immediate_fail)
    {
        globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_gfs_acl_example_init_cb,
            state);

        rc = GLOBUS_GFS_ACL_WOULD_BLOCK;
    }
    else
    {
        rc = GLOBUS_GFS_ACL_COMPLETE;
    }
    
    GlobusGFSDebugExit();
    return rc;
}


static
int
globus_gfs_acl_example_authorize(
    void *                              out_handle,
    globus_gfs_acl_action_t             action,
    globus_gfs_acl_object_desc_t *      object,
    globus_gfs_acl_info_t *             acl_info,
    globus_gfs_acl_handle_t             acl_handle,
    globus_result_t *                   out_res)
{
    globus_bool_t                       immediate_fail;
    globus_bool_t                       callback;
    globus_bool_t                       care_about_this_action;
    globus_gfs_acl_example_state_t *    state;
    
    int                                 rc;
    char *                              msg;
    GlobusGFSName(globus_gfs_acl_example_authorize);
    GlobusGFSDebugEnter();

    state = (globus_gfs_acl_example_state_t *) out_handle;

    immediate_fail = (random() % 4 == 0);
    callback = (random() % 4 > 1);

    switch(action)
    {
        case GFS_ACL_ACTION_DELETE:
            care_about_this_action = GLOBUS_TRUE;
            break;
        case GFS_ACL_ACTION_WRITE:
            care_about_this_action = GLOBUS_TRUE;
            break;
        case GFS_ACL_ACTION_CREATE:
            care_about_this_action = GLOBUS_TRUE;
            break;
        case GFS_ACL_ACTION_READ:
            care_about_this_action = GLOBUS_TRUE;
            break;
        case GFS_ACL_ACTION_LOOKUP:
            care_about_this_action = GLOBUS_TRUE;
            break;
        case GFS_ACL_ACTION_AUTHZ_ASSERT:
            care_about_this_action = GLOBUS_FALSE;
            break;
        case GFS_ACL_ACTION_COMMIT:
            care_about_this_action = GLOBUS_TRUE;
            break;
        default:
            care_about_this_action = GLOBUS_FALSE;
            break;
    }    

    if(care_about_this_action && immediate_fail)
    {
        msg = globus_common_create_string(
            "Authorization failed immediately.\n"
            "Action: %s, Object: %s", 
            globus_gfs_acl_action_to_string(action),
            object->name);
        *out_res = GlobusACLExampleFailure(msg);
        globus_free(msg);
    }
    else
    {
        *out_res = GLOBUS_SUCCESS;
        state->action = action;
        state->object = object;
    }
    
    if(callback && care_about_this_action && !immediate_fail)
    {
        globus_callback_register_oneshot(
            NULL,
            NULL,
            globus_gfs_acl_example_authorize_cb,
            state);

        rc = GLOBUS_GFS_ACL_WOULD_BLOCK;
    }
    else
    {
        rc = GLOBUS_GFS_ACL_COMPLETE;
    }
    
    GlobusGFSDebugExit();
    return rc;
}


static
void
globus_gfs_acl_example_destroy(
    void *                              out_handle)
{
    globus_gfs_acl_example_state_t *    state;

    GlobusGFSName(globus_gfs_acl_example_destroy);
    GlobusGFSDebugEnter();

    state = (globus_gfs_acl_example_state_t *) out_handle;
    
    if(state)
    {
        globus_free(state);
    }

    GlobusGFSDebugExit();
}

static
void
globus_gfs_acl_example_audit(
    void *                              out_handle,
    globus_gfs_acl_action_t             action,
    globus_gfs_acl_object_desc_t *      object,
    const char *                        message)
{

}

globus_gfs_acl_module_t                 globus_gfs_acl_example_module = 
{
    globus_gfs_acl_example_init,
    globus_gfs_acl_example_authorize,
    globus_gfs_acl_example_destroy,
    globus_gfs_acl_example_audit
};

static int globus_gfs_acl_example_activate(void);
static int globus_gfs_acl_example_deactivate(void);

GlobusExtensionDefineModule(globus_gridftp_server_acl_example) =
{
    "globus_gridftp_server_acl_example",
    globus_gfs_acl_example_activate,
    globus_gfs_acl_example_deactivate,
    NULL,
    NULL,
    &local_version
};

static
int
globus_gfs_acl_example_activate(void)
{
    globus_extension_registry_add(
        GLOBUS_GFS_ACL_REGISTRY,
        "example",
        GlobusExtensionMyModule(globus_gridftp_server_acl_example),
        &globus_gfs_acl_example_module);

    return 0;
}

static
int
globus_gfs_acl_example_deactivate(void)
{
    globus_extension_registry_remove(
        GLOBUS_GFS_ACL_REGISTRY, "example");

    return 0;
}

