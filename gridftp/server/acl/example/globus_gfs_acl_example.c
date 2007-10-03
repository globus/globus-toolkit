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


/* this is an example ACL module for the GridFTP server.  this module is
 * functional in the sense that it will randomly fail/deny access for 
 * most actions.  to test, run globus-gridftp-server with the option 
 * '-acl example' after installing this package. 
 * 
 * the code layout is meant to be an example and probably a commonly useful
 * way of implementing your own callout, but it is not strictly the only way.
 * check globus_gridftp_server.h for more information on the interface 
 * this implements. */

#include "globus_gridftp_server.h"
#include "version.h"



/* simple macro to create a result_t mapped to an error string */
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



/* simple structure to store a few things we would like to keep track of
 * across different callouts. */
typedef struct globus_gfs_acl_example_state_s
{
    globus_gfs_acl_info_t *             acl_info;
    globus_gfs_acl_handle_t             acl_handle;
    
    globus_gfs_acl_action_t             action;
    globus_gfs_acl_object_desc_t *      object;
} globus_gfs_acl_example_state_t;



/* initialization callback.  we had to make some sort of asyncronous
 * call and now we are here with our answer. */
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
    
    /* imagine fail here is the answer to our query. */
    if(fail)
    {
        result = GlobusACLExampleFailure(
            "Initialization failed in callback.");
    }
    
    /* to finalize the authorization initialization, we call 
     * globus_gfs_acl_authorized_finished with the result_t specifing 
     * the error message or GLOBUS_SUCCESS.  Note we saved the acl_handle
     * in our state structure in order to carry it over into this callback. */
    globus_gfs_acl_authorized_finished(state->acl_handle, result);
    GlobusGFSDebugExit();
}



/* authorization callback.  we had to make some sort of asyncronous
 * call and now we are here with our answer. */

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

    /* imagine fail here is the answer to our query. */
    if(fail)
    {
        /* notice we stored the action and object information in our 
         * state structure in order to carry it over into this callback
         * and reference it in the error response. */
        msg = globus_common_create_string(
            "Authorization failed in callback.\n"
            "Action: %s, Object: %s", 
            globus_gfs_acl_action_to_string(state->action),
            state->object->name);
        result = GlobusACLExampleFailure(msg);
        globus_free(msg);
    }

    /* to finalize the authorization, we call 
     * globus_gfs_acl_authorized_finished with the result_t specifing 
     * the error message or GLOBUS_SUCCESS.  Note we saved the acl_handle
     * in our state structure (either in the initialzation call or in 
     * the authorization call) in order to carry it over into this callback. */    
    globus_gfs_acl_authorized_finished(state->acl_handle, result);
    GlobusGFSDebugExit();
}



/* initialization callout.  this is ususally necessary.  must be
 * implemented if:
 * 1) we need to set up some sort of internal state/handle that can be passed
 * back to us in all callouts
 * and/or
 * 2) we are interested in authorizing the gridftp session based on client
 * user information.
 * 
 * must return GLOBUS_GFS_ACL_COMPLETE or GLOBUS_GFS_ACL_WOULD_BLOCK, and
 * store GLOBUS_SUCCESS or an error result_t in out_res.  if returning 
 * GLOBUS_GFS_ACL_WOULD_BLOCK, the result must be returned in a call to 
 * globus_gfs_acl_authorized_finished().  optionally, a pointer may be stored
 * in out_handle.  this pointer will then be passed back in later callouts.
 */

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

    /* here we can look at acl_info to get information on the user attempting
     * the connection, and allow/deny based on that.  imagine
     * immediate_fail is the answer to some simple authorization query. */

    /* *out_res is where we store the immediate result.  the macro can be 
     * used to generate an error result_t with a message appropriate
     * for the client.  unless we are failing immediately, *out_res should
     * be GLOBUS_SUCCESS. */
     
    if(immediate_fail)
    {
        *out_res = GlobusACLExampleFailure(
            "Initialization failed immediately.");
    }
    else
    {
        *out_res = GLOBUS_SUCCESS;

        /* as long as we're not going to fail immediately, we can set up
         * an internal state structure with any data we wish.  it might
         * make sense to store the user info struct provided here, in case
         * we need to reference it later.  we store the pointer to our state
         * struct in *out_handle so that it can be passed back to us in 
         * future calls to our authorize function. */

        state = globus_malloc(sizeof(globus_gfs_acl_example_state_t));
        state->acl_info = acl_info;
        state->acl_handle = acl_handle;
        *out_handle = state;
    }

    /* if we need to make an asyncronous call in order to find the information
     * we need, this function must return GLOBUS_GFS_ACL_WOULD_BLOCK now and
     * follow up with the authorization later via a callback.  continue with 
     * globus_gfs_acl_example_init_cb(). */
     
    /* if we return GLOBUS_GFS_ACL_COMPLETE now, then we are finished and 
     * *out_res is the value used to determine if the client is allowed
     * this connection. */
     
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



/* authorization callout.  this is usually necessary.  here we will 
 * get called to authrorize all actions the client performs.  see the
 * globus_gfs_acl_action_t declaration for all of the supported actions.
 * 
 * must return GLOBUS_GFS_ACL_COMPLETE or GLOBUS_GFS_ACL_WOULD_BLOCK, and
 * store GLOBUS_SUCCESS or an error result_t in out_res.  If returning 
 * GLOBUS_GFS_ACL_WOULD_BLOCK, the result must be returned in a call to 
 * globus_gfs_acl_authorized_finished().
 */
 
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

    /* notice we can refer back to our state structure if we saved one
     * during the initialzation call. */
    state = (globus_gfs_acl_example_state_t *) out_handle;

    immediate_fail = (random() % 4 == 0);
    callback = (random() % 4 > 1);

    /* we only need to do work when this is an action we care about.
     * we can get information on the object in the object structure, which
     * contains information such as the object name (usually a filename)
     * and the size of data that we wish to write or commit.  see the 
     * globus_gfs_acl_action_t declaration in globus_gridftp_server.h for
     * further info on each action. */ 
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

    /* *out_res is where we store the immediate result.  the macro can be 
     * used to generate an error result_t with a message appropriate
     * for the client.  unless we are failing immediately, *out_res should
     * be GLOBUS_SUCCESS. */

    /* imagine this is an action we care about, and immediate_fail is 
     * the answer to some simple query. */

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
    
    /* if we need to make an asyncronous call in order to find the information
     * we need, this function must return GLOBUS_GFS_ACL_WOULD_BLOCK now and
     * follow up with the authorization later via a callback.  continue with 
     * globus_gfs_acl_example_authorize_cb(). */
     
    /* if we return GLOBUS_GFS_ACL_COMPLETE now, then we are finished and 
     * *out_res is the value used to determine if the client is allowed this
     * action or not. */

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



/* destructor callout. clean up our session state if necessary */

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


/* audit callout.  informational callout only.  implement this if you would
 * like to be notified of activities, but don't need to allow/deny them. */
 
static
void
globus_gfs_acl_example_audit(
    void *                              out_handle,
    globus_gfs_acl_action_t             action,
    globus_gfs_acl_object_desc_t *      object,
    const char *                        message)
{

}


/* module activation and registration calls */

/* plugin specific module descriptor.  
 * Only define the functions you implement, otherwise NULL */
globus_gfs_acl_module_t                 globus_gfs_acl_example_module = 
{
    globus_gfs_acl_example_init,
    globus_gfs_acl_example_authorize,
    globus_gfs_acl_example_destroy,
    globus_gfs_acl_example_audit
};

static int globus_gfs_acl_example_activate(void);
static int globus_gfs_acl_example_deactivate(void);

/* globus module system descriptor */ 
GlobusExtensionDefineModule(globus_gridftp_server_acl_example) =
{
    "globus_gridftp_server_acl_example",
    globus_gfs_acl_example_activate,
    globus_gfs_acl_example_deactivate,
    NULL,
    NULL,
    &local_version
};


/* activation gets called when the module is loaded.  All we need to do here
 * is insert ourselves into the gridftp acl registry, and remove when we
 * get unloaded. */
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

