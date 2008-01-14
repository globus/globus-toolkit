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

#include "globus_common.h"
#include "version.h"
#include "globus_i_gsi_authz.h"
#include "globus_callout.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_authz_callout_error.h"


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_authz.c
 * Globus Authorization API
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
static int globus_l_gsi_authz_activate(void);
static int globus_l_gsi_authz_deactivate(void);

int globus_i_gsi_authz_debug_level = 0;
FILE * globus_i_gsi_authz_debug_fstream = NULL;

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t globus_i_gsi_authz_module =
{
    "globus_gsi_authz",
    globus_l_gsi_authz_activate,
    globus_l_gsi_authz_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/*
 * These variables are used to keep state across requests.
 */
static globus_callout_handle_t        callout_handle;
static void *                         authz_system_state = NULL;

/**
 * Module activation
 */
static int globus_l_gsi_authz_activate(void)
{
    /* activate any module used by the implementation */
    /* initialize a globus callout handle */
    /* call authz system init callout */
    /* the callout type is "GLOBUS_GSI_AUTHZ_SYSTEM_INIT" */
    /* arguments are: void ** authz_system_state, ie &authz_system_state */
    /* should define some standard errors for this callout */

    int		                        rc = (int) GLOBUS_SUCCESS;
    globus_result_t                     result;
    globus_object_t *                   error;
    char *                              filename = NULL;
    char *                              tmp_string;
    static char *                       _function_name_ =
        "globus_l_gsi_authz_activate";

    tmp_string = globus_module_getenv("GLOBUS_GSI_AUTHZ_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_authz_debug_level = atoi(tmp_string);
        
        if(globus_i_gsi_authz_debug_level < 0)
        {
            globus_i_gsi_authz_debug_level = 0;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSI_AUTHZ_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_authz_debug_fstream = fopen(tmp_string, "a");
        if(globus_i_gsi_authz_debug_fstream == NULL)
        {
            rc = (int) GLOBUS_FAILURE;
            goto exit;
        }
    }
    else
    {
      /* if the env. var. isn't set, use stderr */
        globus_i_gsi_authz_debug_fstream = stderr;
    }

    GLOBUS_I_GSI_AUTHZ_DEBUG_ENTER;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != (int)GLOBUS_SUCCESS)
    {
        goto exit;
    }

    rc = globus_module_activate(GLOBUS_CALLOUT_MODULE);
    if(rc != (int)GLOBUS_SUCCESS)
    {
        goto deactivate_common;
    }

    rc = globus_module_activate(GLOBUS_GSI_AUTHZ_CALLOUT_ERROR_MODULE);
    if(rc != (int)GLOBUS_SUCCESS)
    {
        goto deactivate_callout;
    }
    
    rc = globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE);
    if(rc != (int)GLOBUS_SUCCESS)
    {
        goto deactivate_callout_error;
    }

    
    result = GLOBUS_GSI_SYSCONFIG_GET_AUTHZ_CONF_FILENAME(&filename);

    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_get(result);
        filename = NULL;
        
        if(globus_error_match(
               error,
               GLOBUS_GSI_SYSCONFIG_MODULE,
               GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_AUTHZ_FILENAME)
           == GLOBUS_TRUE)
        {
            globus_object_free(error);
        }
        else
        {
            rc = (int) globus_error_put(error);
            goto deactivate_sysconfig;
        }
    }
    
    /* initialize a globus callout handle */
    rc = (int)globus_callout_handle_init(&callout_handle);
    if(rc != (int)GLOBUS_SUCCESS)
    {
        goto deactivate_sysconfig;
    }

    if(filename)
    { 
        rc = (int)globus_callout_read_config(callout_handle, filename);
        if(rc != (int)GLOBUS_SUCCESS)
        {
            goto free_handle;
        }
        free(filename);
        filename = NULL;
        
        /* call authz system init callout */
        /* the callout type is "GLOBUS_GSI_AUTHZ_SYSTEM_INIT" */
        /* arguments are: void ** authz_system_state, ie &authz_system_state */
        result = globus_callout_call_type(callout_handle,
                                          "GLOBUS_GSI_AUTHZ_SYSTEM_INIT",
                                          &authz_system_state);
        if(result != GLOBUS_SUCCESS)
        {
            error = globus_error_get(result);
            
            if(globus_error_match(
                   error,
                   GLOBUS_CALLOUT_MODULE,
                   GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED)
               == GLOBUS_TRUE)
            {
                globus_object_free(error);
            }
            else
            {
                result = globus_error_put(error);
                result = GLOBUS_GSI_AUTHZ_ERROR_WITH_CALLOUT(result);
                rc = (int) result;
                goto free_handle;
            }
        }
    }

    GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT;
    return rc;

 free_handle:
    globus_callout_handle_destroy(callout_handle);
 deactivate_sysconfig:
    globus_module_deactivate(GLOBUS_GSI_SYSCONFIG_MODULE);
 deactivate_callout_error:
    globus_module_deactivate(GLOBUS_GSI_AUTHZ_CALLOUT_ERROR_MODULE);
 deactivate_callout:
    globus_module_deactivate(GLOBUS_CALLOUT_MODULE);
 deactivate_common:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
 exit:

    if(filename)
    {
        free(filename);
    }
    
    GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT;

    return(rc);
  
}

/**
 * Module deactivation
 ***/
static int globus_l_gsi_authz_deactivate(void)
{
    /* deactivate any module used by the implementation */
    /* destroy globus callout handle */
    /* call authz system destroy callout */
    /* the callout type is "GLOBUS_GSI_AUTHZ_SYSTEM_DESTROY" */
    /* arguments are: void ** authz_system_state, ie &authz_system_state */
    /* should define some standard errors for this callout */
    static char *                       _function_name_ =
	"globus_l_gsi_authz_deactivate";
    
    GLOBUS_I_GSI_AUTHZ_DEBUG_ENTER;
    
    /* destroy globus callout handle here */
    /* call authz system destroy callout */
    /* the callout type is "GLOBUS_GSI_AUTHZ_SYSTEM_DESTROY" */
    /* arguments are: void ** authz_system_state, ie &authz_system_state */
    globus_callout_call_type(callout_handle,
                             "GLOBUS_GSI_AUTHZ_SYSTEM_DESTROY",
                             &authz_system_state);
    
    globus_callout_handle_destroy(callout_handle);
    
    /* deactivate any module used by the implementation */

    globus_module_deactivate(GLOBUS_GSI_SYSCONFIG_MODULE);
    globus_module_deactivate(GLOBUS_GSI_AUTHZ_CALLOUT_ERROR_MODULE);
    globus_module_deactivate(GLOBUS_CALLOUT_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT;
    
    if(globus_i_gsi_authz_debug_fstream != stderr)
    {
	fclose(globus_i_gsi_authz_debug_fstream);
    }
    
    return (int) GLOBUS_SUCCESS;
}

static void callback_wrapper(
    void *                              args)
{
    globus_l_gsi_authz_cb_arg_t *       wrapper_args;
    
    wrapper_args = (globus_l_gsi_authz_cb_arg_t *) args;

    wrapper_args->callback(wrapper_args->arg, wrapper_args->handle,
                           GLOBUS_SUCCESS);
    free(wrapper_args);

    return;
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * @name Initialize Handle
 */
/* @{ */
/**
 * Initializes a handle
 * @ingroup globus_gsi_authz
 *
 * @param handle
 *        Pointer to the handle that is to be initialized
 * @param service_name
 *        Service to authorize access to
 * @param context
 *        Security context used to contact the service
 * @param callback
 *        Callback function to call when authz handle init completes
 * @param callback_arg
 *        Argument to callback function
 * @return
 *        GLOBUS_SUCCESS if successful
 *        A Globus error object on failure:
 */
globus_result_t
globus_gsi_authz_handle_init(
    globus_gsi_authz_handle_t *         handle,
    const char *                        service_name,
    const gss_ctx_id_t                  context,
    globus_gsi_authz_cb_t               callback,
    void *                              callback_arg)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_object_t *                   error;
    static char *                       _function_name_ =
	"globus_gsi_authz_handle_init";
    
    GLOBUS_I_GSI_AUTHZ_DEBUG_ENTER;

    if (handle == NULL)
    {
	result = GLOBUS_GSI_AUTHZ_ERROR_NULL_VALUE("handle");
	goto exit;
    }

    if (service_name == NULL)
    {
	result = GLOBUS_GSI_AUTHZ_ERROR_NULL_VALUE("service_name");
	goto exit;
    }
    
    /* call authz system per connection init callout */
    /* the callout type is "GLOBUS_GSI_AUTHZ_HANDLE_INIT" */
    /* arguments are: globus_gsi_authz_handle_t * handle,
       const char * service_name,
       const gss_ctx_id_t context,
       globus_gsi_authz_cb_t callback,
       void * callback_arg,
       void * authz_system_state */
    result = globus_callout_call_type(callout_handle,
				      "GLOBUS_GSI_AUTHZ_HANDLE_INIT",
				      handle,
				      service_name,
				      context,
				      callback,
				      callback_arg,
				      authz_system_state);
    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_get(result);
            
        if(globus_error_match(
               error,
               GLOBUS_CALLOUT_MODULE,
               GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED)
           == GLOBUS_TRUE)
        {
            globus_l_gsi_authz_cb_arg_t *   callback_wrapper_arg;
            globus_reltime_t                reltime;
            
            globus_object_free(error);
            result = GLOBUS_SUCCESS;

            /* oneshot here */

            callback_wrapper_arg = malloc(sizeof(globus_l_gsi_authz_cb_arg_t));
            if(!callback_wrapper_arg)
            {
                result = GLOBUS_GSI_AUTH_HANDLE_MALLOC_ERROR(
                    sizeof(globus_l_gsi_authz_cb_arg_t));
            }
            else
            {
                *handle = NULL;
                callback_wrapper_arg->handle = NULL;
                callback_wrapper_arg->arg = callback_arg;
                callback_wrapper_arg->callback = callback;
            
                GlobusTimeReltimeSet(reltime, 0, 0);
                globus_callback_register_oneshot(
                    GLOBUS_NULL,
                    &reltime,
                    callback_wrapper,
                    callback_wrapper_arg);
            }
        }
        else
        {
            result = globus_error_put(error);
            result = GLOBUS_GSI_AUTHZ_ERROR_WITH_CALLOUT(result);
        }
    }
    
    GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT;

 exit:
    
    return result;
}
/* globus_gsi_authz_handle_init */
/* @} */


/**
 * @name Authorization decision made here
 */
/*@{*/
/**
 * Authorization decision made here
 * @ingroup globus_gsi_authz
 *
 * @param handle
 *        Pointer to the handle that is to be initialized
 * @param action
 *        Action to authorize
 * @param object
 *        Object that the action pertains to.
 * @param callback
 *        Callback function to call when authorization completes
 * @param callback_arg
 *        Argument to callback function
 *
 * @return
 *        GLOBUS_SUCCESS if successful
 *        A Globus error object on failure:
 */
globus_result_t
globus_gsi_authorize(
  globus_gsi_authz_handle_t             handle,
  const void *                          action,
  const void *                          object,
  globus_gsi_authz_cb_t                 callback,
  void *                                callback_arg)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_object_t *                   error;
    static char *                       _function_name_ =
	"globus_gsi_authorize";
    
    if(callback == GLOBUS_NULL)
    {
	result = GLOBUS_GSI_AUTHZ_ERROR_NULL_VALUE("callback parameter");
	goto exit;
    }
    
    GLOBUS_I_GSI_AUTHZ_DEBUG_ENTER;
    
    /* call main authorization callout */
    /* the callout type is "GLOBUS_GSI_AUTHORIZE_ASYNC" */
    /* arguments are: globus_gsi_authz_handle_t handle,
       const void * action,
       const void * object,                      
       globus_gsi_authz_cb_t callback,
       void * callback_arg,
       void * authz_system_state */
    result = globus_callout_call_type(callout_handle,
				      "GLOBUS_GSI_AUTHORIZE_ASYNC",
				      handle,
				      action,
				      object,
				      callback,
				      callback_arg,
				      authz_system_state);

    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_get(result);
            
        if(globus_error_match(
               error,
               GLOBUS_CALLOUT_MODULE,
               GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED)
           == GLOBUS_TRUE)
        {
            globus_l_gsi_authz_cb_arg_t *   callback_wrapper_arg;
            globus_reltime_t                reltime;
            
            globus_object_free(error);
            result = GLOBUS_SUCCESS;

            /* oneshot here */

            callback_wrapper_arg = malloc(sizeof(globus_l_gsi_authz_cb_arg_t));
            if(!callback_wrapper_arg)
            {
                result = GLOBUS_GSI_AUTH_HANDLE_MALLOC_ERROR(
                    sizeof(globus_l_gsi_authz_cb_arg_t));
            }
            else
            {
                callback_wrapper_arg->handle = handle;
                callback_wrapper_arg->arg = callback_arg;
                callback_wrapper_arg->callback = callback;
            
                GlobusTimeReltimeSet(reltime, 0, 0);
                globus_callback_register_oneshot(
                    GLOBUS_NULL,
                    &reltime,
                    callback_wrapper,
                    callback_wrapper_arg);
            }
        }
        else
        {
            result = globus_error_put(error);
            result = GLOBUS_GSI_AUTHZ_ERROR_WITH_CALLOUT(result);
        }
    }
    
 exit:
    GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT;  
    return result;
}
/*@}*/

globus_result_t
globus_gsi_cancel_authz(
    globus_gsi_authz_handle_t           handle)
{
    /* call cancel callout */
    /* the callout type is "GLOBUS_GSI_AUTHZ_CANCEL" */
    /* arguments are: globus_gsi_authz_handle_t * handle,
       void * authz_system_state */
    /* should define some standard errors for this callout */    
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
	"globus_gsi_cancel_authz";
    
    
    GLOBUS_I_GSI_AUTHZ_DEBUG_ENTER; 

    result = globus_callout_call_type(callout_handle,
				      "GLOBUS_GSI_AUTHZ_CANCEL",
				      handle,
				      &authz_system_state);

    GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT; 
    return result;
}


/**
 * @name Destroy Handle
 */
/*@{*/
/**
 * Destroy a Globus GSI authz handle
 * @ingroup globus_gsi_authz
 *
 * @param handle
 *        The handle that is to be destroyed
 * @param callback
 *        Callback function to call when handle is destroyed
 * @param callback_arg
 *        Argument to callback function
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_authz_handle_destroy(
    globus_gsi_authz_handle_t           handle,
    globus_gsi_authz_cb_t               callback,
    void *                              callback_arg)
{
    /* call authz system callout the frees per connection state */
    /* the callout type is "GLOBUS_GSI_AUTHZ_HANDLE_DESTROY" */
    /* arguments are: globus_gsi_authz_handle_t * handle,
                      globus_gsi_authz_cb_t callback,
                      void * callback_arg,
                      void * authz_system_state */
    /* should define some standard errors for this callout */    

    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_object_t *                   error;
    static char *                       _function_name_ =
	"globus_gsi_authz_handle_destroy";

    GLOBUS_I_GSI_AUTHZ_DEBUG_ENTER;

    result = globus_callout_call_type(callout_handle,
				      "GLOBUS_GSI_AUTHZ_HANDLE_DESTROY",
				      handle,
				      callback,
				      callback_arg,
				      &authz_system_state);

    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_get(result);
            
        if(globus_error_match(
               error,
               GLOBUS_CALLOUT_MODULE,
               GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED)
           == GLOBUS_TRUE)
        {
            globus_l_gsi_authz_cb_arg_t *   callback_wrapper_arg;
            globus_reltime_t                reltime;
            
            globus_object_free(error);
            result = GLOBUS_SUCCESS;

            /* oneshot here */

            callback_wrapper_arg = malloc(sizeof(globus_l_gsi_authz_cb_arg_t));
            if(!callback_wrapper_arg)
            {
                result = GLOBUS_GSI_AUTH_HANDLE_MALLOC_ERROR(
                    sizeof(globus_l_gsi_authz_cb_arg_t));
            }
            else
            {
                callback_wrapper_arg->handle = handle;
                callback_wrapper_arg->arg = callback_arg;
                callback_wrapper_arg->callback = callback;
            
                GlobusTimeReltimeSet(reltime, 0, 0);
                globus_callback_register_oneshot(
                    GLOBUS_NULL,
                    &reltime,
                    callback_wrapper,
                    callback_wrapper_arg);
            }
        }
        else
        {
            result = globus_error_put(error);
            result = GLOBUS_GSI_AUTHZ_ERROR_WITH_CALLOUT(result);
        }
    }
    
    GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT;    
    return result;
}
/*globus_gsi_authz_handle_destroy*/
/*@}*/

/**
 * @name Query for authorization identity
 */
/*@{*/
/**
 * Query for authorization identity
 * @ingroup globus_gsi_authz
 *
 * @param handle
 *        The handle that is to be used for the identity check.
 * @param identity_ptr
 *        The authorization identity determined by the authorization handle.
 *        This is must be freed by the caller.  If the value is NULL (and this
 *        function returned GLOBUS_SUCCESS), the caller should use the
 *        authenticated identity.
 * @param callback
 *        Callback function to call when identity is determined.
 * @param callback_arg
 *        Argument to callback function.
 *
 * @return 
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_authz_get_authorization_identity(
    globus_gsi_authz_handle_t           handle,
    char **				identity_ptr,
    globus_gsi_authz_cb_t               callback,
    void *                              callback_arg)
{

    /* call authz system callout to get the authorization identity */
    /* the callout type is "GLOBUS_GSI_AUTHZ_GET_AUTHORIZATION_IDENTITY" */
    /* arguments are: globus_gsi_authz_handle_t * handle,
       		      char **identity_ptr,
                      globus_gsi_authz_cb_t callback,
                      void * callback_arg,
                      void * authz_system_state */
    /* should define some standard errors for this callout */    

    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_object_t *                   error;
    static char *                       _function_name_ =
	"globus_gsi_authz_get_authorization_identity";

    GLOBUS_I_GSI_AUTHZ_DEBUG_ENTER;

    if(callback == GLOBUS_NULL)
    {
	result = GLOBUS_GSI_AUTHZ_ERROR_NULL_VALUE("callback parameter");
	goto exit;
    }
    
    if(callback == GLOBUS_NULL)
    {
	result = GLOBUS_GSI_AUTHZ_ERROR_NULL_VALUE("identity_ptr parameter");
	goto exit;
    }
    
    result = globus_callout_call_type(callout_handle,
				      "GLOBUS_GSI_GET_AUTHORIZATION_IDENTITY",
				      handle,
				      identity_ptr,
				      callback,
				      callback_arg,
				      &authz_system_state);

    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_get(result);
            
        if(globus_error_match(
               error,
               GLOBUS_CALLOUT_MODULE,
               GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED)
           == GLOBUS_TRUE)
        {
            globus_l_gsi_authz_cb_arg_t *   callback_wrapper_arg;
            globus_reltime_t                reltime;
            
            globus_object_free(error);
            result = GLOBUS_SUCCESS;

            /* oneshot here */

            callback_wrapper_arg = malloc(sizeof(globus_l_gsi_authz_cb_arg_t));
            if(!callback_wrapper_arg)
            {
                result = GLOBUS_GSI_AUTH_HANDLE_MALLOC_ERROR(
                    sizeof(globus_l_gsi_authz_cb_arg_t));
            }
            else
            {
                callback_wrapper_arg->handle = handle;
                callback_wrapper_arg->arg = callback_arg;
                callback_wrapper_arg->callback = callback;
            
                GlobusTimeReltimeSet(reltime, 0, 0);
                globus_callback_register_oneshot(
                    GLOBUS_NULL,
                    &reltime,
                    callback_wrapper,
                    callback_wrapper_arg);
            }
        }
        else
        {
            result = globus_error_put(error);
            result = GLOBUS_GSI_AUTHZ_ERROR_WITH_CALLOUT(result);
        }
    }
    
 exit:
    
    GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT;    
    return result;
}
/* globus_gsi_authz_get_authorization_identity() */
/*@}*/
