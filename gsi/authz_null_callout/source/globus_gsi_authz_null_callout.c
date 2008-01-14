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
#include "globus_gsi_authz.h"
#include "globus_i_gsi_authz_null_callout.h"
#include <stdlib.h>

#ifdef BUILD_DEBUG
int      globus_i_gsi_authz_null_callout_debug_level   = 0;
FILE *   globus_i_gsi_authz_null_callout_debug_fstream = 0;
#endif /* BUILD_DEBUG */

/*
 * ap is:
 *		void * authz_system_state;
 */
globus_result_t
authz_null_system_init_callout(
    va_list                             ap)
{
    void * authz_system_state;
    
    globus_result_t                 result = GLOBUS_SUCCESS;
    static char *                   _function_name_ =
	"authz_null_system_init_callout";
#ifdef BUILD_DEBUG
    char *			  tmp_string = 0;
#endif /* BUILD_DEBUG */

#ifdef BUILD_DEBUG    
    tmp_string = globus_module_getenv("GLOBUS_GSI_AUTHZ_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_authz_null_callout_debug_level = atoi(tmp_string);
        
        if(globus_i_gsi_authz_null_callout_debug_level < 0)
        {
            globus_i_gsi_authz_null_callout_debug_level = 0;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSI_AUTHZ_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_authz_null_callout_debug_fstream = fopen(tmp_string, "a");
    }

    if (globus_i_gsi_authz_null_callout_debug_fstream == 0)
    {
      /* if the env. var. isn't set (or the fopen failed), use stderr */
        globus_i_gsi_authz_null_callout_debug_fstream = stderr;
    }
#endif /* BUILD_DEBUG */

    authz_system_state = va_arg(ap, void *);
    GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF3(
	GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_TRACE,
	"in %s, system state is %x\n",
	_function_name_,
	(unsigned)authz_system_state);
    
    /* Do something here.  */
    
    return result;
}

globus_result_t
authz_null_system_destroy_callout(
    va_list                             ap)
{
    void * authz_system_state;
    
    globus_result_t                 result = GLOBUS_SUCCESS;
    static char *                   _function_name_ =
	"authz_null_system_destroy_callout";
    
    
    authz_system_state = va_arg(ap, void *);
    GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF3(
	GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_TRACE,
	"in %s, system state is %x\n", _function_name_,
	 (unsigned)authz_system_state);
    
    /* Do something here. */
    
#ifdef BUILD_DEBUG
    if (globus_i_gsi_authz_null_callout_debug_fstream &&
	(globus_i_gsi_authz_null_callout_debug_fstream != stderr))
    {
	fclose(globus_i_gsi_authz_null_callout_debug_fstream);
	globus_i_gsi_authz_null_callout_debug_fstream = stderr;
    }
#endif /* BUILD_DEBUG */
	
    return result;

}


globus_result_t
authz_null_handle_init_callout(
    va_list                             ap)
{
  char * service_name;
  gss_ctx_id_t context;
  globus_gsi_authz_cb_t callback;
  void * callback_arg;
  void * authz_system_state;
  globus_gsi_authz_handle_t *handle;

  globus_result_t                 result = GLOBUS_SUCCESS;
  static char *                   _function_name_ =
    "authz_null_handle_init_callout";

  handle = va_arg(ap, globus_gsi_authz_handle_t *);
  service_name = va_arg(ap, char *);
  context = va_arg(ap, gss_ctx_id_t);
  callback = va_arg(ap,  globus_gsi_authz_cb_t);
  callback_arg = va_arg(ap, void *);
  authz_system_state = va_arg(ap, void *);
  GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF5(
      GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_TRACE,
      "in %s\n\tservice name is %s\n\tcontext is %x\n\tsystem state is %x\n",
      _function_name_,
      service_name,
      (unsigned)context,
      (unsigned)authz_system_state);
      
  *handle = globus_libc_calloc(1, sizeof(globus_gsi_authz_cb_t));
  /* Do something here. */
  callback(callback_arg, callback_arg, result);

  return result;
}


globus_result_t
authz_null_authorize_async_callout(
    va_list                             ap)
{
  globus_gsi_authz_handle_t handle;
  char * action;
  char * object;
  globus_gsi_authz_cb_t callback;
  void * callback_arg;
  void * authz_system_state;

  globus_result_t                 result = GLOBUS_SUCCESS;
  static char *                   _function_name_ =
    "authz_null_authorize_async_callout";

  
  handle = va_arg(ap, globus_gsi_authz_handle_t);
  action = va_arg(ap, char *);
  object = va_arg(ap, char *);
  callback = va_arg(ap,  globus_gsi_authz_cb_t);
  callback_arg = va_arg(ap, void *);
  authz_system_state = va_arg(ap, void *);

  /* ???????????? */
  /* Am I supposed to call GAA-API as a callback with callback_arg???? */
  /* Or, can I just do something like below? */
  GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF5(
      GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_TRACE,
      "in %s, action is %s, object is %s, system state is %x\n",
      _function_name_,
      action,
      object,
      (unsigned)authz_system_state);

  callback(callback_arg, handle, result);

  return result;
}

int
authz_null_cancel_callout(
    va_list                             ap)
{
    globus_gsi_authz_handle_t           handle;
    void * 				authz_system_state;

  int                             	result = (int) GLOBUS_SUCCESS;
  static char *                   	_function_name_ =
    "authz_null_cancel_callout";

    handle = va_arg(ap, globus_gsi_authz_handle_t);
    authz_system_state = va_arg(ap, void *);
    
    GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF3(
	GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_TRACE,
	"in %s, system state is %x\n",
	_function_name_,
	(unsigned)authz_system_state);

    return result;
}

int
authz_null_handle_destroy_callout(
    va_list                             ap)
{
    globus_gsi_authz_handle_t 		handle;
    void * 				authz_system_state;
    
    int                             	result = (int) GLOBUS_SUCCESS;
    static char *                   	_function_name_ =
	"authz_null_handle_destroy_callout";
    globus_gsi_authz_cb_t		callback;
    void *				callback_arg;
    
    
    handle = va_arg(ap, globus_gsi_authz_handle_t);
    callback = va_arg(ap, globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);
    
    GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF3(
	GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_TRACE,
	"in %s, system state is %x\n",
	_function_name_,
	(unsigned)authz_system_state);
    
    if (handle != NULL)
    {
	globus_libc_free(handle);
    }
    
    callback(callback_arg, handle, result);
    return result;
}

int
globus_gsi_authz_null_get_authorization_identity_callout(
    va_list                             ap)
{
    globus_gsi_authz_handle_t		handle;
    char **				identity_ptr;
    globus_gsi_authz_cb_t		callback;
    void *				callback_arg;
    void * 				authz_system_state;
    
    globus_result_t                    	result = GLOBUS_SUCCESS;
    static char *                   	_function_name_ =
	"globus_gsi_authz_null_handle_destroy_callout";


    handle = va_arg(ap, globus_gsi_authz_handle_t);
    identity_ptr = va_arg(ap, char **);
    callback = va_arg(ap, globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);

    return((int) result);
}

