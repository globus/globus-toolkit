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
#include <stdlib.h>


/*
 * ap is:
 *		void * authz_system_state;
 */
globus_result_t
authz_test_system_init_callout(
    va_list                             ap)
{
  void * authz_system_state;
  
  globus_result_t                 result = GLOBUS_SUCCESS;
  static char *                   _function_name_ =
    "authz_test_system_init_callout";

  authz_system_state = va_arg(ap, void *);
  printf("in %s, system state is %x\n", _function_name_,
	 (unsigned)authz_system_state);

  /* Do something here.  */

  return result;
}


globus_result_t
authz_test_system_destroy_callout(
    va_list                             ap)
{
  void * authz_system_state;
  
  globus_result_t                 result = GLOBUS_SUCCESS;
  static char *                   _function_name_ =
    "authz_test_system_destroy_callout";


  authz_system_state = va_arg(ap, void *);
  printf("in %s, system state is %x\n", _function_name_,
	 (unsigned)authz_system_state);
  /* Do something here. */

  return result;

}


globus_result_t
authz_test_handle_init_callout(
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
    "authz_test_handle_init_callout";

  handle = va_arg(ap, globus_gsi_authz_handle_t *);
  service_name = va_arg(ap, char *);
  context = va_arg(ap, gss_ctx_id_t);
  callback = va_arg(ap,  globus_gsi_authz_cb_t);
  callback_arg = va_arg(ap, void *);
  authz_system_state = va_arg(ap, void *);
  printf("in %s\n\tservice name is %s\n\tcontext is %x\n\tsystem state is %x\n",
	 _function_name_, service_name,
	 (unsigned)context,
	 (unsigned)authz_system_state);

  *handle = malloc(sizeof(globus_gsi_authz_cb_t));
  memset(*handle, 0, sizeof(*handle));
      
  /* Do something here. */
  callback(callback_arg, callback_arg, result);

  return result;
}


globus_result_t
authz_test_authorize_async_callout(
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
    "authz_test_authorize_async_callout";

  
  handle = va_arg(ap, globus_gsi_authz_handle_t);
  action = va_arg(ap, char *);
  object = va_arg(ap, char *);
  callback = va_arg(ap,  globus_gsi_authz_cb_t);
  callback_arg = va_arg(ap, void *);
  authz_system_state = va_arg(ap, void *);

  /* ???????????? */
  /* Am I supposed to call GAA-API as a callback with callback_arg???? */
  /* Or, can I just do something like below? */
  printf("in %s, action is %s, object is %s, system state is %x\n",
	 _function_name_, action, object,
	 (unsigned)authz_system_state);

  callback(callback_arg, handle, result);

  return result;
}

int
authz_test_cancel_callout(
    va_list                             ap)
{
  void * authz_system_state;

  int                             result = (int) GLOBUS_SUCCESS;
  static char *                   _function_name_ =
    "authz_test_cancel_callout";

  authz_system_state = va_arg(ap, void *);
  printf("in %s, system state is %x\n", _function_name_,
	 (unsigned)authz_system_state);
  /* Do something here. */

  return result;
}

int
authz_test_handle_destroy_callout(
    va_list                             ap)
{
  globus_gsi_authz_handle_t * handle;
  void * authz_system_state;

  int                             result = (int) GLOBUS_SUCCESS;
  static char *                   _function_name_ =
    "authz_test_handle_destroy_callout";

  authz_system_state = va_arg(ap, void *);
  printf("in %s, system state is %x\n", _function_name_,
	 (unsigned)authz_system_state);

  if (handle != NULL)
  {
    free(handle);
  }
  
  return result;
    
}
