#include "globus_common.h"
#include "gssapi.h"
#include "version.h"
#include <stdlib.h>


/**
 * GSI Authorization Callout Function
 *
 * This function exemplifies the GRAM authorization callout usage by writing
 * some of its arguments to the file "authz_callout.txt".
 *
 * @param ap
 *        This function, like all functions using the Globus Callout API, is 
 *        passed parameter though the variable argument list facility. The
 *        actual arguments that are passed are:
 *
 *        - The GSS Security context established during job startup
 *        - The GSS Security context established for the current operation.
 *        - The job id string
 *        - The parsed RSL used for job startup
 *        - A string describing the current operation. This string is currently
 *          limited to the values: "start", "cancel", "register", "unregister",
 *          "signal", "status" and "renew"
 *
 * @return
 *        GLOBUS_SUCCESS upon success
 *        A globus result structure upon failure (needs to be defined better)
 */

globus_result_t
globus_gsi_authz_system_init_callout(
    va_list                             ap)
{
  void * authz_system_state;
  
  int                             result = (int) GLOBUS_SUCCESS;
  char *                          tmp_string;
  static char *                   _function_name_ =
    "globus_gsi_authz_system_init_callout";

  authz_system_state = va_arg(ap, void *);

  /* Do something here.  */

  return result;
}


globus_result_t
globus_gsi_authz_system_destroy_callout(
    va_list                             ap)
{
  void * authz_system_state;
  
  int                             result = (int) GLOBUS_SUCCESS;
  char *                          tmp_string;
  static char *                   _function_name_ =
    "globus_gsi_authz_system_destroy_callout";


  authz_system_state = va_arg(ap, void *);

  /* Do something here. */

  return result;

}


globus_result_t
globus_gsi_authz_handle_init_callout(
    va_list                             ap)
{
  const char * service_name;
  const gss_ctx_id_t context;
  globus_gsi_authz_cb_t callback;
  void * callback_arg;
  void * authz_system_state;

  int                             result = (int) GLOBUS_SUCCESS;
  char *                          tmp_string;
  static char *                   _function_name_ =
    "globus_gsi_authz_handle_init_callout";

  service_name = va_arg(ap, char *);
  context = va_arg(ap, gss_ctx_id_t);
  callback = va_arg(ap,  globus_gsi_authz_cb_t);
  callback_arg = va_arg(ap, void *);
  authz_system_state = va_arg(ap, void *);

  /* Do something here. */

  return result;
}


globus_result_t
globus_gsi_authz_authorize_async_callout(
    va_list                             ap)
{
  globus_gsi_authz_handle_t * handle;
  const void * action;
  const void * object;
  globus_gsi_authz_cb_t callback;
  void * callback_arg;
  void * authz_system_state;

  int                             result = (int) GLOBUS_SUCCESS;
  char *                          tmp_string;
  static char *                   _function_name_ =
    "globus_gsi_authz_authorize_async_callout";

  
  handle = va_arg(ap, globus_gsi_authz_handle_t *);
  action = va_arg(ap, void *);
  object = va_arg(ap, void *);
  callback = va_arg(ap,  globus_gsi_authz_cb_t);
  callback_arg = va_arg(ap, void *);
  authz_system_state = va_arg(ap, void *);

  /* ???????????? */
  /* Am I supposed to call GAA-API as a callback with callback_arg???? */
  /* Or, can I just do something like below? */
  authz_system_state = globus_gsi_authz_gaa_callout(object, action);

  return result;
}


globus_gsi_authz_cancel_callout(
    va_list                             ap)
{
  void * authz_system_state;

  int                             result = (int) GLOBUS_SUCCESS;
  char *                          tmp_string;
  static char *                   _function_name_ =
    "globus_gsi_authz_cancel_callout";

  authz_system_state = va_arg(ap, void *);

  /* Do something here. */

  return result;


  
}


globus_gsi_authz_handle_destroy_callout(
    va_list                             ap)
{
  globus_gsi_authz_handle_t * handle;
  void * authz_system_state;

  int                             result = (int) GLOBUS_SUCCESS;
  char *                          tmp_string;
  static char *                   _function_name_ =
    "globus_gsi_authz_handle_destroy_callout";

  handle = va_arg(ap, globus_gsi_authz_handle_t);
  authz_system_state = va_arg(ap, void *);

  if (handle != NULL)
  {
    free(handle);
  }
  
  return result;
    
}
