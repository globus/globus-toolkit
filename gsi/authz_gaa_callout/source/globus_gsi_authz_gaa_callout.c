#include "globus_common.h"
#include "globus_gsi_authz.h"
#include "globus_i_gsi_authz_gaa_callout.h"
#include "globus_gsi_authz_callout_error.h"
#include "gaa.h"
#include "gaa_plugin.h"
#include <stdlib.h>

#ifdef BUILD_DEBUG
int      globus_i_gsi_authz_gaa_callout_debug_level   = 0;
FILE *   globus_i_gsi_authz_gaa_callout_debug_fstream = 0;
#endif /* BUILD_DEBUG */

static const gss_OID_desc saml_extension_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x09"}; 
const gss_OID_desc * const saml_extension = 
                &saml_extension_oid;

typedef struct authz_gaa_system_state_struct {
    char *gaa_config_file_name;
} authz_gaa_system_state_s, *authz_gaa_system_state_t;


/*
 * ap is:
 *		void * authz_system_state;
 */
globus_result_t
globus_gsi_authz_gaa_system_init_callout(
    va_list                             ap)
{
    void * authz_system_state;
    
    globus_result_t                 result = GLOBUS_SUCCESS;
    static char *                   _function_name_ =
	"globus_gsi_authz_gaa_system_init_callout";
    authz_gaa_system_state_t 	    my_state = 0;
    
#ifdef BUILD_DEBUG
    char *			  tmp_string = 0;
#endif /* BUILD_DEBUG */
    
#ifdef BUILD_DEBUG    
    /* Init debug stuff */
    tmp_string = globus_module_getenv("GLOBUS_GSI_AUTHZ_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_authz_gaa_callout_debug_level = atoi(tmp_string);
        
        if(globus_i_gsi_authz_gaa_callout_debug_level < 0)
        {
            globus_i_gsi_authz_gaa_callout_debug_level = 0;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSI_AUTHZ_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_authz_gaa_callout_debug_fstream = fopen(tmp_string, "a");
    }

    if (globus_i_gsi_authz_gaa_callout_debug_fstream == 0)
    {
      /* if the env. var. isn't set (or the fopen failed), use stderr */
        globus_i_gsi_authz_gaa_callout_debug_fstream = stderr;
    }

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER;
#endif /* BUILD_DEBUG */

    authz_system_state = va_arg(ap, void *);

    if ((my_state = globus_libc_calloc(1, sizeof(struct globus_i_gsi_authz_handle_s))) == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
	goto end;

    }
    my_state->gaa_config_file_name = globus_module_getenv("GLOBUS_GSI_AUTHZ_GAA_CONFIG_FILE");
    if(my_state->gaa_config_file_name == GLOBUS_NULL)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(result,
				       GLOBUS_GSI_AUTHZ_CALLOUT_CONFIGURATION_ERROR,
				       "No GAA config file defined");
	goto end;
    }

 end:

    if (result == GLOBUS_SUCCESS)
    {
	*(authz_gaa_system_state_t *)authz_system_state = my_state;
    }
    else
    {
	if (my_state)
	{
	    free(my_state);
	}
    }

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT;
    return(result);
}

globus_result_t
globus_gsi_authz_gaa_system_destroy_callout(
    va_list                             ap)
{
    void * authz_system_state;
    
    globus_result_t                 result = GLOBUS_SUCCESS;
    static char *                   _function_name_ =
	"globus_gsi_authz_gaa_system_destroy_callout";
    
    
    authz_system_state = va_arg(ap, void *);
    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	"in %s, system state is %x\n", _function_name_,
	 (unsigned)authz_system_state);
    
    /* Do something here. */
    
#ifdef BUILD_DEBUG
    if (globus_i_gsi_authz_gaa_callout_debug_fstream &&
	(globus_i_gsi_authz_gaa_callout_debug_fstream != stderr))
    {
	fclose(globus_i_gsi_authz_gaa_callout_debug_fstream);
	globus_i_gsi_authz_gaa_callout_debug_fstream = stderr;
    }
#endif /* BUILD_DEBUG */
	
    return result;

}


globus_result_t
globus_gsi_authz_gaa_handle_init_callout(
    va_list                             ap)
{
    char *				service_name;
    gss_ctx_id_t 			context;
    globus_gsi_authz_cb_t 		callback;
    void * 				callback_arg;
    void *	 			authz_system_state;
    globus_gsi_authz_handle_t *		handle;
    gaa_status 				status;
    gaa_ptr				gaa = 0;
    gaa_sc_ptr				sc = 0;
    gss_buffer_set_t 			data_set = 0;
    
    globus_result_t                 	result = GLOBUS_SUCCESS;
    static char *                   	_function_name_ =
	"globus_gsi_authz_gaa_handle_init_callout";
    authz_gaa_system_state_t		gaa_state;
    gaa_cred_ptr			cred = 0;
    OM_uint32				minor_status;
    void *				getpolicy_param;
    char *				assertion;
    int					i;

    handle = va_arg(ap, globus_gsi_authz_handle_t *);
    service_name = va_arg(ap, char *);
    context = va_arg(ap, gss_ctx_id_t);
    callback = va_arg(ap,  globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);
    gaa_state = (authz_gaa_system_state_t)authz_system_state;


    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF5(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	"in %s\n\tservice name is %s\n\tcontext is %x\n\tsystem state is %x\n",
	_function_name_,
	service_name,
	(unsigned)context,
	(unsigned)authz_system_state);

    globus_assert(handle);
    if ((*handle = globus_libc_calloc(1, sizeof(struct globus_i_gsi_authz_handle_s))) == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
	goto end;

    }

    if ((gss_inquire_sec_context_by_oid(&minor_status,
					context,
					(gss_OID) saml_extension,
					&data_set)) != GSS_S_COMPLETE)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(result,
				       GLOBUS_GSI_AUTHZ_CALLOUT_CREDENTIAL_ERROR,
				       "error checking for authz extension");	
	goto end;
    }

    if (data_set->count == 0)
    {
	(*handle)->no_cred_extension = 1;
	goto end;
    }

    for (i = 0; i < data_set->count; i++)
    {
	if (assertion = data_set->elements[i].value)
	    break;
    }

    if (! assertion)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(result,
				       GLOBUS_GSI_AUTHZ_CALLOUT_CREDENTIAL_ERROR,
				       "authz extension found, but no assertion");
	goto end;
    }

    if ((status = gaa_initialize(&gaa,
	 (void *)gaa_state->gaa_config_file_name)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result, "gaa_initialize", status);
	goto end;
    }

    if ((status = gaa_x_get_getpolicy_param(gaa, &getpolicy_param)) != GAA_S_SUCCESS) {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(result,
				       GLOBUS_GSI_AUTHZ_CALLOUT_CONFIGURATION_ERROR,
				       "No GAA getpolicy parameter configured");
	goto end;
    }

    if (getpolicy_param)
	*((char **)getpolicy_param) = assertion;

    if ((status = gaa_new_sc(&sc)) != GAA_S_SUCCESS) {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result, "gaa_new_sc", status);
	goto end;
    }
    if ((status = gaa_new_cred(gaa, sc, &cred, "gss", context,
			       GAA_IDENTITY, 1, 0)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result, "gaa_new_cred", status);
	goto end;
    }
    if ((status = gaa_add_cred(gaa, sc, cred)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result, "gaa_add_cred", status);
	goto end;
    }

    if ((status = gaa_pull_creds(gaa,
				 sc,
				 GAA_ANY,
				 0)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result, "gaa_pull_creds", status);
	goto end;
    }

    (*handle)->gaa = gaa;
    (*handle)->sc = sc;
	
 end:
    if (result != GLOBUS_SUCCESS)
    {
	if (*handle)
	{
	    globus_assert((*handle)->gaa == 0);
	    globus_assert((*handle)->sc == 0);
	}
	if (gaa)
	    gaa_free_gaa(gaa);
	if (sc)
	    gaa_free_sc(sc);
    }
    callback(callback_arg, callback_arg, result);
    return result;
}


globus_result_t
globus_gsi_authz_gaa_authorize_async_callout(
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
    "globus_gsi_authz_gaa_authorize_async_callout";

  
  handle = va_arg(ap, globus_gsi_authz_handle_t);
  action = va_arg(ap, char *);
  object = va_arg(ap, char *);
  callback = va_arg(ap,  globus_gsi_authz_cb_t);
  callback_arg = va_arg(ap, void *);
  authz_system_state = va_arg(ap, void *);

  /* ???????????? */
  /* Am I supposed to call GAA-API as a callback with callback_arg???? */
  /* Or, can I just do something like below? */
  GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF5(
      GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
      "in %s, action is %s, object is %s, system state is %x\n",
      _function_name_,
      action,
      object,
      (unsigned)authz_system_state);

  callback(callback_arg, handle, result);

  return result;
}


int
globus_gsi_authz_gaa_cancel_callout(
    va_list                             ap)
{
  void * authz_system_state;

  int                             result = (int) GLOBUS_SUCCESS;
  static char *                   _function_name_ =
    "globus_gsi_authz_gaa_cancel_callout";

  authz_system_state = va_arg(ap, void *);

  GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(
      GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
      "in %s, system state is %x\n",
      _function_name_,
      (unsigned)authz_system_state);

  /* Do something here. */

  return result;
}


int
globus_gsi_authz_gaa_handle_destroy_callout(
    va_list                             ap)
{
  globus_gsi_authz_handle_t * handle;
  void * authz_system_state;

  int                             result = (int) GLOBUS_SUCCESS;
  static char *                   _function_name_ =
    "globus_gsi_authz_gaa_handle_destroy_callout";

  authz_system_state = va_arg(ap, void *);

  GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(
      GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
      "in %s, system state is %x\n",
      _function_name_,
      (unsigned)authz_system_state);

  if (handle != NULL)
  {
    free(handle);
  }
  
  return result;
}

