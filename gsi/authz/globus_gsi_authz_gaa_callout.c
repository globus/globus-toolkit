/**
 * @file globus_gsi_authz_gaa_callout.c
 * Globus Authorization API -- GAA-API callout
 *
 *
 */

#include "globus_i_gsi_authz.h"
#include "globus_gsi_authz_gaa_callout.h"

int      globus_i_gsi_authz_debug_level   = 0;
FILE *   globus_i_gsi_authz_debug_fstream = NULL;


globus_result_t
globus_gsi_authz_gaa_callout(const void *object, *action)
{
  globus_callout_handle_t         handle;
  
  char *cfname;
  globus_result_t                     result = GLOBUS_SUCCESS;
  char *                          tmp_string;
  static char *                   _function_name_ =
    "globus_gsi_authz_gaa_callout";

  gaa_status status;
  gaa_sc_ptr sc = 0;
  gaa_ptr gaa = 0;
  gaa_policy *policy = 0;
  gaa_list_ptr rlist;
  gaa_policy_right *pright;
  gaa_list_entry_ptr ent;
  gaa_answer_ptr answer;

  char *auth;
  char *val;
  gaa_list_ptr list = 0;
  gaa_request_right *right;



  GLOBUS_I_GSI_AUTHZ_DEBUG_ENTER;

  /*** ??????
   * dunno what to do with callback and callback_arg ?
   * ===> call callback at the end... with handle and callback_arg
   *      return value will be the "result"
   ****/
  result = globus_callback_register_oneshot(
    handle,
    GLOBUS_NULL,
    callback,
    callback_arg);
  if(result != GLOBUS_SUCCESS)
  {
    goto exit;
  }
  


  cfname = globus_module_getenv("GLOBUS_GSI_AUTHZ_GAA_CONFIG_FILE");
  if(cfname == GLOBUS_NULL)
  {
    GLOBUS_GSI_AUTHZ_NO_CONFIG_FILE(result);
    goto exit;
  }

  /** Below needs to be cleaned up **/

  if ((status = gaa_initialize(&gaa, (void *)cfname)) != GAA_S_SUCCESS) {
    GLOBUS_GSI_AUTHZ_GAA_FAIL("gaa_initialize() failed:",
                              gaa_x_majstat_str(status), gaa_get_err());
    result = (int) GLOBUS_FAILURE;
    goto exit;
  }
  (*handle)->gaa = gaa;

  if ((status = gaa_new_sc(&sc)) != GAA_S_SUCCESS) {
    GLOBUS_GSI_AUTHZ_GAA_FAIL("gaa_new_sc failed",
                              gaa_x_majstat_str(status), gaa_get_err());
    result = (int) GLOBUS_FAILURE;
    goto exit;
  }
  (*handle)->sc = sc;

  (*handle)->status = status;
  
  /********
	if ((status = gaa_new_cred(gaa, sc, &c, "assertion", authctxt->user, GAA_IDENTITY, 1, &estat)) != GAA_S_SUCCESS)
    debug("GAA failed on gaa_new_cred");
  
	if ((status = gaa_add_cred(gaa, sc, c)) != GAA_S_SUCCESS)
    debug("GAA failed on gaa_add_cred");
  ************/

  gaa = handle->gaa;
  status = handle->status;

  gaa_clear_policy(policy);

  if ((status = gaa_get_object_policy_info(object, gaa, &policy)) != GAA_S_SUCCESS)
    GLOBUS_GSI_AUTHZ_GAA_FAIL("gaa_get_object_policy_info failed",
             gaacore_majstat_str(status), gaa_get_err());

/*   debug("gaa_clear_policy() okay" ); */

	if (list == 0)
    list = gaa_new_req_rightlist();
	if ((status = gaa_new_request_right(gaa, &right, auth, val)) != GAA_S_SUCCESS) {
    GLOBUS_GSI_AUTHZ_GAA_FAIL("gaa_new_request_right failed",
             gaacore_majstat_str(status), gaa_get_err());
    result = (int) GLOBUS_FAILURE;
    goto exit;
	}
	if ((status = gaa_add_request_right(list, right)) != GAA_S_SUCCESS) {
    GLOBUS_GSI_AUTHZ_GAA_FAIL("gaa_add_request_right failed",
             gaacore_majstat_str(status), gaa_get_err());
    result = (int) GLOBUS_FAILURE;
    goto exit;
	}

  if ((status = gaa_new_answer(&answer)) != GAA_S_SUCCESS) {
    GLOBUS_GSI_AUTHZ_GAA_FAIL("gaa_new_answer failed",
             gaacore_majstat_str(status), gaa_get_err());
    result = (int) GLOBUS_FAILURE;
    goto exit;
  }

  status = gaa_check_authorization(gaa, sc, policy, list, answer);
  switch(status) {
    case GAA_C_YES:
    case GAA_C_NO:
    case GAA_C_MAYBE:
      handle->status = status; /* redundant */

/*       GLOBUS_I_GSI_AUTHZ_DEBUG_FPRINTF(9, gaacore_majstat_str(status)); */
      /*
      gaadebug_answer_string(gaa, str, outbsize, answer);
      */
      break;
    default:
      GLOBUS_GSI_AUTHZ_GAA_FAIL("gaa_check_authorization failed",
                                gaacore_majstat_str(status), gaa_get_err());
      result = (int) GLOBUS_FAILURE;
      goto exit;
  }
  

  GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT;  

exit:
  
  return result;
}


