#include "gaa.h"
#include "gaa_simple.h"
#include "gaa_util.h"

#include "saml.h"

/** gaa_simple_read_saml()
 *
 * @ingroup gaa_simple
 *
 * Create a GAA policy from a signed saml assertion.  This function
 * is meant to be used as a GAA getpolicy callback function.
 *
 * @param gaa
 *        input gaa pointer
 * @param policy
 *        output policy pointer
 * @param object
 *        name of the object whose policies are being queried.
 * @param params
 *        input (char **) pointer to a signed saml assertion
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INVALID_ARG
 *         one of gaa, policy, object, params, or *params was 0, or
 *         params/object is not a valid filename.
 * @retval GAA_S_POLICY_PARSING_FAILURE
 *         syntax error in policy file.
 */
gaa_status
gaa_simple_read_saml(gaa_ptr		      gaa,
                     gaa_policy     **policy,
                     gaa_string_data	object,
                     void            *params)
{
  gaa_status	status = GAA_S_SUCCESS;
  char				ebuf[2048];
  char				*eptr = 0;
  char 				type[50];
  char        auth[128], *auth_p = 0;
  char        val[256],  *val_p = 0;
/*  static int	i = 0; */
  gaa_policy_right *right = 0;
  gaa_condition    *cond = 0;
  int					pri = -1;
  int					num = -1;
  int         valid = 0;
  char        *saml_assertion = 0;
  int f = 0;
  assertionPtr Assertion = 0;
  adsPtr cur_ads = 0;
  actionPtr cur_action = 0;
  
  if (gaa == 0 || policy == 0 || object == 0 || params == 0)  {
    gaa_set_callback_err("gaa_simple_read_saml: called with null gaa, policy, or samldir pointer");
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  }

  if ((saml_assertion = *(char **)params) == 0)  {
    gaa_set_callback_err("gaa_simple_read_saml: called with null saml string");
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  }

  Assertion = parseSAMLassertion(saml_assertion, 1);

  if (!Assertion) {
      if ((eptr = malloc(strlen(saml_assertion) + 60)) == 0) {
	  eptr = "gaa_simple_read_saml: Error parsing SAML assertion";
      } else {
	  sprintf(eptr, "gaa_simple_read_saml: Error parsing SAML assertion %s\n", saml_assertion);
      }
      gaa_set_callback_err(eptr);
      return(GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE, 0));
  }

  if ((status = gaa_new_policy(policy)) != GAA_S_SUCCESS)
    return(status);

  cur_ads = Assertion->ads;
  
  while (cur_ads != NULL) {  // Traverse each ADS
    
    cur_action = cur_ads->action;

    /* If the resource name on SAML does not match the object,
       skip the whole thing */
    if (strcasecmp(cur_ads->resource, object))
      goto next;
    else
      valid = 1;
    
    ///--------------
    
    while (cur_action != NULL) {  // Traverse each Action in an ADS
      if (right) {
        if ((status = gaa_add_policy_entry((*policy), right, pri, num))
            != GAA_S_SUCCESS) {
	    snprintf(ebuf, sizeof(ebuf),
		     "gaa_simple_read_eacl: failed to add right in saml assertion: %s\n",
		     gaa_x_majstat_str(status));
	    gaa_set_callback_err(ebuf);
	    return (status);
        }
        right = 0;
      }
      auth_p = (char *)cur_action->ActionNS;
      val_p = (char *)cur_action->Action;
      
      while (isspace(*val_p))
        val_p++;
      
      if (strcasecmp(cur_ads->decision, "permit") == 0)	{
        gaa_new_policy_right(gaa, &right, gaa_pos_access_right, auth_p, val_p);
      }
      else if (strcasecmp(cur_ads->decision, "deny") == 0){ 
        gaa_new_policy_right(gaa, &right, gaa_neg_access_right, auth_p, val_p);
      }
      else { // Indeterminate or something else
	  if ((eptr = malloc(strlen(cur_ads->decision) + 60)) == 0) {
	      eptr = "Unrecognized decision value in SAML assertion";
	  } else {
	      sprintf(eptr, "gaa_simple_read_saml: Unrecognized decision value in SAML assertion: \"%s\"\n", cur_ads->decision);
	  }
	  gaa_set_callback_err(eptr);
	  return(GAA_STATUS(GAA_S_INVALID_POLICY_RIGHT_HNDL, 0));
      }
      num++;
  
      /* Conditions */

      if (cur_ads->NameIDformat) {
        strcpy(type, "subject");  // not sure what to put here
        
        strcpy (auth, (char *)cur_ads->NameIDformat);  // not sure what to put here
        strcpy (val, (char *)cur_ads->NameID);
        val_p = val;
        while (isspace(*val_p))
          val_p++;
        
        if ((status = gaa_new_condition(&cond, type, auth, val_p)) != GAA_S_SUCCESS)
          return status;
        
        if ((status = gaa_add_condition(right, cond)) != GAA_S_SUCCESS)
          return status;
      }
      
      if (Assertion->NotBefore) {
        strcpy(type, "NotBefore");  // not sure what to put here
        
        strcpy (auth, (char *)cur_action->ActionNS); // not sure what to put here
        strcpy (val, (char *)Assertion->NotBefore);
        
        if ((status = gaa_new_condition(&cond, type, auth, val)) != GAA_S_SUCCESS)
          return status;
        
        if ((status = gaa_add_condition(right, cond)) != GAA_S_SUCCESS)
          return status;
      }
      
      if (Assertion->NotOnOrAfter) {
        strcpy(type, "NotOnOrAfter");  // not sure what to put here
        
        strcpy (auth, (char *)cur_action->ActionNS); // not sure what to put here
        strcpy (val, (char *)Assertion->NotOnOrAfter);
        
        if ((status = gaa_new_condition(&cond, type, auth, val)) != GAA_S_SUCCESS)
          return status;
        
        if ((status = gaa_add_condition(right, cond)) != GAA_S_SUCCESS)
          return status;
      }
      
      cur_action = cur_action->next;
    } // End of all Action in an ADS
    next:
    cur_ads = cur_ads->next;
  } // End of all ADS in an Assertion

  if (right)
    if ((status = gaa_add_policy_entry((*policy), right, pri,
                                       num)) != GAA_S_SUCCESS)    {
	    snprintf(ebuf, sizeof(ebuf),
               "gaa_simple_read_saml: failed to add right: %s\n",
               gaa_x_majstat_str(status));
	    gaa_set_callback_err(ebuf);
	    return (status);
    }

  /** If there was no resource name that matches the object name,
      something must be wrong.  **/
  if (valid == 0) {
      snprintf(ebuf, sizeof(ebuf),
	       "gaa_simple_read_saml: No matching object (%s) found in the SAML assertion: %s\n", object, gaa_x_majstat_str(status));
      gaa_set_callback_err(ebuf);
      return(GAA_STATUS(GAA_S_NO_MATCHING_ENTRIES, 0));
  }
  
  freeAssertion(Assertion);
  
  return status;
}


void
freeAssertion(assertionPtr Assertion)
{
  adsPtr f_ads=0, r_ads= 0;
  actionPtr f_action= 0, r_action=0;

  if (Assertion) {
    f_ads = Assertion->ads;
    while (f_ads) {
      f_action = f_ads->action;
      while (f_action) {
        r_action = f_action;
        f_action = f_action->next;
        free(r_action);
      }
      r_ads = f_ads;
      f_ads = f_ads->next;
      free(r_ads);
    }
    free (Assertion);
  }
}

