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

#include "gaa.h"
#include "gaa_simple.h"
#include "gaa_util.h"

#include "saml.h"
#define WILDCARD_MATCH_NAME "FTPDirectoryTree|"
#define TIME_NS "utctime"


#ifndef COMPILE_NAME_TEST
static int
gaa_simple_l_name_matches(char *policyname, char *objectname, char *ebuf, int ebuflen);
#endif /* COMPILE_NAME_TEST */

static gaa_status
gaa_simple_l_add_ads_rights (gaa_ptr		gaa,
			     gaa_policy *	policy,
			     adsPtr		ads,
			     xmlChar *		NotBefore,
			     xmlChar *		NotOnOrAfter,
			     int *		found_rights,
			     char *		ebuf,
			     int		ebuflen);


/**
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
  char        *saml_assertion = 0;
  assertionPtr Assertion = 0;
  adsPtr ads = 0;
  int rights_added = 0;
  int found_rights = 0;
  
  if (gaa == 0 || policy == 0 || object == 0 || params == 0)  {
    gaa_set_callback_err("gaa_simple_read_saml: called with null gaa, policy, or samldir pointer");
    return(GAA_S_INVALID_ARG);
  }

  if ((saml_assertion = *(char **)params) == 0)  {
    gaa_set_callback_err("gaa_simple_read_saml: called with null saml string");
    return(GAA_S_INVALID_ARG);
  }

  Assertion = parseSAMLassertion(saml_assertion, 1);

  if (!Assertion) {
      gaa_set_callback_err("gaa_simple_read_saml: Error parsing SAML assertion");
      return(GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE, 0));
  }

  if ((status = gaa_new_policy(policy)) != GAA_S_SUCCESS)
  {
      goto end;
  }

  for (ads = Assertion->ads; ads != NULL; ads = ads->next)
  {
      if (ads->resource &&
	  gaa_simple_l_name_matches(ads->resource,
				    object,
				    ebuf,
				    sizeof(ebuf)))
      {
	  if ((status = gaa_simple_l_add_ads_rights(gaa,
						     *policy,
						     ads,
						     Assertion->NotBefore,
						     Assertion->NotOnOrAfter,
						     &found_rights,
						     ebuf,
						     sizeof(ebuf))) == GAA_S_SUCCESS)
	  {
	      if (found_rights)
	      {
		  rights_added = 1;
	      }
	  }
      }
  }

  if ((rights_added == 0) && (status == GAA_S_SUCCESS))
  {
      snprintf(ebuf, sizeof(ebuf),
	       "gaa_simple_read_saml: No matching object (%s) found in the SAML assertion: %s\n", object, gaa_x_majstat_str(status));
      gaa_set_callback_err(ebuf);
      status = GAA_S_NO_MATCHING_ENTRIES;
  }
  
 end:
  freeAssertion(Assertion);
  return(status);
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

#ifndef COMPILE_NAME_TEST
static int
#endif /* COMPILE_NAME_TEST */
gaa_simple_l_name_matches(char *	policyname,
			  char *	objectname,
			  char *	ebuf,
			  int 		ebuflen)
{
    int prlen;
    char *policybuf = 0;
    int matches = 0;
    
    /*
     * We know how to parse only policy resource names that start with
     * WILDCARD_MATCH_NAME.  Verify that it does.
     */
    if (strncmp(policyname, WILDCARD_MATCH_NAME,
		sizeof(WILDCARD_MATCH_NAME)-1))
    {
	snprintf(ebuf, ebuflen,
		 "ignoring resource in policy assertion -- name does not begin with '%s'",
		 WILDCARD_MATCH_NAME);
	gaa_set_callback_err(ebuf);
	goto end;
    }
    
    /*
     * For comparison purposes, use only the part of policyname name that
     * comes after WILDCARD_MATCH_NAME.
     */
    policybuf = strdup(policyname + sizeof(WILDCARD_MATCH_NAME) - 1);
      
    if (policybuf == 0)
    {
	gaa_set_callback_err("Malloc failed");
	goto end;
    }

    if (*policybuf == '\0')
    {
	snprintf(ebuf, ebuflen,
		 "ignoring null %s resource in policy assertion",
		 WILDCARD_MATCH_NAME);
	gaa_set_callback_err(ebuf);
	goto end;
    }
      
    /* Now check that the resource and object names match */
    prlen = strlen(policybuf);
    /* The name "*" matches everything */
    if ((prlen == 1) && policybuf[0] == '*')
    {
	matches = 1;
	goto end;
    }
    
    /*
     * Names like "/foo/bar/ *" match anything that starts with /foo/bar
     * or /foo/bar/blech/, but not /fooo.
     */
    if ((prlen > 1) &&
	(policybuf[prlen-2] == '/') &&
	(policybuf[prlen-1] == '*'))
    {
	if (strncmp(objectname, policybuf, prlen-1) == 0)
	{
	    matches = 1;
	    goto end;
	}
	
	/*
	 * Names like "/foo/bar/ *" also match /foo/bar/ and /foo/bar
	 */
	policybuf[prlen-1] = '\0';
	if (strcmp(policybuf, objectname) == 0)
	{
	    matches = 1;
	    goto end;
	}
	
	policybuf[prlen-2] = '\0';
	if (strcmp(policybuf, objectname) == 0)
	{
	    matches = 1;
	    goto end;
	}
    } else {
	if (strcmp(policybuf, objectname) == 0)
	{
	    matches = 1;
	    goto end;
	}
    }

 end:
    if (policybuf)
	free(policybuf);

    return(matches);
}

/**
 *
 * Add all policy rights from this ads.
 *
 * @param gaa
 *        input gaa pointer
 * @param policy
 *	  input/output - policy to add rights to.
 * @param ads
 * 	  input - ads to read rights from
 * @param NotBefore
 *        input - NotBefore attribute
 * @param NotOnOrAfter
 *        input - NotOnOrAfter attribute
 * @param ebuf
 *	  output - buffer to hold error string
 * @param ebuflen
 *        input - length of ebuf
 * @param found_rights
 *	  output - 1 if any rights were added, 0 otherwise
 */
static gaa_status
gaa_simple_l_add_ads_rights (gaa_ptr 		gaa,
			     gaa_policy *	policy,
			     adsPtr		ads,
			     xmlChar *		NotBefore,
			     xmlChar *		NotOnOrAfter,
			     int *		found_rights,
			     char *		ebuf,
			     int		ebuflen)
{
    gaa_policy_right *right = 0;
    gaa_condition    *cond = 0;
    char *auth_p;
    char *val_p;
    gaa_right_type right_type;
    int pri = 1;
    int num = 0;
    struct action *action;
    gaa_status status = GAA_S_SUCCESS;
    *found_rights = 0;

    if (strcasecmp(ads->decision, "permit") == 0)
    {
	right_type = gaa_pos_access_right;
    }
    else  if (strcasecmp(ads->decision, "deny") == 0)
    {
	right_type = gaa_neg_access_right;
    }
    else {
	gaa_set_callback_err("Unrecognized decision value in SAML assertion");
	return(GAA_STATUS(GAA_S_INVALID_POLICY_RIGHT_HNDL, 0));
    }

    for (action = ads->action, num = 0; action; action = action->next, num++)
    {
	auth_p = (char *)action->ActionNS;
	val_p = (char *)action->Action;
	
	if (auth_p == 0 || val_p == 0) /* null action */
	{
	    return(GAA_S_POLICY_PARSING_FAILURE);
	}
	
	/*
	 * TODO -- figure out whether all this val_p skipping over spaces
	 * is necessary, and whether it can't be done when the saml assertion
	 * is parsed instead of here.  For now, I'm putting these where Dongho
	 * had them.
	 */
	while (isspace(*val_p))
	{
	    val_p++;
	}

	/* Create right */
	if ((status = gaa_new_policy_right(gaa,
					   &right,
					   right_type,
					   auth_p,
					   val_p)) != GAA_S_SUCCESS)
	{
	    goto end;
	}
  
	/* Add Conditions */

	if (ads->NameIDformat)
	{
	    val_p = ads->NameID;
	    while (isspace(*val_p))
	    {
		val_p++;
	    }

	    if ((status = gaa_new_condition(&cond,
					    "identity",
					    ads->NameIDformat,
					    val_p)) != GAA_S_SUCCESS)
	    {
		goto end;
	    }

	    if ((status = gaa_add_condition(right, cond)) != GAA_S_SUCCESS)
	    {
		gaa_free_condition(cond);
		goto end;
	    }
	}

	if (NotBefore)
	{
	    if ((status = gaa_new_condition(&cond, "NotBefore",
					    TIME_NS,
					    NotBefore)) != GAA_S_SUCCESS)
	    {
		goto end;
	    }
        
	    if ((status = gaa_add_condition(right, cond)) != GAA_S_SUCCESS)
	    {
		gaa_free_condition(cond);
		goto end;
	    }
	}

	if (NotOnOrAfter)
	{
	    if ((status = gaa_new_condition(&cond, "NotOnOrAfter",
					    TIME_NS,
					    NotOnOrAfter)) != GAA_S_SUCCESS)
	    {
		goto end;
	    }
	    
	    if ((status = gaa_add_condition(right, cond)) != GAA_S_SUCCESS)
	    {
		gaa_free_condition(cond);
		goto end;
	    }
	}
      
	if (right) {
	    if ((status = gaa_add_policy_entry(policy,
					       right,
					       pri,
					       num++)) == GAA_S_SUCCESS)
	    {
		*found_rights = 1;
	    }
	    else
	    {
		snprintf(ebuf, sizeof(ebuf),
			 "gaa_simple_read_eacl: failed to add right in saml assertion: %s\n",
			 gaa_x_majstat_str(status));
		gaa_set_callback_err(ebuf);
		goto end;
	    }
	}
    }

 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_policy_right(right);
    }
    return(status);
}
    
gaa_status
gaa_simple_get_saml_signer_identity(gaa_ptr		*gaa,
				    char **		identity_ptr,
				    void *		params)
{
    char *			saml_assertion = 0;
    void *			policy_params = 0;
    gaa_status			status = GAA_S_SUCCESS;
    char			errbuf[1024];
    xmlDocPtr			doc;
    
    if (gaa == 0 || identity_ptr == 0 || params == 0)  {
	gaa_set_callback_err("gaa_simple_get_saml_signer_identity: called with null gaa or identity pointer or params");
	return(GAA_S_INVALID_ARG);
    }

    *identity_ptr = 0;

    xmlInitParser();
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    if ((saml_assertion = *(char **)params) == 0)  {
	goto end;
    }

    if (*saml_assertion == '\0') {
	goto end;
    }

    doc = xmlParseMemory(saml_assertion, strlen(saml_assertion));

    status = gaa_simple_i_find_signer(doc,
				      identity_ptr,
				      errbuf,
				      sizeof(errbuf));

    if (status != GAA_S_SUCCESS)
    {
	gaa_set_callback_err(errbuf);
    }

 end:

    if (doc)
	xmlFreeDoc(doc);
    
    /* Clean up everything else before quitting. */
    xmlCleanupParser();
 
    return(status);

}
