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
#include "gaa_private.h"
#include <string.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
static char *rcsid = "$Header$";

/** @defgroup gaa_policy_static Static-scope functions in gaa_policy.c
 */
static gaa_status
gaa_l_reset_answer(gaa_answer *answer);

static gaa_status
gaa_l_check_one_right(gaa_ptr gaa, gaaint_sc *sc, gaa_policy *policy,
		      gaa_request_right *right, gaa_answer *ans, int *ynm);

static
gaa_l_arbitrate_status(int aggregate, int current);

static void
gaa_l_clear_answer(gaa_answer *answer);

static gaa_status
gaa_l_init_answer(gaa_answer *answer);

static gaa_status
gaa_l_check_simple(gaa_ptr gaa, gaaint_sc *sc, gaa_policy_entry *p_ent,
		   gaa_list_ptr options, gaa_policy_right **pright,
		   int *condstat, gaa_time_period *vtp, int idonly);

static void
gaa_l_set_times(gaa_time_period *to, gaa_time_period *from);

static void
gaa_l_intersect_times(gaa_time_period *to, gaa_time_period *from);

static void
gaa_l_free_time_period(gaa_time_period *time_period);

static gaa_status
gaa_l_init_policy(gaa_policy *policy, int freerights);

static void
gaa_l_clear_answer(gaa_answer *answer);

static gaa_status
gaa_l_clone_policy_right(gaa_ptr gaa, gaa_policy_right **new,
			 gaa_policy_right *old);

static gaa_status
gaa_l_clone_condition(gaa_condition **new, gaa_condition *old);

static void
gaa_l_free_policy_entry_noright(gaa_policy_entry *ent);

static void
gaa_l_free_gaaint_policy_right(gaaint_policy_right *i);

static gaa_status
gaa_l_new_gaaint_policy_right(gaaint_policy_right **i, gaa_freefunc freefunc);

static void
gaa_l_free_gaaint_policy(gaaint_policy *i);

static gaa_status
gaa_l_match_authority(gaa_request_right *rright, gaa_policy_right *pright,
		      int *match);

static gaaint_cond_eval_entry *
gaa_l_find_cond_eval_entry(gaa_ptr gaa, gaa_condition *cond);

static gaa_status
gaa_l_new_gaaint_policy(gaaint_policy **i);

static void
gaa_l_free_gaaint_policy(gaaint_policy *i);

static gaa_status
gaa_l_check_condition(gaa_ptr gaa, gaa_sc_ptr sc, gaa_condition *cond,
		      gaa_time_period *vtp, gaa_list_ptr options,
		      int *ynm, gaaint_cond_eval_entry *ce);

static gaa_status
gaa_l_new_time_period(gaa_time_period **time_period, time_t start_time,
		      time_t end_time);

static gaa_status
gaa_l_new_policy_entry(gaa_policy_entry **ent, gaa_policy_right *right,
		       int priority, int num);
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *  
 *  Check whether the requested rights are authorized under the specified
 *  policy.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param sc
 *         input security context
 *  @param policy
 *         input policy
 *  @param req_rights
 *	   input list of requested rights
 *  @param answer
 *         output detailed answer -- lists all matching policy rights
 *         and associated conditions, with flags set to indicate whether
 *         each condition was evaluated and/or met.  If the result is
 *         GAA_C_YES, then the answer includes the time period for which
 *         the result is valid (if the start or end time is 0, that time
 *         is indefinite).  Before being passed to this function,
 *         the answer structure should be created with gaa_new_answer().
 *
 *  @retval GAA_C_YES
 *          Access is granted to all requested rights.
 *  @retval GAA_C_NO
 *          Access is denied for at least one requested right.
 *  @retval GAA_C_MAYBE
 *          Access is not explicitly denied for any requested right, but
 *          there is at least one requested right that GAA cannot decide.
 *  @retval GAA_S_INVALID_ARG
 *          sc, policy, answer, or gaa is null
 *  @retval GAA_S_NO_MATCHING_ENTRIES
 *          The list of requested rights is empty.
 * 
 *  This function makes use of several callback routines -- the
 *  GAA matchrights callback to determine the subset of the policy
 *  that applies to the requested rights, and cond_eval callbacks
 *  to evaluate specific conditions.
 *  The matchrights callback is also likely to use the valmatch
 *  function from the appropriate authinfo callback(s) to determine
 *  whether a specific request right matches a specific policy right.
 */
gaa_status
gaa_check_authorization(gaa_ptr		gaa,
			gaa_sc_ptr	sc,
			gaa_policy_ptr	policy,
			gaa_list_ptr	req_rights,
			gaa_answer_ptr	answer)
{
    gaaint_list_entry *			ent;
    gaa_request_right *			right;
    int					first = 1;
    gaa_status				status;
    int					current_ynm; /* yes/no/maybe */
    int					aggregate_ynm;

    if (sc == 0 || policy == 0 || answer == 0 || gaa == 0)
    {
	gaacore_set_err("gaa_check_authorization: called with null gaa, sc, policy, or answer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((status = gaa_l_reset_answer(answer)) != GAA_S_SUCCESS)
	return(status);
    for (ent = gaa_list_first(req_rights); ent; ent = gaa_list_next(ent))
	if (right = (gaa_request_right *)gaa_list_entry_value(ent))
	{
	    if ((status =
		 gaa_l_check_one_right(gaa, sc, policy, right, answer,
				       &current_ynm)) != GAA_S_SUCCESS)
		break;
	    if (first)
		aggregate_ynm = current_ynm;
	    else
		aggregate_ynm =
		    gaa_l_arbitrate_status(aggregate_ynm, current_ynm);
	    first = 0;
	}
    if (first)
    {
	if (status == GAA_S_SUCCESS)
	{
	    gaacore_set_err("gaa_check_authorization: no rights were checked");
	    status = GAA_STATUS(GAA_S_NO_MATCHING_ENTRIES, 0);
	}
    }
    if (status == GAA_S_SUCCESS)
	return(aggregate_ynm);
    else
	return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Return the subset of the input policy that applies to the individual
 *  identified with the specified security context.  This is the union
 *  of the set of rights that do not have any identity conditions with
 *  the set of rights whose identity conditions all match the individual.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param sc
 *         input security context
 *  @param policy
 *         input policy
 *  @param out_rights
 *         output list of policy rights
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa, sc, out_rights, or policy is null
 *
 *  @note
 *  The list returned in out_rights should be freed with gaa_list_free().
 */
gaa_status
gaa_inquire_policy_info(gaa_ptr		gaa,
			gaa_sc_ptr	sc,
			gaa_policy_ptr	policy,
			gaa_list_ptr *	out_rights)
{
    gaaint_list_entry *			ent;
    gaa_policy_entry *			pent;
    gaa_policy_right *			pright = 0;
    gaa_condition *			cond;
    int					cflags;
    gaa_status				status = GAA_S_SUCCESS;
    int					condstat;

    if (out_rights)
	*out_rights = 0;
    if (gaa == 0 || sc == 0 || out_rights == 0 || policy == 0)
    {
	gaacore_set_err("gaa_inquire_policy_info: null gaa, sc, policy, or out_rights");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    for (ent = gaa_list_first(policy->entries); ent; ent = gaa_list_next(ent))
    {
	if (pent = (gaa_policy_entry *)gaa_list_entry_value(ent))
	{
	    condstat = 0;
	    if ((status = gaa_l_check_simple(gaa, sc, pent, 0, &pright,
					     &condstat, 0,
					     1)) != GAA_S_SUCCESS)
		goto end;
	    if ((condstat & GAA_COND_FLG_MET) ||
		(! (condstat & GAA_COND_FLG_EVALUATED)))
	    {
		if (*out_rights == 0)
		    if ((*out_rights = gaa_i_new_silo((gaa_freefunc)gaa_free_policy_right)) == 0)
			goto end;
		if ((status = gaa_i_list_add_entry(*out_rights,
						     pright)) != GAA_S_SUCCESS)
		    goto end;
	    }
	}
    }
 end:
    if (status != GAA_S_SUCCESS)
    {
	if (pright)
	    gaa_free_policy_right(pright);
	gaa_list_free(*out_rights);
	*out_rights = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Determines whether a request right matches a policy right.  If the
 *  two rights do not have the same authority, they don't match.  If they
 *  do, then the valmatch callback appropriate to that authority is called
 *  to determine whether they match or not.  This utility function is
 *  meant to be used in GAA matchrights callback functions.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param rright
 *         input request right
 *  @param pright
 *         input policy right
 *  @param match
 *         output -- set to 1 if they match, 0 if they don't
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa, rright, pright, or match is null 
 *  @retval GAA_S_NO_AUTHINFO_CALLBACK
 *          No authinfo callback was installed for this authority, and there's
 *          no default authinfo callback.
 */
gaa_status
gaa_match_rights(gaa_ptr		gaa,
		 gaa_request_right *	rright,
		 gaa_policy_right *	pright,
		 int *			match)
{
    gaa_status				status;
    gaaint_authinfo *			ai;
    
    if (rright == 0 || pright == 0 || match == 0 || gaa == 0)
    {
	gaacore_set_err("gaa_match_rights: called with null gaa, rright, pright, or match");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((status = gaa_l_match_authority(rright, pright, match)) != GAA_S_SUCCESS)
	return(status);
    if (*match == 0)
	return(status);
    if ((ai = gaa_i_find_authinfo(gaa, pright)) == 0)
	return(GAA_STATUS(GAA_S_NO_AUTHINFO_CALLBACK, 0));    
    if (ai->match == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if(match)
        *match = ai->match(pright->authority, rright->value, pright->value,
		       ai->params);
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa
 *
 *  Check a single condition.  This utility function is meant to be used
 *  in cond_eval callbacks, when evaluating conditions recursively.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param sc
 *         input security context
 *  @param cond
 *         input condition to evaluate
 *  @param vtp
 *         output valid time period
 *  @param ynm
 *         output answer -- set to GAA_C_YES, GAA_C_NO, or GAA_C_MAYBE
 *  @param options
 *         optional input request options
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa, sc, cond, or vtp is null
 */
gaa_status
gaa_check_condition(gaa_ptr		gaa,
		    gaa_sc_ptr		sc,
		    gaa_condition *	cond,
		    gaa_time_period *	vtp,
		    int *		ynm,
		    gaa_list_ptr	options)
{
    gaaint_cond_eval_entry *		ce;
    gaa_status				status;

    if (! (gaa && sc && cond && vtp))
    {
	gaacore_set_err("gaa_check_condition: called with null gaa, sc, cond, or vtp");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    cond->status = 0;
    if (! ((ce = gaa_l_find_cond_eval_entry(gaa, cond)) && ce->cb))
    {
	if (ynm)
	    *ynm = GAA_C_MAYBE;
	return(GAA_S_SUCCESS);
    }
    return(gaa_l_check_condition(gaa, sc, cond, vtp, options, ynm, ce));
}

/**
 *
 *  @ingroup gaa
 *
 *  Create a new answer structure (suitable for use in a call to
 *  gaa_check_authorization()).
 *
 *  @param answer
 *         output answer structure to create
 *
 *  @retval GAA_S_SUCCES
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          answer is null
 *
 *  @note
 *  A structure created with this function should be freed with
 *  gaa_free_answer().
 */
gaa_status
gaa_new_answer(gaa_answer **answer)
{
    gaa_status status = GAA_S_SUCCESS;
    if (answer == 0)
    {
	gaacore_set_err("gaa_new_answer: called with null answer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*answer = (gaa_answer *)malloc(sizeof(gaa_answer))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    return(gaa_l_init_answer(*answer));
}

/**
 *
 *  @ingroup gaa
 *
 *  Free an answer structure.
 *
 *  @param answer
 *         input/output structure to free.
 */
void
gaa_free_answer(gaa_answer *answer)
{
    if (answer == 0)
	return;
    gaa_l_clear_answer(answer);
    free(answer);
}

/**
 *
 *  @ingroup gaa
 *
 *  Create and initialize a policy structure.  This utility routine is
 *  meant to be used by gaa getpolicy callback functions.
 *
 *  @param policy
 *         output policy to create
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          policy is null
 *
 *  @note
 *  A policy structure allocated by this function should be freed
 *  with gaa_free_policy().
 */
gaa_status
gaa_new_policy(gaa_policy **policy)
{
    gaa_status status = GAA_S_SUCCESS;
    if (policy == 0)
    {
	gaacore_set_err("gaa_new_policy: called with null policy handle");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if (((*policy) = (gaa_policy *)malloc(sizeof(gaa_policy))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    return(gaa_init_policy(*policy));
}

/**
 *
 *  @ingroup gaa
 *
 *  Initialize a policy structure.
 *
 *  @param policy
 *         input/output policy to initialize
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          policy is null
 */
gaa_status
gaa_init_policy(gaa_policy *policy)
{
    if (policy == 0)
    {
	gaacore_set_err("gaa_init_policy: called with null policy handle");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    return(gaa_l_init_policy(policy, 1));
}

/**
 *
 *  @ingroup gaa
 *
 *  Clear a policy structure (and free all its entries).
 *
 *  @param policy
 *         input/output policy to clear
 */
void
gaa_clear_policy(gaa_policy *policy)
{
    if (policy == 0)
	return;
    gaa_i_list_clear(policy->entries);
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a policy structure and all its entries.
 *
 *  @param policy
 *         input/output policy to free
 */
void
gaa_free_policy(gaa_policy *policy)
{
    if (policy)
    {
	gaa_list_free(policy->entries);
	gaa_l_free_gaaint_policy(policy->i);
	free(policy);
    }
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Create a new policy entry.  Called by gaa_add_policy_entry.
 *
 *  @param ent
 *         output entry to create
 *  @param right
 *         input policy right
 *  @param priority
 *         input entry priority
 *  @param num
 *         input priority number (for order within priority)
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          ent or right is null
 */
static
gaa_status
gaa_l_new_policy_entry(gaa_policy_entry **ent,
		       gaa_policy_right * right,
		       int		  priority,
		       int		  num)
{
    if (ent == 0 || right == 0)
    {
	gaacore_set_err("gaa_l_new_policy_entry: called with null entry or right");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*ent = (gaa_policy_entry *)malloc(sizeof(gaa_policy_entry))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*ent)->priority = priority;
    (*ent)->num = num;
    (*ent)->right = right;
    return(GAA_S_SUCCESS);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *
 *  Add a policy entry to a policy.
 *
 *  @param policy
 *         input/output policy
 *  @param right
 *         input right to add
 *  @param priority
 *         input entry priority
 *  @param num
 *         input entry number (for order within priority)
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          policy or right is null
 */
gaa_status
gaa_add_policy_entry(gaa_policy *	policy,
		     gaa_policy_right *	right,
		     int		priority,
		     int		num)
{
    gaa_status				status = GAA_S_SUCCESS;
    gaa_policy_entry *			ent = 0;

    if (policy == 0 || right == 0)
    {
	gaacore_set_err("gaa_add_policy_entry: called with null policy handle or right");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((status =
	 gaa_l_new_policy_entry(&ent, right, priority, num)) != GAA_S_SUCCESS)
	return(status);
    ent->right = right;
    ent->priority = priority;
    ent->num = num;
    return(gaa_i_list_add_entry(policy->entries, ent));
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a policy entry and its associated right.
 *
 *  @param ent
 *         input/output entry to free
 * 
 *  @note
 *  If a policy was created using gaa_new_policy() or initialized using
 *  gaa_init_policy(), then this function will be called by gaa_free_policy()
 *  when the policy is freed.
 */
void
gaa_free_policy_entry(gaa_policy_entry *ent)
{
    if (ent)
    {
	gaa_free_policy_right(ent->right);
	free(ent);
    }
}

/**
 *
 *  @ingroup gaa
 *
 *  Create a new policy right.  This utility function is meant to be used
 *  by gaa getpolicy callback functions.  This function uses the authinfo
 *  newval callback to translate the string representation of the value
 *  into the appropriate internal format.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param right
 *         output policy right to create
 *  @param type
 *         input right type (pos_access_right or neg_access_right)
 *  @param authority
 *         input right authority
 *  @param val
 *         input string representation of right value
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          right or authority is null
 *  @retval GAA_S_NO_AUTHINFO_CALLBACK
 *          no authinfo callback was installed for this authority, and
 *          there's no default authinfo callback.
 *  @retval GAA_S_NO_NEWVAL_CALLBACK
 *          an authinfo callback was found, but it does not include a
 *          newval callback.
 */
gaa_status
gaa_new_policy_right(gaa_ptr		gaa,
		     gaa_policy_right **right,
		     gaa_right_type	type,
		     gaa_string_data	authority,
		     gaa_string_data	val)
{
    gaa_status				status = GAA_S_SUCCESS;
    gaaint_authinfo *			ai;
    void *				pval;

    if (right == 0 || authority == 0)
    {
	gaacore_set_err("gaa_new_policy_right: called with null right or authority pointer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    if ((ai = gaa_i_auth2authinfo(gaa, authority)) == 0)
    {
	gaacore_set_err("gaa_new_policy_right: no callback for this authority");
	status = (GAA_STATUS(GAA_S_NO_AUTHINFO_CALLBACK, 0));
	goto end;
    }
    if (ai->pvinfo == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if (ai->pvinfo->newval == 0)
    {
	gaacore_set_err("gaa_new_policy_right: no newval callback for this authority");
	status = GAA_STATUS(GAA_S_NO_NEWVAL_CALLBACK, 0);
	goto end;
    }

    if ((status =
	 ai->pvinfo->newval(&pval, authority, val, ai->params)) != GAA_S_SUCCESS)
	goto end;

    if ((status =
	 gaa_new_policy_right_rawval(gaa, right, type, authority,
				     pval)) != GAA_S_SUCCESS)
	goto end;
 end:
    if (status != GAA_S_SUCCESS) 
	*right = 0;
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Allocate a new policy right structure and fill it in with the specified
 *  values.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param right
 *         output right pointer
 *  @param type
 *         input right type (pos_access_right or neg_access_right)
 *  @param authority
 *         input authority
 *  @param val
 *         input value
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa, right, or authority is null
 *  @retval GAA_S_NO_AUTHINFO_CALLBACK
 *          No authinfo callback was installed appropriate for the specified
 *          authority
 *
 *  @note
 *  Policy rights created with this routine should be freed with
 *  gaa_free_policy_right().
 *
 *  This function does not do any translation of the policy right
 *  value; the value should be in a form that's understood by the
 *  matchrights, copyval, and freeval, and valmatch functions
 *  in the authinfo callback associated with this authority.
 */
gaa_status
gaa_new_policy_right_rawval(gaa_ptr		gaa,
			    gaa_policy_right **	right,
			    gaa_right_type	type,
			    gaa_string_data	authority,
			    void *		val)
{
    gaa_status				status = GAA_S_SUCCESS;
    gaaint_authinfo *			ai = 0;

    if (gaa == 0 || right == 0 || authority == 0)
    {
	gaacore_set_err("gaa_new_policy_right_rawval: gaa, right or authority was 0");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    if ((*right = (gaa_policy_right *)malloc(sizeof(gaa_policy_right))) == 0)
    {
	gaacore_set_err("gaa_new_policy_right: malloc failed");
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    (*right)->type = type;
    (*right)->value = val;
    (*right)->conditions = 0;
    (*right)->i = 0;
    if ((status =
	 gaa_i_new_string(&(*right)->authority, authority)) != GAA_S_SUCCESS)
	goto end;
    if ((ai = gaa_i_auth2authinfo(gaa, authority)) == 0)
    {
	gaacore_set_err("gaa_new_policy_right_rawval: no callback for this authority");
	status = (GAA_STATUS(GAA_S_NO_AUTHINFO_CALLBACK, 0));
	goto end;
    }
    if (ai->pvinfo == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (((*right)->conditions =
	 gaa_i_new_silo((gaa_freefunc)gaa_free_condition)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if ((status =
	 gaa_l_new_gaaint_policy_right(&(*right)->i,
				       ai->pvinfo->freeval)) != GAA_S_SUCCESS)
	goto end;
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_policy_right(*right);
	*right = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a policy right.
 *
 *  @param right
 *         input/output right to free
 *
 *  @note
 *  If a policy was created with gaa_new_policy() or initialized with
 *  gaa_init_policy() and is freed with gaa_free_policy(), then this
 *  function will be called to free all associated policy rights
 *  when the policy is freed.
 */
void
gaa_free_policy_right(gaa_policy_right *right)
{
    if (right == 0)
	return;

    gaa_i_free_simple(right->authority);
    if (right->value && right->i && right->i->freeval)
	right->i->freeval(right->value);
    gaa_list_free(right->conditions);
    gaa_l_free_gaaint_policy_right(right->i);
    free(right);
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Free an internal policy representation.  Called by gaa_free_policy().
 *
 *  @param i
 *         input/output object to free.
 */
static void
gaa_l_free_gaaint_policy(gaaint_policy *i)
{
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Reset an answer, freeing all policy entries associated with it.
 *  Called by gaa_check_authorization().
 *
 *  @param answer
 *         input/output answer to clear.
 */
static gaa_status
gaa_l_reset_answer(gaa_answer *answer)
{
    gaa_l_clear_answer(answer);
    return(gaa_l_init_answer(answer));
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Check a single request right against a policy.  Called by
 *  gaa_check_authorization().
 *
 *  @param gaa
 *         input gaa pointer
 *  @param sc
 *         input security context
 *  @param policy
 *         input policy
 *  @param right
 *         input request right to check
 *  @param ans
 *         input/output answer
 *  @param ynm
 *         output -- set to GAA_C_YES, GAA_C_NO, or GAA_C_MAYBE
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_NO_MATCHING_ENTRIES
 *          No policy entries match the requested right
 *  @retval GAA_S_NO_MATCHRIGHTS_CALLBACK
 *          No matchrights callback exists to find the appropriate
 *          policy subset.
 *
 *  @note
 *  This function finds the policy entries that match the request
 *  right (using the matchrights callback), and then checks the right
 *  against those policy entries in order.  If it finds a positive entry
 *  that has no conditions or whose conditions are all met, then it stops
 *  looking and returns GAA_C_YES (unless it had previously encountered
 *  a negative policy right that it couldn't evaluate, in which case it
 *  returns GAA_C_MAYBE).  If it finds a negative entry that has no
 *  conditions or whose conditions are all met, then it stops looking
 *  and returns GAA_C_NO (unless it had previously encountered a
 *  positive policy right that it couldn't evaluate, in which case it
 *  returns GAA_C_MAYBE).  If it gets through the entire policy without
 *  finding any entries whose conditions are all met, then it returns
 *  GAA_C_MAYBE if there were any positive entries that it could not
 *  evaluate, and GAA_C_NO if there weren't.
 */
static gaa_status
gaa_l_check_one_right(gaa_ptr		 gaa,
		      gaaint_sc *	 sc,
		      gaa_policy *	 policy,
		      gaa_request_right *right,
		      gaa_answer *	 ans,
		      int *		 ynm)
{
    gaaint_list_entry *	      ent;
    gaa_policy_entry *	      p_ent;
    gaa_status		      status = GAA_STATUS(GAA_S_NO_MATCHING_ENTRIES, 0);
    gaa_policy		      newpolicy;
    int			      condstat = 0;
    int			      had_pos_maybe = 0;
    int			      had_neg_maybe = 0;
    gaa_time_period	      ctp;
    gaa_policy_right *	      pright = 0;

    ctp.start_time = ctp.end_time = 0;
    gaa_l_init_policy(&newpolicy, 0);
    if (gaa == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (! (gaa->matchrights && gaa->matchrights->func))
    {
	status = GAA_STATUS(GAA_S_NO_MATCHRIGHTS_CALLBACK, 0);
	goto end;
    }
    if ((status =
	 gaa->matchrights->func(gaa, policy, right, &newpolicy,
				gaa->matchrights->param)) != GAA_S_SUCCESS)
	goto end;
    if (gaa_i_list_empty(newpolicy.entries))
    {
	status = GAA_STATUS(GAA_S_NO_MATCHING_ENTRIES, 0);
	goto end;
    }

    for (ent = gaa_list_first(newpolicy.entries); ent; ent = gaa_list_next(ent))
	if (p_ent = (gaa_policy_entry *)gaa_list_entry_value(ent))
	{
	    if ((status = gaa_l_check_simple(gaa, sc, p_ent,
					     right->options, &pright,
					     &condstat, &ctp,
					     0)) != GAA_S_SUCCESS)
		break;
	    gaa_i_list_add_entry(ans->rights, pright);
	    if (condstat & GAA_COND_FLG_MET)
	    {
		/* Matched a positive or negative right -- we're done */
		*ynm = ((p_ent->right->type == gaa_pos_access_right) ?
			GAA_C_YES : GAA_C_NO);
		break;
	    }
	    else if (condstat & GAA_COND_FLG_EVALUATED)
	    {
		/* We failed to meet the conditions for a right, so the
		 * answer for this entry is "no", whether this right
		 * is positive or negative.  In either case, we want
		 * to keep looking for other rights.
		 */
		*ynm = GAA_C_NO;
	    }
	    else
	    {
		*ynm = GAA_C_MAYBE;
		if (p_ent->right->type == gaa_pos_access_right)
		    had_pos_maybe = 1;
		else
		    had_neg_maybe = 1;
	    }
	}
    /*
     * At this point:
     *   If *ynm is yes, we've met the conditions for a positive right and
     *   should answer "yes" -- unless there was an earlier negative policy
     *   right that we couldn't decide, in which case we should answer "maybe".
     *
     *   If *ynm is maybe, then we haven't met the conditions for any
     *   rights, positive or negative, and should answer "maybe".
     *
     *   If *ynm is no, then either we've matched a negative right and
     *   stopped, or we've gotten to the end of the list without
     *   meeting the conditions for any right.  In either case, we
     *   should answer "no", unless there was an earlier positive policy
     *   right that we couldn't decide, in which case we should answer
     *   "maybe".
     */

    if ((*ynm == GAA_C_NO) && had_pos_maybe)
	*ynm = GAA_C_MAYBE;
    if ((*ynm == GAA_C_YES) && had_neg_maybe)
	*ynm = GAA_C_MAYBE;

    /*
     * Fix the time period in the global answer.  If this right's answer
     * is "maybe", leave the time period alone.  If it's "yes", intersect
     * the answer time period with the current time period.  If it's "no",
     * set the answer time period to the current time period.
     */
    if ((status == GAA_S_SUCCESS) && ans->valid_time)
    {
	if (*ynm == GAA_C_YES)
	    gaa_l_intersect_times(ans->valid_time, &ctp);
	else if (*ynm == GAA_C_NO)
	    gaa_l_set_times(ans->valid_time, &ctp);
    }

 end:    
    gaa_clear_policy(&newpolicy);
    return(status);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Combine a current and aggregate status into a new aggregate
 *  status.  Called by gaa_check_authorization().
 *
 *  @param aggregate
 *         input aggregate status
 *  @param current
 *         input current status
 *
 *  @retval GAA_C_YES
 *          current and aggregate were both GAA_C_YES
 *  @retval GAA_C_NO
 *          current or aggregate was GAA_C_NO
 *  @retval GAA_C_MAYBE
 *          neither current nor aggregate was GAA_C_NO, and at least
 *          one of them was GAA_C_MAYBE.
 */ 
static
gaa_l_arbitrate_status(int aggregate, int current)
{
    switch (aggregate) {
    case GAA_C_YES:
	return(current);
    case GAA_C_NO:
	return(aggregate);
    case GAA_C_MAYBE:
	if (current == GAA_C_YES || current == GAA_C_MAYBE)
	    return(aggregate);
	else
	    return(current);
    default:			/* we can never get here */
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    }
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Clear an answer pointer, freeing all its associated policy rights.
 *  Called by gaa_free_answer() and gaa_l_reset_answer().
 *
 *  @param answer
 *         input/output answer to clear.
 */ 
static void
gaa_l_clear_answer(gaa_answer *answer)
{
    if (answer == 0)
	return;
    gaa_l_free_time_period(answer->valid_time);
    answer->valid_time = 0;
    gaa_list_free(answer->rights);
    answer->rights = 0;
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Initialize an answer structure.  Called by gaa_new_answer() and
 *  gaa_l_reset_answer().
 *
 *  @param answer
 *         input/output answer to initialize.
 */ 
static gaa_status
gaa_l_init_answer(gaa_answer *answer)
{
    gaa_status status;

    if (answer == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    answer->valid_time = 0;
    answer->rights = 0;
    if ((answer->rights =
	 gaa_i_new_silo((gaa_freefunc)gaa_free_policy_right)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if ((status =
	 gaa_l_new_time_period(&answer->valid_time, 0, 0)) != GAA_S_SUCCESS)
	goto end;
 end:
    return(status);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Check the conditions associated with a policy entry.
 *  Return a standard status flag, and set *condstat.  If there
 *  is a "no" condition, set *condstat to "evaluated" and vtime
 *  to the time period for that condition.  Otherwise, set *condstat
 *  to the intersection of all the condition statuses of all conditions
 *  in the entry and vtime to the intersection of all returned time
 *  periods.  If the entry has no conditions, return the "evaluated"
 *  and "met" flags. If idonly is nonzero, check only those conditions
 *  that are considered identity conditions.  Called by
 *  gaa_inquire_policy_info() and gaa_l_check_one_right().
 *
 *  @param gaa
 *         input gaa pointer
 *  @param sc
 *         input security context
 *  @param p_ent
 *         input policy entry
 *  @param options
 *         input request options
 *  @param pright
 *         output policy right
 *  @param condstat
 *         output aggregate condition status
 *  @param vtp
 *         output aggregate condition time period
 *  @param idonly
 *         input flag -- if set, only "identity" conditions are checked.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_BAD_CALLBACK_RETURN
 *          bad return value from cond_eval callback
 *
 */
static gaa_status
gaa_l_check_simple(gaa_ptr		gaa,
		   gaaint_sc *		sc,
		   gaa_policy_entry *	p_ent,
		   gaa_list_ptr		options,
		   gaa_policy_right **	pright,
		   int *		condstat,
		   gaa_time_period *	vtp,
		   int			idonly)
{
    gaaint_list_entry *			ent;
    gaa_condition *			cond;
    int					current_ynm;
    int					hasconds = 0;
    gaa_time_period			curtp;
    gaaint_cond_eval_entry *		ce;
    gaa_status				status = GAA_S_SUCCESS;
    
    if (! (gaa && sc && p_ent && pright))
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    /* Start with no time restrictions */
    if (vtp)
	vtp->start_time = vtp->end_time = 0;
    curtp.start_time = curtp.end_time = 0;

    /*
     * Make a copy of the right, because the one in the policy may be
     * shared by multiple threads, and we'll be changing the status
     * value of the associated conditions.
     */
    if ((status =
	 gaa_l_clone_policy_right(gaa, pright, p_ent->right)) != GAA_S_SUCCESS)
	return(status);
    *condstat = (GAA_COND_FLG_EVALUATED | GAA_COND_FLG_MET);
    for (ent = gaa_list_first((*pright)->conditions); ent;
	 ent = gaa_list_next(ent))
	if (cond = (gaa_condition *)gaa_list_entry_value(ent))
	{
	    cond->status = 0;	/* this should be true anyway */
	    if ((ce = gaa_l_find_cond_eval_entry(gaa, cond)) && ce->cb)
	    {
		if (idonly && ! ce->is_idcred)
		    continue;	/* skip this entry */
		if ((status = gaa_l_check_condition(gaa, sc, cond, &curtp,
						      options, &current_ynm,
						      ce)) != GAA_S_SUCCESS)
		    return(status);
		switch(current_ynm)
		{
		case GAA_C_YES:
		    gaa_l_intersect_times(vtp, &curtp);
		    break;
		case GAA_C_NO:
		    gaa_l_set_times(vtp, &curtp);
		    *condstat = cond->status;
		    return(status);
		case GAA_C_MAYBE:
		    break;
		default:
		    return(GAA_STATUS(GAA_S_BAD_CALLBACK_RETURN, 0));
		}
	    }
	    else if (idonly)
		continue;
	    else
		current_ynm = GAA_C_MAYBE;
	    *condstat &= cond->status;
	}
    return(status);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Find the intersection of two time periods.  Called by
 *  gaa_l_check_one_right() and gaa_l_check_simple().
 *
 *  @param to
 *         input/output time period
 *  @param from
 *         input time period
 */ 
static void
gaa_l_intersect_times(gaa_time_period *to, gaa_time_period *from)
{
    if (! (to && from))
	return;
    to->start_time = MAX(to->start_time, from->start_time);
    if (to->end_time == 0)
	to->end_time = from->end_time;
    else if (from->end_time != 0)
	to->end_time = MIN(to->start_time, to->end_time);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Copy the time period "from" into "to".  Called by
 *  gaa_l_check_one_right and gaa_l_check_simple().
 *
 *  @param to
 *         output time period to copy to
 *  @param from
 *         input time period to copy from
 */ 
static void
gaa_l_set_times(gaa_time_period *to, gaa_time_period *from)
{
    if (! (to && from))
	return;
    to->start_time = from->start_time;
    to->end_time = from->end_time;
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Free a time period.  Called by gaa_l_clear_answer().
 *
 *  @param time_period
 *         input/output time period to free.
 */ 
static void
gaa_l_free_time_period(gaa_time_period *time_period)
{
    if (time_period)
	free(time_period);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Initialize a policy structure.  Called by gaa_init_policy() and
 *  gaa_l_check_one_right()
 *
 *  @param policy
 *         input/output policy to initialize
 *  @param freerights
 *         input -- if nonzero, then the policy will be initialized so that
 *         gaa_free_policy() will free all policy rights associated with
 *         the policy when freeing the policy itself.  If freerights is
 *         0, then the policy will be initialized so that gaa_free_policy
 *         will not free the associated policy rights when freeing the
 *         policy.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 */ 
static gaa_status
gaa_l_init_policy(gaa_policy *		policy,
		  int			freerights)
{
    gaa_status status;

    if (policy == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    policy->entries = 0;
    if ((policy->entries =
	 gaa_i_new_sorted_list((gaa_listcompfunc)gaa_i_policy_order,
				 (freerights ?
				  (gaa_freefunc)gaa_free_policy_entry :
				  (gaa_freefunc)gaa_l_free_policy_entry_noright))) == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((status = gaa_l_new_gaaint_policy(&policy->i)) != GAA_S_SUCCESS)
	return(status);
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Create a new internal representation of a policy.
 *  Called by gaa_l_init_policy().
 *
 *  @param i
 *         output structure to create
 */
static gaa_status
gaa_l_new_gaaint_policy(gaaint_policy **i)
{
    if (i == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    *i = 0;
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Create a new policy right that's a copy of an old right.  Called by
 *  gaa_l_check_simple().  This function uses the policy right copyval
 *  authinfo callback.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param new
 *         output new right to create
 *  @param old
 *         input old right to copy
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_NO_AUTHINFO_CALLBACK
 *          no authinfo callback was found.
 */
static gaa_status
gaa_l_clone_policy_right(gaa_ptr	    gaa,
			 gaa_policy_right **new,
			 gaa_policy_right * old)
{
    gaa_status				status = GAA_S_SUCCESS;
    gaa_list_entry_ptr			ent;
    gaa_condition *			cond;
    gaa_condition *			ncond;
    gaaint_authinfo *			ai;
    void *				pval;
    
    if (! (old && new))
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((ai = gaa_i_find_authinfo(gaa, old)) == 0)
    {
	gaacore_set_err("gaa_l_clone_policy_right: no authinfo callback for this authority");
	return(GAA_STATUS(GAA_S_NO_AUTHINFO_CALLBACK, 0));
    }
    if (ai->pvinfo == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (ai->pvinfo->copyval == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((status =
	 ai->pvinfo->copyval(&pval, old->authority, old->value,
			     ai->params)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_new_policy_right_rawval(gaa, new, old->type,
					      old->authority,
					      pval)) != GAA_S_SUCCESS)
	return(status);
    for (ent = gaa_list_first(old->conditions); ent; ent = gaa_list_next(ent))
    {
	cond = (gaa_condition *)gaa_list_entry_value(ent);
	if ((status = gaa_l_clone_condition(&ncond, cond)) != GAA_S_SUCCESS)
	    goto end;
	if ((status = gaa_add_condition(*new, ncond)) != GAA_S_SUCCESS)
	    goto end;
    }
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_policy_right(*new);
	*new = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Create a new condition that's a copy of an old one.  Called by
 *  gaa_l_clone_policy_right().
 *
 *  @param new
 *         output condition to create
 *  @param old
 *         inpur condition to copy
 */
static gaa_status
gaa_l_clone_condition(gaa_condition **new, gaa_condition *old)
{
    if (! (old && new))
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    return(gaa_new_condition(new, old->type, old->authority, old->value));
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Free a policy entry without freeing its associated policy right.
 *  This function is (sometimes) called by gaa_free_policy().
 *
 *  @param ent
 *         input/output policy entry to free.
 */
static void
gaa_l_free_policy_entry_noright(gaa_policy_entry *ent)
{
    if (ent)
	free(ent);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Check whether the request right and policy right have the same authority
 *
 *  @param rright
 *         input request right
 *  @param pright
 *         input policy right
 *  @param match
 *         output -- 1 if authorities match, 0 otherwise
 *
 *  @retval GAA_S_SUCCESS
 *          success
 */
static gaa_status
gaa_l_match_authority(gaa_request_right *	rright,
		      gaa_policy_right *	pright,
		      int *		match)
{
    if (match == 0 || rright == 0 || pright == 0 || pright->authority == 0 ||
	rright->authority == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    *match = (strcmp(rright->authority, pright->authority) == 0);
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Free the internal representation of a policy right.  Called by
 *  gaa_free_policy_right().
 *
 *  @param i
 *         input/output pointer to free
 */
static void
gaa_l_free_gaaint_policy_right(gaaint_policy_right *i)
{
    if (i)
	free(i);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Create a new internal representation of a policy right.
 *
 *  @param i
 *         output structure to create
 *  @param freefunc
 *         input function to be used to free the policy right value when
 *         the policy right is freed.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 */
static gaa_status
gaa_l_new_gaaint_policy_right(gaaint_policy_right **i,
			      gaa_freefunc	    freefunc)
{
    if (i == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (((*i) = (gaaint_policy_right *)malloc(sizeof(gaaint_policy_right))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*i)->freeval = freefunc;
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Find the condition evaluation callback appropriate for the specified
 *  condition.  Called by gaa_check_condition() and gaa_l_check_simple().
 *
 *  @param gaa
 *         input gaa pointer
 *  @param cond
 *         input condition
 *
 *  @retval <cond_eval_entry>
 *          the cond_eval entry that was found
 *  @retval 0
 *          no cond_eval entry was found
 */
static gaaint_cond_eval_entry *
gaa_l_find_cond_eval_entry(gaa_ptr gaa, gaa_condition *cond)
{
    gaaint_list_entry *ent;
    gaaint_cond_eval_entry *ce;

    if (gaa == 0 || cond == 0)
	return(0);
    for (ent = gaa_list_first(gaa->cond_callbacks); ent; ent = gaa_list_next(ent)) {
	ce = (gaaint_cond_eval_entry *)gaa_list_entry_value(ent);
	if (((ce->type == 0) ||
	     (cond->type && (strcmp(ce->type, cond->type) == 0))) &&
	    ((ce->authority == 0) ||
	     (cond->authority && (strcmp(ce->authority, cond->authority) == 0))))
	    return(ce);
    }
    return(0);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Use a condition evaluation entry to check a single condition.
 *  Called by gaa_check_condition() and gaa_l_check_simple().
 *
 *  @param gaa
 *         input gaa pointer
 *  @param sc
 *         input security context
 *  @param cond
 *         input condition
 *  @param vtp
 *         output time period associated with this condition
 *  @param options
 *         input list of request options
 *  @param ynm
 *         optional output yes/no/maybe (set by the cond_eval callback in ce)
 *  @param ce
 *         input condition evaluation entry.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_BAD_CALLBACK_RETURN
 *          bad return value from cond_eval callback.
 */
static gaa_status
gaa_l_check_condition(gaa_ptr		      gaa,
		      gaa_sc_ptr	      sc,
		      gaa_condition *	      cond,
		      gaa_time_period *	      vtp,
		      gaa_list_ptr	      options,
		      int *		      ynm,
		      gaaint_cond_eval_entry *ce)
{
    gaa_status status;
    char ebuf[1024];
    gaa_status oflags = 0;

    if (! (gaa && sc && cond && vtp))
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    vtp->start_time = vtp->end_time = 0;
    cond->status = 0;
    if (ynm)
	*ynm = GAA_C_MAYBE;

    if (! (ce && ce->cb))	/* No callback installed */
	return(GAA_S_SUCCESS);

    if ((status = ce->cb->func(gaa, sc, cond, vtp, options, &oflags,
			       ce->cb->params)) != GAA_S_SUCCESS)
    {
	
	snprintf(ebuf, sizeof(ebuf),
		 "gaa_l_check_condition: callback function returned %s (condition type/auth was %s/%s); callback error was: %s",
		 gaacore_majstat_str(status),
		 (cond->type ? cond->type : "(null)"),
		 (cond->authority ? cond->authority : "(null)"),
		 gaa_get_callback_err());
	gaacore_set_err(ebuf);
	return(status);
    }
    cond->status = oflags;
    if (ynm && (cond->status & GAA_COND_FLG_EVALUATED))
	*ynm = ((cond->status & GAA_COND_FLG_MET) ? GAA_C_YES : GAA_C_NO);
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa_policy_static
 *
 *  Create a new time period structure and fill in values.  Called
 *  by gaa_l_init_answer().
 * 
 *  @param time_period
 *         output time period to create.
 *  @param start_time
 *         input start time
 *  @param end_time
 *         input end time
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 */
static gaa_status
gaa_l_new_time_period(gaa_time_period **time_period,
		      time_t		start_time,
		      time_t		end_time)
{
    gaa_status status = GAA_S_SUCCESS;
    if (time_period == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((*time_period = (gaa_time_period *)malloc(sizeof(gaa_time_period))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));    
    (*time_period)->start_time = 0;
    (*time_period)->end_time = 0;
    return(status);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
