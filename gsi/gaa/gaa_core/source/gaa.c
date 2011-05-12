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

/** @defgroup gaa Generic Authorization and Access Control API
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file gaa.c GAA Core
 */
/**
 * @defgroup gaa_c_static Static-scope functions in gaa.c
 */
static int
gaa_l_order_mechinfo(void *d1, void *d2);

static gaaint_mechinfo *
gaa_l_find_mechinfo(gaa_ptr gaa, gaa_string_data mech_type);

static gaa_status
gaa_l_new_cond_eval_entry(gaaint_cond_eval_entry **ce, char *type,
		      char *authority, gaa_cond_eval_callback_ptr cb,
		      int is_idcred);

static void
gaa_l_free_cond_eval_entry(gaaint_cond_eval_entry *ce);

static int
gaa_l_order_cond_eval_entry(gaaint_cond_eval_entry *c1,
			    gaaint_cond_eval_entry *c2);

static gaa_status
gaa_l_new_gaaint_cond(gaaint_cond **ic, gaa_condition *c);

static void
gaa_l_free_gaaint_cond(gaaint_cond *c);

static void
gaa_l_free_gaaint_request_right(gaaint_request_right *i);

static int
gaa_l_order_authinfo(gaaint_authinfo *a1, gaaint_authinfo *a2);

static gaa_status
gaa_l_new_gaaint_request_right(gaaint_request_right **i,
			       gaa_freefunc freefunc);

static void
gaa_l_free_getpolicy_callback(gaaint_getpolicy_callback *getp);

static void
gaa_l_free_matchrights_callback(gaaint_matchrights_callback *mr);

static gaa_status
gaa_l_new_getpolicy_callback(gaaint_getpolicy_callback **gp,
			     gaa_getpolicy_func func, void *param,
			     gaa_freefunc freefunc);

static gaa_status
gaa_l_new_matchrights_callback(gaaint_matchrights_callback **m,
			       gaa_matchrights_func func, void *param,
			       gaa_freefunc freefunc);

static gaa_status
gaa_l_new_mechinfo(gaaint_mechinfo **minfo, gaa_string_data mech_type,
		   gaa_cred_pull_func cred_pull,
		   gaa_cred_eval_func cred_eval,
		   gaa_cred_verify_func cred_verify,
		   gaa_freefunc cred_free, void *param,
		   gaa_freefunc freeparam);

static void
gaa_l_free_mechinfo(gaaint_mechinfo *minfo);

static void
gaa_l_clear_sec_attrb(gaa_sec_attrb *a);

static gaa_status
gaa_l_init_sec_attrb(gaa_sec_attrb *a, gaa_cred_type type,
		     char *authority, char *value);

static void
gaa_l_free_gaaint_request_option(gaaint_request_option *i);

static gaa_status
gaa_l_new_gaaint_request_option(gaaint_request_option **i,
				gaa_freefunc freefunc);

static gaa_status
gaa_l_new_option(gaa_request_option **opt, char *type, char *authority,
		 void *value, gaa_freefunc freeval);

static void
gaa_l_free_request_option(gaa_request_option *option);

static int
gaa_l_checkdiff_sec_attrb(gaa_sec_attrb *a1, gaa_sec_attrb *a2);

static int
gaa_l_checkdiff_id_info(gaa_identity_info *i1, gaa_identity_info *i2);

static int
gaa_l_checkdiff_conditions(gaa_condition *c1, gaa_condition *c2);

static int
gaa_l_checkdiff_condlists(gaa_list_ptr l1, gaa_list_ptr l2);

static int
gaa_l_checkdiff_attr_info(gaa_attribute_info *a1, gaa_attribute_info *a2);

static int
gaa_l_checkdiff_authr_info(gaa_authr_info *a1, gaa_authr_info *a2);

static int
gaa_l_checkdiff_creds(void *c1, void *c2);
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 * @ingroup gaa
 *
 * Allocates a new gaa_condition structure and fills in the specified values.
 *
 * @param cond
 *        output condition
 * @param type
 *        input condition type
 * @param authority
 *        input condition authority
 * @param value
 *        input condition value
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INVALID_ARG
 *         cond is null, or authority is null but value is not.
 * 
 * @note
 * Conditions allocated with this function should be freed with
 * gaa_free_condition().
 */
gaa_status
gaa_new_condition(gaa_condition **	cond,
		  gaa_string_data	type,
		  gaa_string_data	authority,
		  gaa_string_data	value)
{
    gaa_status				status = GAA_S_SUCCESS;
    if (cond == 0)
    {
	gaacore_set_err("gaa_new_condition: called with null condition pointer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if (value && ! authority)
    {
	gaacore_set_err("gaa_new_condition: called with value but no authority");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*cond = (gaa_condition *)malloc(sizeof(gaa_condition))) == 0)
    {
	gaacore_set_err("gaa_new_condition: malloc failed");
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    (*cond)->type = 0;
    (*cond)->authority = 0;
    (*cond)->value = 0;
    (*cond)->status = 0;
    (*cond)->i = 0;
    if ((status = gaa_i_new_string(&(*cond)->type, type)) != GAA_S_SUCCESS)
	goto end;
    if (authority)
	if ((status =
	     gaa_i_new_string(&(*cond)->authority,
				authority)) != GAA_S_SUCCESS)
	    goto end;
    if (value)
	if ((status =
	     gaa_i_new_string(&(*cond)->value, value)) != GAA_S_SUCCESS)
	    goto end;
    if ((status = gaa_l_new_gaaint_cond(&(*cond)->i, *cond)) != GAA_S_SUCCESS)
	goto end;
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_condition(*cond);
	*cond = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a condition (and all its components).
 *
 *  @param cond
 *         input/output condition to free.
 */
void
gaa_free_condition(gaa_condition *cond)
{
    if (cond == 0)
	return;
    gaa_i_free_simple(cond->type);
    gaa_i_free_simple(cond->authority);
    gaa_i_free_simple(cond->value);
    gaa_l_free_gaaint_cond(cond->i);
    free(cond);
}

/**
 *
 *  @ingroup gaa
 *
 *  Allocate a new request right structure and fill it in with the specified
 *  values.
 *
 *  @param gaa
 *         the gaa pointer to inspect
 *  @param right
 *         output right pointer
 *  @param authority
 *         input authority
 *  @param val
 *         input string representation of value
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa, right, or authority is null
 *  @retval GAA_S_NO_AUTHINFO_CALLBACK
 *          No authinfo callback was installed appropriate for the specified
 *          authority
 *  @retval GAA_S_NO_NEWVAL_CALLBACK
 *          The authinfo callback does not include a newval function for
 *          request rights.
 *
 *  @note
 *  Request rights created with this routine should be freed with
 *  gaa_free_request_right().
 *
 *  This function uses the authinfo callback associated with the
 *  specified authority (or the default authinfo callback) to translate
 *  the value string into the appropriate representation of the value.
 */
gaa_status
gaa_new_request_right(gaa_ptr		  gaa,
		      gaa_request_right **right,
		      gaa_string_data     authority,
		      gaa_string_data     val)
{
    gaa_status				status = GAA_S_SUCCESS;
    gaaint_authinfo *			ai;
    void *				value;
    
    if (gaa == 0 || right == 0 || authority == 0)
    {
	gaacore_set_err("gaa_new_request_right: called with null gaa, right, or authority");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((ai = gaa_i_auth2authinfo(gaa, authority)) == 0)
    {
	gaacore_set_err("gaa_new_request_right: no callback for this authority");
	return(GAA_STATUS(GAA_S_NO_AUTHINFO_CALLBACK, 0));
    }
    if (ai->rvinfo == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (ai->rvinfo->newval == 0)
    {
	gaacore_set_err("gaa_new_request_right: no newval callback for this authority");
	return(GAA_STATUS(GAA_S_NO_NEWVAL_CALLBACK, 0));
    }
    
    if ((status = ai->rvinfo->newval(&value, authority, val, ai->params)) != GAA_S_SUCCESS)
	return(status);

    return(gaa_new_request_right_rawval(gaa, right, authority, value));
}

/**
 *
 *  @ingroup gaa
 *
 *  Allocate a new request right structure and fill it in with the specified
 *  values.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param right
 *         output right pointer
 *  @param authority
 *         input authority
 *  @param value
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
 *  Request rights created with this routine should be freed with
 *  gaa_free_request_right().
 *
 *  This function does not do any translation of the request right
 *  value; the value should be in a form that's understood by the
 *  matchrights, copyval, and freeval, and valmatch functions
 *  in the authinfo callback associated with this authority.
 */
gaa_status
gaa_new_request_right_rawval(gaa_ptr	         gaa,
			     gaa_request_right **right,
			     gaa_string_data	 authority,
			     void *		 value)
{
    gaa_status				status = GAA_S_SUCCESS;
    gaaint_authinfo *			ai;

    if (gaa == 0)
    {
	gaacore_set_err("gaa_new_request_right: called with null gaa pointer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if (right == 0)
    {
	gaacore_set_err("gaa_new_request_right: called with null right pointer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if (authority == 0)
    {
	gaacore_set_err("gaa_new_request_right: called with null authority pointer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    if ((*right
	 = (gaa_request_right *)malloc(sizeof(gaa_request_right))) == 0)
    {
	gaacore_set_err("gaa_new_request_right: malloc failed");
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    (*right)->value = 0;
    (*right)->options = 0;
    (*right)->i = 0;
    if ((status =
	 gaa_i_new_string(&(*right)->authority, authority)) != GAA_S_SUCCESS)
	goto end;
    if ((ai = gaa_i_auth2authinfo(gaa, authority)) == 0)
    {
	gaacore_set_err("gaa_new_request_right_rawval: no callback for this authority");
	status = (GAA_STATUS(GAA_S_NO_AUTHINFO_CALLBACK, 0));
	goto end;
    }
    if (ai->rvinfo == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    (*right)->value = value;
    if (((*right)->options =
	 gaa_i_new_silo((gaa_freefunc)gaa_l_free_request_option)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if ((status =
	 gaa_l_new_gaaint_request_right(&(*right)->i,
					ai->rvinfo->freeval)) != GAA_S_SUCCESS)
	goto end;
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_request_right(*right);
	*right = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a request right (and all its components).
 *
 *  @param right
 *         input/output request right to free.
 */
void
gaa_free_request_right(gaa_request_right *right)
{
    if (right == 0)
	return;

    gaa_i_free_simple(right->authority);
    if (right->value && right->i && right->i->freeval)
	right->i->freeval(right->value);
    gaa_list_free(right->options);
    gaa_l_free_gaaint_request_right(right->i);
    free(right);
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_c_static
 *
 *  Free the internal representation of a request right.
 *
 *  @param i
 *         input/output internal request right to free.
 */
static void
gaa_l_free_gaaint_request_right(gaaint_request_right *i)
{
    if (i)
	free(i);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *
 *  Add a condition to a policy right.
 *
 *  @param right
 *         input right to add
 *  @param condition
 *         input/output condition to add right to.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 */
gaa_status
gaa_add_condition(gaa_policy_right *	right,
		  gaa_condition *	condition)
{
    return(gaa_i_list_add_entry(right->conditions, condition));
}

/**
 *
 *  @ingroup gaa
 *
 * Create a new gaa pointer.
 *
 * @param gaa
 *        output gaa pointer to create.
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INVALID_ARG
 *         gaa is null.
 *
 * @note
 * A gaa pointer created using this function should be freed with
 * gaa_free_gaa().
 */
gaa_status
gaa_new_gaa(gaa_ptr *gaa)
{
    gaa_status status = GAA_S_SUCCESS;

    if (gaa == 0)
    {
	gaacore_set_err("gaa_new_gaa: called with null gaa");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*gaa = (gaaint_gaa *)malloc(sizeof(gaaint_gaa))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*gaa)->mechinfo = 0;
    (*gaa)->getpolicy = 0;
    (*gaa)->matchrights = 0;
    (*gaa)->cond_callbacks = 0;
    (*gaa)->authorization_identity_callback = 0;
    if (((*gaa)->mechinfo =
	 gaa_i_new_sorted_list(gaa_l_order_mechinfo,
				 (gaa_freefunc)gaa_l_free_mechinfo)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if (((*gaa)->cond_callbacks =
	 gaa_i_new_sorted_list((gaa_listcompfunc)gaa_l_order_cond_eval_entry,
				 (gaa_freefunc)gaa_l_free_cond_eval_entry)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if (((*gaa)->authinfo =
	 gaa_i_new_sorted_list((gaa_listcompfunc)gaa_l_order_authinfo,
				 (gaa_freefunc)gaa_i_free_authinfo)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }

 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_gaa(*gaa);
	*gaa = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 * Create a new gaa security context
 *
 * @param sc
 *        output security context
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INVALID_ARG
 *         sc is null.
 *
 * @note
 * A security context created using this function should be freed with
 * gaa_free_sc().
 */
gaa_status
gaa_new_sc(gaa_sc_ptr *sc)
{
    gaa_status status = GAA_S_SUCCESS;

    if (sc == 0)
    {
	gaacore_set_err("gaa_new_sc: called with null sc");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*sc = (gaaint_sc *)malloc(sizeof(gaaint_sc))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*sc)->identity_cred = 0;
    (*sc)->authr_cred = 0;
    (*sc)->attr_cred = 0;
    (*sc)->group_membership = 0;
    (*sc)->group_non_membership = 0;
    (*sc)->uneval_cred = 0;
    if (((*sc)->identity_cred =
	 gaa_i_new_stack((gaa_freefunc)gaa_free_cred)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    (*sc)->authr_cred = 0;
    if (((*sc)->group_membership =
	 gaa_i_new_stack((gaa_freefunc)gaa_free_cred)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if (((*sc)->group_non_membership =
	 gaa_i_new_stack((gaa_freefunc)gaa_free_cred)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if (((*sc)->authr_cred =
	 gaa_i_new_stack((gaa_freefunc)gaa_free_cred)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if (((*sc)->attr_cred =
	 gaa_i_new_stack((gaa_freefunc)gaa_free_cred)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
    if (((*sc)->uneval_cred =
	 gaa_i_new_stack((gaa_freefunc)gaa_free_cred)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_sc(*sc);
	*sc = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Create a new gaa_sec_attrb, and fill it in with the specified values.
 *  This is a utility function for use by condition evaluation callback
 *  functions.
 *
 *  @param a
 *         output gaa_sec_attrb to create
 *  @param type
 *         input credential type
 *  @param authority
 *         input authority
 *  @param value
 *         input value
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          a is null.
 * 
 *  @note
 *  A gaa_sec_attrb created using this function should be freed with
 *  gaa_free_sec_attrb().  This will happen automatically if it's part
 *  of a credential freed with gaa_free_cred().
 */
gaa_status
gaa_new_sec_attrb(gaa_sec_attrb **	a,
		  gaa_cred_type		type,
		  gaa_string_data	authority,
		  gaa_string_data	value)
{
    if (a == 0)
    {
	gaacore_set_err("gaa_new_sec_attrb: called with null sec_attrb");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*a = (gaa_sec_attrb *)malloc(sizeof(gaa_sec_attrb))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    return(gaa_l_init_sec_attrb(*a, type, authority, value));
}

/**
 *
 *  @ingroup gaa
 *
 * Frees a gaa_sec_attrb.
 *
 * @param a
 *        input/output sec_attrb to free.
 */
void
gaa_free_sec_attrb(gaa_sec_attrb *a)
{
    if (a)
    {
	gaa_l_clear_sec_attrb(a);
	free(a);
    }
}

/**
 *
 *  @ingroup gaa
 *
 *  Create a new gaa_identity_info structure.
 *  This is a utility function for use by condition evaluation callback
 *  functions.
 *
 *  @param gaa
 *         This argument is ignored.
 *  @param info
 *         output identity info to create.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          info is null.
 * 
 *  @note
 *  A gaa_identity_info created using this function should be freed with
 *  gaa_free_identity_info().  This will happen automatically if it's part
 *  of a credential freed with gaa_free_cred().
 */
gaa_status
gaa_new_identity_info(gaa_ptr gaa, gaa_identity_info **info)
{
    gaa_status status = GAA_S_SUCCESS;

    if (info == 0)
    {
	gaacore_set_err("gaa_new_identity_info: called with null info pointer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*info = (gaa_identity_info *)malloc(sizeof(gaa_identity_info))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));

    if (((*info)->conditions =
	 gaa_i_new_silo((gaa_freefunc)gaa_free_condition)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_identity_info(*info);
	*info = 0;
    }
    return(status);
}

/**
 *  @ingroup gaa
 *
 *  Create a new credential and fill it in with appropriate values.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param sc
 *         input security context
 *  @param cred
 *         credential to initialize
 *  @param mech_type
 *         input credential mechanism type
 *  @param mech_spec_cred
 *         input raw credential
 *  @param cred_type
 *         input credential type (identity, group, etc.).
 *  @param evaluate
 *         input flag -- if nonzero, the credential is evaluated
 *         (i.e. the appropriate cond_eval callback is called)
 *  @param estat
 *         output -- if evaluate and estat are both nonzero, then
 *         estat is set to the return value of the cond_eval function.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa, cred, or mech_type is null
 *  @retval GAA_S_UNKNOWN_MECHANISM
 *          there are no registered mechanism information callbacks for this
 *          mech_type
 * 
 *  @note
 *  A credential created using this function should be freed with
 *  gaa_free_cred.
 */
gaa_status
gaa_new_cred(gaa_ptr			gaa,
	     gaa_sc_ptr			sc,
	     gaa_cred **		cred,
	     gaa_string_data		mech_type,
	     void *			mech_spec_cred,
	     gaa_cred_type		cred_type,
	     int			evaluate,
	     gaa_status *		estat)
{
    gaa_status				status = GAA_S_SUCCESS;
    gaa_status				es;

    if (gaa == 0 || cred == 0 || mech_type == 0)
    {
	gaacore_set_err("gaa_new_cred: called with null gaa, cred or mechanism type");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*cred = (gaa_cred *)malloc(sizeof(gaa_cred))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*cred)->grantor = (*cred)->principal = 0;
    (*cred)->mech_spec_cred = mech_spec_cred;
    (*cred)->type = GAA_UNEVAL;
    if (((*cred)->mechinfo = gaa_l_find_mechinfo(gaa, mech_type)) == 0)
    {
	gaacore_set_err("gaa_new_cred: unknown mechanism type");
	status = GAA_STATUS(GAA_S_UNKNOWN_MECHANISM, 0);
	goto end;
    }
    if (evaluate && (*cred)->mechinfo->cred_eval)
    {
	es = (*cred)->mechinfo->cred_eval(gaa, sc, *cred, mech_spec_cred,
				       cred_type, (*cred)->mechinfo->param);
	if (estat)
	    *estat = es;
    }

 end:
    if (GAA_MAJSTAT(status) != GAA_S_SUCCESS)
    {
	free(*cred);		/* don't free anything we didn't allocate */
	*cred = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a gaa_identity_info structure (and its components).
 *
 *  @param info
 *         input/output structure to free.
 */
void
gaa_free_identity_info(gaa_identity_info *info)
{
    if (info == 0)
	return;
    gaa_list_free(info->conditions);
    free(info);
}

/**
 *
 *  @ingroup gaa
 *
 *  Create a new gaa_authr_info structure and fill it in with appropriate values.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param info
 *         output structure to create
 *  @param objects
 *         input objects to store in info
 *  @param free_objects
 *         input function to be used to free objects when info is freed.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          info or objects is null
 *  @note
 *  A gaa_authr_info created using this function should be freed with
 *  gaa_free_authr_info().  This will happen automatically if it's part
 *  of a credential freed with gaa_free_cred().
 */
gaa_status
gaa_new_authr_info(gaa_ptr	    gaa,
		   gaa_authr_info **info,
		   void *	    objects,
		   gaa_freefunc	    free_objects)
{
    gaa_status status = GAA_S_SUCCESS;

    if (info == 0 || objects == 0)
    {
	gaacore_set_err("gaa_new_authr_info: called with null cred or objects");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*info = (gaa_authr_info *)malloc(sizeof(gaa_authr_info))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*info)->objects = objects;
    (*info)->free_objects = free_objects;
    if (((*info)->access_rights =
	 gaa_i_new_silo((gaa_freefunc)gaa_free_policy_right)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
 end:
    if (status != GAA_S_SUCCESS)
    {
	(*info)->free_objects = 0; /* don't free anything we didn't allocate */
	gaa_free_authr_info(*info);
	*info = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a gaa_authr_info structure (and its components).
 *
 *  @param info
 *         input/output structure to free.
 */
void
gaa_free_authr_info(gaa_authr_info *info)
{
    if (info == 0)
	return;
    gaa_list_free(info->access_rights);
    if (info->free_objects && info->objects)
	info->free_objects(info->objects);
    free(info);
}

/**
 *
 *  @ingroup gaa
 *
 *  Add a credential to a security context.
 *
 *  @param gaa
 *         input gaa pointer (ignored).
 *  @param sc
 *         input/output security context.
 *  @param cred
 *         input credential to add
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          sc or cred is null
 */
gaa_status
gaa_add_cred(gaa_ptr	gaa,
	     gaaint_sc *sc,
	     gaa_cred *	cred)
{

    if (sc == 0 || cred == 0)
    {
	gaacore_set_err("gaa_add_cred: called with null cred or sc");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    switch(cred->type)
    {
	case GAA_IDENTITY:
	    return(gaa_i_list_add_unique_entry(sc->identity_cred, cred,
						 gaa_l_checkdiff_creds));
	case GAA_GROUP_MEMB:
	    return(gaa_i_list_add_unique_entry(sc->group_membership, cred,
						 gaa_l_checkdiff_creds));
	case GAA_GROUP_NON_MEMB:
	    return(gaa_i_list_add_unique_entry(sc->group_non_membership, cred,
						 gaa_l_checkdiff_creds));
	case GAA_AUTHORIZED:
	    return(gaa_i_list_add_unique_entry(sc->authr_cred, cred,
						 gaa_l_checkdiff_creds));
	case GAA_ATTRIBUTES:
	    return(gaa_i_list_add_unique_entry(sc->attr_cred, cred,
						 gaa_l_checkdiff_creds));
	case GAA_UNEVAL:
	    return(gaa_i_list_add_unique_entry(sc->uneval_cred, cred,
						 gaa_l_checkdiff_creds));
	default:
	    return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    }
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_c_static
 *  
 *  Free a gaaint_getpolicy_callback structure.  Called by gaa_free_gaa().
 *
 *  @param getp
 *         input/output structure to free
 */
static void
gaa_l_free_getpolicy_callback(gaaint_getpolicy_callback *getp)
{
    if (getp == 0)
	return;
    if (getp->param && getp->free)
	getp->free(getp->param);
    free(getp);
}

static void
gaa_l_x_free_authorization_identity_callback(gaaint_x_get_authorization_identity_callback *gc)
{
    if (gc == 0)
	return;
    if (gc->param && gc->free)
	gc->free(gc->param);
    free(gc);
}

/**
 *
 *  @ingroup gaa_c_static
 *  
 *  Free a gaaint_matchrights_callback structure.  Called by gaa_free_gaa().
 *
 *  @param mr
 *         input/output structure to free
 */
static void
gaa_l_free_matchrights_callback(gaaint_matchrights_callback *mr)
{
    if (mr == 0)
	return;
    if (mr->param && mr->free)
	mr->free(mr->param);
    free(mr);
}

/**
 *
 *  @ingroup gaa_c_static
 *  
 *  Create a gaaint_getpolicy_callback structure and fill it with
 *  appropriate values.  Called by gaa_set_getpolicy_callback().
 *
 *  @param gp
 *         output structure to create
 *  @param func
 *         input getpolicy callback function
 *  @param param
 *         input getpolicy callback parameter (to always be passed to func)
 *  @param freefunc
 *         input getpolicy freefunc (to be called to free param when
 *         gp is freed).
 *
 *  @retval GAA_S_SUCCESS
 *          success
 * 
 *  @note
 *  A structure created with this function should be freed using
 *  gaa_l_free_getpolicy_callback().  This will happen automatically
 *  if this structure is part of a gaa structure freed with gaa_free_gaa().
 */
static gaa_status
gaa_l_new_getpolicy_callback(gaaint_getpolicy_callback **gp,
			     gaa_getpolicy_func		 func,
			     void *			 param,
			     gaa_freefunc		 freefunc)
{
    gaa_status status = GAA_S_SUCCESS;

    if (gp == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((*gp =
	 (gaaint_getpolicy_callback *)malloc(sizeof(gaaint_getpolicy_callback))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));    
    (*gp)->func = func;
    (*gp)->param = param;
    (*gp)->free = freefunc;
    return(status);
}

/**
 *
 *  @ingroup gaa_c_static
 *  
 *  Create a gaaint_matchrights_callback structure and fill it with
 *  appropriate values.  Called by gaa_set_matchrights_callback().
 *
 *  @param m
 *         output structure to create
 *  @param func
 *         input matchrights callback function
 *  @param param
 *         input matchrights callback parameter (to always be passed to func)
 *  @param freefunc
 *         input matchrights freefunc (to be called to free param when
 *         m is freed).
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @note
 *  A structure created with this function should be freed using
 *  gaa_l_free_matchrights_callback().  This will happen automatically
 *  if this structure is part of a gaa structure freed with gaa_free_gaa().
 */
static gaa_status
gaa_l_new_matchrights_callback(gaaint_matchrights_callback **m,
			       gaa_matchrights_func          func,
			       void *			     param,
			       gaa_freefunc		     freefunc)
{
    gaa_status status = GAA_S_SUCCESS;
    if (m == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((*m = (gaaint_matchrights_callback *)malloc(sizeof(gaaint_matchrights_callback))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));    
    (*m)->func = func;
    (*m)->param = param;
    (*m)->free = freefunc;
    return(status);
}

/**
 *
 *  @ingroup gaa_c_static
 *  
 *  Create a gaaint_x_get_authorization_identity_callback structure and fill it
 *  with appropriate values.  Called by
 *  gaa_x_set_authorization_identity_callback().
 *
 *  @param gp
 *         output structure to create
 *  @param func
 *         input callback function
 *  @param param
 *         input callback parameter (to always be passed to func)
 *  @param freefunc
 *         input freefunc (to be called to free param when
 *         ap is freed).
 *
 *  @retval GAA_S_SUCCESS
 *          success
 * 
 *  @note
 *  A structure created with this function should be freed using
 *  gaa_l_free_getpolicy_callback().  This will happen automatically
 *  if this structure is part of a gaa structure freed with gaa_free_gaa().
 */
static gaa_status
gaa_l_x_new_get_authorization_identity_callback(gaaint_x_get_authorization_identity_callback **gp,
			     gaa_x_get_authorization_identity_func		 func,
			     void *			 param,
			     gaa_freefunc		 freefunc)
{
    gaa_status status = GAA_S_SUCCESS;

    if (gp == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((*gp =
	 (gaaint_x_get_authorization_identity_callback *)malloc(sizeof(gaaint_x_get_authorization_identity_callback))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));    
    (*gp)->func = func;
    (*gp)->param = param;
    (*gp)->free = freefunc;
    return(status);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */


/**
 *
 *  @ingroup gaa
 *
 *  Set the gaa getpolicy callback.  The getpolicy callback function is
 *  used by gaa_get_object_policy_info() to create a policy structure
 *  containing the policy information associated with an object.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param func
 *         input getpolicy function
 *  @param param
 *         input getpolicy parameter (to be passed to func whenever it's called).
 *  @param freefunc
 *         input function to be used to free param when the gaa pointer is freed.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa or func is null
 */
gaa_status
gaa_set_getpolicy_callback(gaa_ptr	      gaa,
			   gaa_getpolicy_func func,
			   void *	      param,
			   gaa_freefunc	      freefunc)
{

    if (gaa == 0 || func == 0)
    {
	gaacore_set_err("gaa_set_getpolicy_callback: called with null gaa or func");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    return(gaa_l_new_getpolicy_callback(&gaa->getpolicy, func, param, freefunc));
}

/**
 *
 *  @ingroup gaa
 *
 *  Set the get_authorization_identity callback
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param func
 *         input get_authorization_identity function
 *  @param param
 *         input getpolicy parameter (to be passed to func whenever it's called).
 *  @param freefunc
 *         input function to be used to free param when the gaa pointer is freed.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa or func is null
 */
gaa_status
gaa_x_set_get_authorization_identity_callback(gaa_ptr	      gaa,
			   gaa_x_get_authorization_identity_func func,
			   void *	      param,
			   gaa_freefunc	      freefunc)
{
    if (gaa == 0 || func == 0)
    {
	gaacore_set_err("gaa_x_set_get_authorization_identity_callback: called with null gaa or func");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    return(gaa_l_x_new_get_authorization_identity_callback(&gaa->authorization_identity_callback, func, param, freefunc));
}

/**
 *
 *  @ingroup gaa
 *
 *  Set the gaa matchrights callback.  This callback is used by
 *  gaa_check_authorization() to find the subset of a policy that's
 *  relevant to a specific request.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param func
 *         input matchrights function
 *  @param param
 *         input getpolicy parameter (to be passed to func whenever it's called).
 *  @param freefunc
 *         input function to be used to free param when the gaa pointer is freed.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa or func is null
 */
gaa_status
gaa_set_matchrights_callback(gaa_ptr	          gaa,
			     gaa_matchrights_func func,
			     void *		  param,
			     gaa_freefunc	  freefunc)
{
    if (gaa == 0 || func == 0)
    {
	gaacore_set_err("gaa_set_matchrights_callback: called with null gaa or func");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    return(gaa_l_new_matchrights_callback(&gaa->matchrights, func, param,
					  freefunc));
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a gaa security context and its components.
 *
 *  @param sc
 *         input/output security context to free.
 */
void
gaa_free_sc(gaa_sc_ptr sc)
{
    if (sc == 0)
	return;
    gaa_list_free(sc->identity_cred);
    gaa_list_free(sc->authr_cred);
    gaa_list_free(sc->group_membership);
    gaa_list_free(sc->group_non_membership);
    gaa_list_free(sc->uneval_cred);
    free(sc);
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a gaa structure and its components.
 *
 *  @param gaa
 *         input/output gaa structure to free.
 */
void
gaa_free_gaa(gaa_ptr gaa)
{
    if (gaa == 0)
	return;
    gaa_list_free(gaa->mechinfo);
    gaa_l_free_getpolicy_callback(gaa->getpolicy);
    gaa_l_free_matchrights_callback(gaa->matchrights);
    gaa_list_free(gaa->cond_callbacks);
    gaa_list_free(gaa->authinfo);
    gaa_l_x_free_authorization_identity_callback(gaa->authorization_identity_callback);
    free(gaa);
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_c_static
 *
 *  Create a new gaaint_mechinfo structure.
 *
 *  @param minfo
 *         output structure to create
 *  @param mech_type
 *         input mechanism type
 *  @param cred_pull
 *         input cred_pull function
 *  @param cred_eval
 *         input cred_eval function
 *  @param cred_verify
 *         input cred_verify function
 *  @param cred_free
 *         input cred_free function
 *  @param param
 *         input mechinfo parameter (to be passed to cred_pull, cred_eval,
 *         and cred_verify whenever they're called)
 *  @param freeparam
 *         input function to free param when minfo is freed.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *
 *  @note
 *  A mechinfo structure created with this function should be freed with
 *  gaa_l_free_mechinfo().  This will happen automatically if this structure
 *  is part of a gaa structure freed with gaa_free_gaa().
 */
static gaa_status
gaa_l_new_mechinfo(gaaint_mechinfo **	minfo,
		   gaa_string_data	mech_type,
		   gaa_cred_pull_func	cred_pull,
		   gaa_cred_eval_func	cred_eval,
		   gaa_cred_verify_func cred_verify,
		   gaa_freefunc		cred_free,
		   void *		param,
		   gaa_freefunc		freeparam)
{
    gaa_status status = GAA_S_SUCCESS;

    if (minfo == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((*minfo = (gaaint_mechinfo *)malloc(sizeof(gaaint_mechinfo))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*minfo)->mech_type = 0;
    (*minfo)->cred_pull = cred_pull;
    (*minfo)->cred_eval = cred_eval;
    (*minfo)->cred_verify = cred_verify;
    (*minfo)->cred_free = cred_free;
    (*minfo)->param = param;
    (*minfo)->freeparam = freeparam;
    if ((status =
	 gaa_i_new_string(&(*minfo)->mech_type, mech_type)) != GAA_S_SUCCESS)
	goto end;
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_l_free_mechinfo(*minfo);
	*minfo = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Free a gaaint_mechinfo structure.  Called by gaa_free_gaa().
 *
 *  @param minfo
 *         input/output structure to free.
 */
static void
gaa_l_free_mechinfo(gaaint_mechinfo *minfo)
{
    if (minfo == 0)
	return;
    gaa_i_free_simple(minfo->mech_type);
    if (minfo->freeparam && minfo->param)
	minfo->freeparam(minfo->param);
    free(minfo);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Partial ordering function for mechanism info.  Used in gaa_list
 *  routines to ensure that mechinfo entries that have mech_type values
 *  come before any that don't.
 *
 *  @param d1
 *         input mechinfo to compare
 *  @param d2
 *         input mechinfo to compare
 */
static int
gaa_l_order_mechinfo(void *d1,
		     void *d2)
{
    gaaint_mechinfo *m1 = d1;
    gaaint_mechinfo *m2 = d2;

    if (!(m1 && m1->mech_type) && (m2 && m2->mech_type))
	return(-1);
    if (!(m1 && m1->mech_type) && !(m2 && m2->mech_type))
	return(0);
    if ((m1 && m1->mech_type) && !(m2 && m2->mech_type))
	return(1);

    return(strcmp(m1->mech_type, m2->mech_type));
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *
 *  Create and add a mechinfo callback, which consists of routines to
 *  pull additional credentials, evaluate raw credentials, verify
 *  credentials, and free raw credentials.  This callback can either
 *  be associated with a specific mechanism type, or can be installed
 *  as a default to be used when no other mechinfo callback matches
 *  the requested mechanism type.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param mech_type
 *         input mechanism type
 *  @param cred_pull
 *         input cred_pull callback.  Used by gaa_pull_creds() to pull
 *         additional credentials.
 *  @param cred_eval
 *         input cred_eval callback.  Used by gaa_new_cred() to evaluate
 *         a raw credential (translate it into a gaa identity, group, etc.
 *         credential).
 *  @param cred_verify
 *         input cred_verify callback.  Used by gaa_verify_cred() to
 *         verify the raw credential (check that it's still valid).
 *  @param cred_free
 *         input cred_free callback.  Used by gaa_free_cred() to free
 *         the raw credential.
 *  @param param
 *         input mechinfo parameter -- passed as an argument to cred_pull,
 *         cred_eval, and cred_verify whenever they're called.
 *  @param freeparams
 *         input freeparam function -- called to free param when the
 *         gaa pointer is freed.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa or mech_type is null
 */
gaa_status
gaa_add_mech_info(gaa_ptr		gaa,
		  gaa_string_data	mech_type,
		  gaa_cred_pull_func	cred_pull,
		  gaa_cred_eval_func	cred_eval,
		  gaa_cred_verify_func	cred_verify,
		  gaa_freefunc		cred_free,
		  void *		param,
		  gaa_freefunc		freeparams)
{
    gaa_status				status = GAA_S_SUCCESS;
    gaaint_mechinfo *			minfo = 0;

    if (gaa == 0 || mech_type == 0)
    {
	gaacore_set_err("gaa_add_mech_info: called with null gaa or mech_type");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((status = gaa_l_new_mechinfo(&minfo, mech_type, cred_pull,
				       cred_eval, cred_verify, cred_free,
				       param, freeparams)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_i_list_add_entry(gaa->mechinfo, minfo));
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_c_static
 *
 *  Find the mechinfo structure for the specified mech_type (or the default
 *  mechinfo structure).  Used by gaa_new_cred() and gaa_pull_creds().
 *
 *  @param gaa
 *         input gaa pointer
 *  @param mech_type
 *         input mechanism type to search for.
 *
 *  @retval 0
 *          No appropriate mechinfo was found.
 */
static gaaint_mechinfo *
gaa_l_find_mechinfo(gaa_ptr		gaa,
		    gaa_string_data	mech_type)
{
    gaaint_list_entry *			ent;
    gaaint_mechinfo *			minfo;

    if (! (gaa && mech_type))
	return(0);

    for (ent = gaa_list_first(gaa->mechinfo); ent; ent = gaa_list_next(ent))
	if (minfo = (gaaint_mechinfo *)gaa_list_entry_value(ent))
	{
	    if (minfo->mech_type && (strcmp(mech_type, minfo->mech_type) == 0))
		return(minfo);
	}
    return(0);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *
 *  Get policy information for an object.  This function calls the installed
 *  getpolicy callback.
 * 
 *  @param object
 *         input object to get policy for
 *  @param gaa
 *         input gaa pointer
 *  @param policy
 *         output policy to create
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa or policy is null
 *  @retval GAA_S_NO_GETPOLICY_CALLBACK
 *          no getpolicy callback was installed.
 */
gaa_status
gaa_get_object_policy_info(gaa_string_data	object,
			   gaa_ptr		gaa,
			   gaa_policy_ptr *	policy)
{
    if (gaa == 0 || policy == 0)
    {
	gaacore_set_err("gaa_get_object_policy_info: called with null gaa or policy");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if (! (gaa->getpolicy && gaa->getpolicy->func))
	return(GAA_STATUS(GAA_S_NO_GETPOLICY_CALLBACK, 0));
    return(gaa->getpolicy->func(gaa, policy, object, gaa->getpolicy->param));
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_c_static
 *
 *  Create a new gaaint_cond.  Called by gaa_new_condition().
 *
 *  @param ic
 *         output gaaint_cond to create
 *  @param cond
 *         input condition
 *
 *  @retval GAA_S_SUCCESS
 *          success
 */
static gaa_status
gaa_l_new_gaaint_cond(gaaint_cond **ic, gaa_condition *cond)
{
    if (ic == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    *ic = 0;
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Create a new gaaint_request_right.  Called by gaa_new_request_right().
 *
 *  @param i
 *         output gaaint_request_right to create
 *  @param freefunc
 *         input function to free the request_right value when the request_right
 *         is freed.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 */
static gaa_status
gaa_l_new_gaaint_request_right(gaaint_request_right **i,
			       gaa_freefunc	      freefunc)
{
    if (i == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (((*i) =
	 (gaaint_request_right *)malloc(sizeof(gaaint_request_right))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*i)->freeval = freefunc;
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Set values for a gaa_sec_attrb.  Called by gaa_new_sec_attrb().
 *
 *  @param a
 *         input/output sec attrb to initialize
 *  @param type
 *         input attribute type
 *  @param authority
 *         input attribute authority
 *  @param value
 *         input attribute value
 *
 *  @retval GAA_S_SUCCESS
 *          success
 */
static gaa_status
gaa_l_init_sec_attrb(gaa_sec_attrb *	a,
		     gaa_cred_type	type,
		     char *		authority,
		     char *		value)
{
    gaa_status status = GAA_S_SUCCESS;

    if (a == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    a->type = type;
    if ((status = gaa_i_new_string(&a->authority,
				     authority)) != GAA_S_SUCCESS)
	goto end;
    if ((status = gaa_i_new_string(&a->value,
				     value)) != GAA_S_SUCCESS)
	goto end;
 end:
    if (status != GAA_S_SUCCESS)
	gaa_l_clear_sec_attrb(a);
    return(status);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Clear a gaa_sec_attrb.  Called by gaa_free_sec_attrb() and
 *  gaa_l_init_sec_attrb() (on failure).
 *
 *  @param a
 *         input/output sec attrb to clear
 */
static void
gaa_l_clear_sec_attrb(gaa_sec_attrb *a)
{
    if (a) {
	a->type = GAA_UNEVAL;
	gaa_i_free_simple(a->authority);
	a->authority = 0;
	gaa_i_free_simple(a->value);
	a->value = 0;
    }
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *
 *  Locate and call the appropriate callback function to pull additional
 *  credentials for the specified mechanism type (or if no mechanism type
 *  was specified, call the cred_pull callback functions for all mechanism
 *  types), and add the new credentials to the security context.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param sc
 *         input/putput security context
 *  @param which
 *         input what type of credential to pull (identity, group, etc.)
 *  @param mech_type
 *         which mechanism type to pull (or all of them, if 0)
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa or sc is null
 *  @retval GAA_S_UNKNOWN_MECHANISM
 *          no mechinfo callback was found for the specified mechanism type
 *  @retval GAA_S_UNKNOWN_MECHANISM
 *          a mechinfo callback was found for the specified mechanism type,
 *          but it does not include a cred_pull function.
 */
gaa_status
gaa_pull_creds(gaa_ptr			gaa,
	       gaa_sc_ptr		sc,
	       gaa_cred_type		which,
	       gaa_string_data		mech_type)
{
    gaaint_list_entry *			ent;
    gaaint_mechinfo *			minfo;
    gaa_status				status = GAA_S_SUCCESS;

    if (sc == 0 || gaa == 0)
    {
	gaacore_set_err("gaa_pull_creds: called with null sc or gaa");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if (mech_type)
    {
	if (minfo = gaa_l_find_mechinfo(gaa, mech_type))
	{
	    if (minfo->cred_pull == 0)
	    {
		gaacore_set_err("gaa_pull_creds: no cred_pull callback");
		return(GAA_STATUS(GAA_S_NO_CRED_PULL_CALLBACK, 0));
	    }
	    else
		return(minfo->cred_pull(gaa, sc, which, minfo->param));
	}
	else
	{
	    gaacore_set_err("gaa_pull_creds: unknown mechanism type");
	    return(GAA_STATUS(GAA_S_UNKNOWN_MECHANISM, 0));
	}
    }
    else
    {
	for (ent = gaa_list_first(gaa->mechinfo); ent; ent = gaa_list_next(ent))
	    if (minfo = (gaaint_mechinfo *)gaa_list_entry_value(ent))
	    {
		if (minfo->cred_pull)
		    if ((status =
			 minfo->cred_pull(gaa, sc, which,
					  minfo->param)) != GAA_S_SUCCESS)
			return(status);
	    }
    }
    return(status);
}

/**
 *
 *  @ingroup gaa
 *
 *  Create a condition evaluation callback.  If the callback is later
 *  installed with gaa_add_cond_eval_callback(), then it will be used
 *  (when appropriate) by gaa_check_authorization() and
 *  gaa_inquire_policy_info() to evaluate conditions.
 *
 *  @param cb
 *         output callback to create.
 *  @param func
 *         input callback function.
 *  @param params
 *         input callback params -- will be passed to func whenever it's called.
 *  @param freefunc
 *         input function to free params when cb is freed.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          cb or func is null.
 *
 *  @note
 *  A callback created with this function should be freed with
 *  gaa_free_cond_eval_callback().  If a callback is added to a
 *  gaa structure with gaa_add_cond_eval_callback(), it will be
 *  freed automatically when the gaa structure is freed with
 *  gaa_free_gaa().
 */
gaa_status
gaa_new_cond_eval_callback(gaa_cond_eval_callback_ptr *cb,
			   gaa_cond_eval_func	       func,
			   void *		       params,
			   gaa_freefunc		       freefunc)
{
    gaa_status status = GAA_S_SUCCESS;

    if (cb == 0 || func == 0)
    {
	gaacore_set_err("gaa_new_cond_eval_callback: called with null pointer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*cb =
	 (gaaint_cond_eval_callback *)malloc(sizeof(gaaint_cond_eval_callback))) == 0)
    {
	gaacore_set_err("gaa_new_cond_eval_callback: malloc failed");
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    (*cb)->func = func;
    (*cb)->params = params;
    (*cb)->free = freefunc;
    (*cb)->refcount = 0;
    (*cb)->refcount_mutex = 0;
    if ((status = gaacore_mutex_create(&(*cb)->refcount_mutex)) != GAA_S_SUCCESS)
    {
	gaa_free_cond_eval_callback(*cb);
	*cb = 0;
	return(status);
    }
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa
 *
 *  Free a condition evaluation callback structure.
 *
 *  @param cb
 *         input/output structure to free.
 *
 *  @note
 *  If a callback is installed in a gaa structure, then gaa_free()
 *  will call this function to free the callback.
 */
void
gaa_free_cond_eval_callback(gaa_cond_eval_callback_ptr cb)
{
    int freeit = 0;
    if (cb == 0)
	return;
    gaacore_mutex_lock(cb->refcount_mutex);
    if (--cb->refcount <= 0)
	freeit = 1;
    gaacore_mutex_unlock(cb->refcount_mutex);
    if (freeit) {
	if (cb->free && cb->params)
	    cb->free(cb->params);
	gaacore_mutex_destroy(cb->refcount_mutex);
	free(cb);
    }
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_c_static
 *
 *  Create a new condition evaluation entry (which associates a condition
 *  evaluation callback with a type and authority).  Called by
 *  gaa_add_cond_eval_callback().
 *
 *  @param ce
 *         output entry to create
 *  @param type
 *         optional input condition type
 *  @param authority
 *         optional input condition authority
 *  @param cb
 *         input callback pointer
 *  @param is_idcred
 *         input flag -- if nonzero, this condition/authority is considered
 *         by gaa_inquire_policy_info() to be an identity condition.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          ce is null
 */
static gaa_status
gaa_l_new_cond_eval_entry(gaaint_cond_eval_entry **  ce,
			  char *		     type,
			  char *		     authority,
			  gaa_cond_eval_callback_ptr cb,
			  int			     is_idcred)
{
    gaa_status status = GAA_S_SUCCESS;

    if (ce == 0)
    {
	gaacore_set_err("gaa_new_condition_eval_entry: called with null pointer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*ce =
	 (gaaint_cond_eval_entry *)malloc(sizeof(gaaint_cond_eval_entry))) == 0)
    {
	gaacore_set_err("gaa_new_condition_eval_entry: malloc failed");
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    (*ce)->type = 0;
    (*ce)->authority = 0;
    (*ce)->is_idcred = is_idcred;
    if (type)
	if ((status = gaa_i_new_string(&(*ce)->type, type)) != GAA_S_SUCCESS)
	    goto end;
    if (authority)
	if ((status = gaa_i_new_string(&(*ce)->authority,
					 authority)) != GAA_S_SUCCESS)
	goto end;
    gaacore_mutex_lock(cb->refcount_mutex);
    cb->refcount++;
    gaacore_mutex_unlock(cb->refcount_mutex);
    (*ce)->cb = cb;
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_l_free_cond_eval_entry(*ce);
	*ce = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Free a condition evaluation entry and its components.  Called
 *  by gaa_free_gaa().
 *
 *  @param ce
 *  input/output entry to free.
 */
static void
gaa_l_free_cond_eval_entry(gaaint_cond_eval_entry *ce)
{
    if (ce == 0)
	return;
    gaa_i_free_simple(ce->type);
    gaa_i_free_simple(ce->authority);
    gaa_free_cond_eval_callback(ce->cb);
    free(ce);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Provide a partial ordering of cond_eval entries.  Entries with
 *  both type and auth are first, followed by entries with type and no
 *  auth, followed by entries with auth and no type, followed finally by
 *  entries with neither type nor auth.  This is used by gaa_list
 *  functions when adding cond_eval entries to a gaa structure.
 *
 *  @param c1
 *         input entry to compare
 *  @param c2
 *         input entry to compare
 */
static int
gaa_l_order_cond_eval_entry(gaaint_cond_eval_entry *c1,
			    gaaint_cond_eval_entry *c2)
{
    int val;

    if (c1 && ! c2)
	return(-1);
    if (! c1 && ! c2)
	return(0);
    if (c2 && ! c1)
	return(1);

    /* c1 and c2 are nonzero */
    if (c1->type && ! c2->type)
	return(-1);
    if (! c1->type && c2->type)
	return(1);

    /* type is either set for both c1 and c2, or 0 for both c1 and c2 */

    if (c1->authority && ! c2->authority)
	return(-1);
    if (! c1->authority && c2->authority)
	return(1);

    /* auth is either set for both c1 and c2, or 0 for both c1 and c2 */

    if (c1->type)
    {		/* type and auth are both set for both */
	if ((val = strcmp(c1->type, c2->type)) != 0)
	    return(val);
	if (c1->authority)	/* then c2->authority is also nonzero */
	    return(strcmp(c1->authority, c2->authority));
    }
    else if (c1->authority)
	return(strcmp(c1->authority, c2->authority));

    /* At this point the types are either both null, or are equal, and
     * both authorities are null.
     */
    return(0);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *
 *  Add a condition evaluation callback, associated with the specified
 *  type and authority.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param cb
 *         input condition evaluation callback (should be a callback
 *         created with gaa_new_cond_eval_callback()).
 *  @param type
 *         input condition type to associate this callback with
 *  @param authority
 *         input condition authority to associate this callback with
 *  @param is_idcred
 *         input flag -- if nonzero, then gaa_inquire_policy_info()
 *         will interpret conditions with this type and authority to
 *         be identity conditions.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa or cb was null
 *
 *  @note
 *  When gaa_check_authorization() or gaa_inquire_policy_info() searches
 *  for a callback routine for a condition, it first looks for a
 *  callback that was installed with the same type and authority as
 *  the condition.  If no match is found, it searches for a callback
 *  with the same authority and a null type.  If no match is found,
 *  it searches for a callback with the same type and a null authority.
 *  If no match is found, it searches for a callback with null type and
 *  authority.
 */
gaa_status
gaa_add_cond_eval_callback(gaa_ptr		      gaa,
			   gaa_cond_eval_callback_ptr cb,
			   gaa_string_data	      type,
			   gaa_string_data	      authority,
			   int			      is_idcred)
{
    gaa_status				status;
    gaaint_cond_eval_entry *		ce = 0;

    if (gaa == 0 || cb == 0)
    {
	gaacore_set_err("gaa_add_cond_eval_callback: called with null gaa or cb");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((status = gaa_l_new_cond_eval_entry(&ce, type, authority, cb,
					      is_idcred)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_i_list_add_entry(gaa->cond_callbacks, ce));
}

/**
 *
 *  @ingroup gaa
 *
 *  Add credentials of the specified type from the security context
 *  to the credential list.
 *
 *  @param gaa
 *         input gaa pointer (ignored)
 *  @param sc
 *         input security context
 *  @param credlist
 *         input/output credential list
 *  @param which
 *         input desired credential type
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          sc or credlist is 0
 *  @retval GAA_S_UNKNOWN_CRED_TYPE
 *          which is not a recognized credential type.
 */
gaa_status
gaa_getcreds(gaa_ptr			gaa,
	     gaa_sc_ptr			sc,
	     gaa_list_ptr *		credlist,
	     gaa_cred_type		which)
{
    gaa_status				status;
    gaa_list_ptr			slist = 0;

    if (sc == 0 || credlist == 0)
    {
	gaacore_set_err("gaa_getcreds: called with null gaa, sc, or credlist");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*credlist = gaa_i_new_silo(0)) == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    switch(which)
    {
    case GAA_IDENTITY: slist = sc->identity_cred; break;
    case GAA_AUTHORIZED: slist = sc->authr_cred; break;
    case GAA_ATTRIBUTES: slist = sc->attr_cred; break;
    case GAA_GROUP_MEMB: slist = sc->group_membership; break;
    case GAA_GROUP_NON_MEMB: slist = sc->group_non_membership; break;
    case GAA_UNEVAL: slist = sc->uneval_cred; break;
    default: return(GAA_STATUS(GAA_S_UNKNOWN_CRED_TYPE, 0));
    }

    if (slist)
	status = gaa_i_list_merge(*credlist, slist);

    if (status != GAA_S_SUCCESS)
    {
	gaa_list_free(*credlist);
	*credlist = 0;
    }
    return(status);
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_c_static
 * 
 *  Free an internal condition pointer.  Currently does nothing.  Called
 *  by gaa_free_condition().
 *
 *  @param c
 *         input/output gaaint_cond to free.
 */
static void
gaa_l_free_gaaint_cond(gaaint_cond *c)
{
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Provide a partial ordering of authinfo entries.  Ensure that
 *  null authinfo pointers (and authinfo pointers with null authorities)
 *  come after non-null ones.
 *
 *  @param a1
 *         input entry to compare
 *  @param a2
 *         input entry to compare
 */
static int
gaa_l_order_authinfo(gaaint_authinfo *a1, gaaint_authinfo *a2)
{
    if (a1 && ! a2)
	return(-1);
    if (! a1 && a2)
	return(1);
    if (! a1 && ! a2)
	return(0);
    if (a1->authority && *a1->authority && ! (a2->authority && *a2->authority))
	return(-1);
    if (! (a1->authority && *a1->authority) && a2->authority && *a2->authority)
	return(1);
    return(0);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *
 *  Create a new list of requested rights.  Rights can be added to this
 *  list with gaa_add_request_right(), and the result can be used as
 *  an argument to gaa_check_authorization().
 *
 */
gaa_list_ptr
gaa_new_req_rightlist()
{
    return(gaa_i_new_silo((gaa_freefunc)gaa_free_request_right));
}

/**
 *
 *  @ingroup gaa
 *
 *  Add a request right to a list created with gaa_new_req_rightlist().
 * 
 *  @param rightlist
 *         input/output list to add right to
 *  @param right
 *         input right to add.
 */
gaa_status
gaa_add_request_right(gaa_list_ptr	 rightlist,
		      gaa_request_right *right)
{
    return(gaa_i_list_add_entry(rightlist, right));
}

/**
 *
 *  @ingroup gaa
 *
 *  Add an option to a request right.
 *
 *  @param right
 *         input/output right
 *  @param type
 *         input option type
 *  @param authority
 *         input option authority
 *  @param value
 *         input option value
 *  @param freeval
 *         optional input function to free value when the option is
 *         freed (which will happen automatically when right is freed
 *         with gaa_free_request_right().
 *
 *  @retval GAA_S_SUCCES
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          right, t ype, or authority is null.
 */
gaa_status
gaa_add_option(gaa_request_right *	right,
	       gaa_string_data		type,
	       gaa_string_data		authority,
	       void *			value,
	       gaa_freefunc		freeval)
{
    gaa_status				status;
    gaa_request_option *		opt = 0;

    if (right == 0 || type == 0 || authority == 0)
    {
	gaacore_set_err("gaa_add_option: called with null right, type, or authority");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((status = gaa_l_new_option(&opt, type, authority, value,
				     freeval)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_i_list_add_entry(right->options, opt));
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_c_static
 *
 *  Create a new request option.  Called by gaa_add_option().
 *
 *  @param opt
 *         output option to create
 *  @param type
 *         input option type
 *  @param authority
 *         input option authority
 *  @param value
 *         input option value
 *  @param freeval
 *         optional input function to be called to free value when
 *         opt is freed.
 */
static gaa_status
gaa_l_new_option(gaa_request_option **	opt,
		 char *			type,
		 char *			authority,
		 void *			value,
		 gaa_freefunc		freeval)
{
    gaa_status status;

    if (opt == 0 || type == 0 || authority == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    if ((*opt = (gaa_request_option *)malloc(sizeof(gaa_request_option))) == 0)
    {
	gaacore_set_err("gaa_request_option: malloc failed");
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    (*opt)->value = value;
    (*opt)->authority = 0;
    (*opt)->i = 0;
    if ((status = gaa_i_new_string(&(*opt)->type, type)) != GAA_S_SUCCESS)
	goto end;
    if ((status =
	 gaa_i_new_string(&(*opt)->authority, authority)) != GAA_S_SUCCESS)
	goto end;
    if ((status =
	 gaa_l_new_gaaint_request_option(&(*opt)->i,
					 freeval)) != GAA_S_SUCCESS)
	goto end;

 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_l_free_request_option(*opt);
	*opt = 0;
    }
    return(status);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Create a new internal representation of a request option.
 *  Called by gaa_l_new_option().
 *
 *  @param i
 *         output structure to create
 *  @param freefunc
 *         optional input function to be called to free the request
 *         option's value when that option is freed.
 */
static gaa_status
gaa_l_new_gaaint_request_option(gaaint_request_option **i,
				gaa_freefunc		freefunc)
{
    if (i == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (((*i) =
	 (gaaint_request_option *)malloc(sizeof(gaaint_request_option))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*i)->freeval = freefunc;
    return(GAA_S_SUCCESS);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Free a request option and its components.  Called by
 *  gaa_free_request_right()
 *
 *  @param option
 *         input/output option to free
 */
static void
gaa_l_free_request_option(gaa_request_option *option)
{
    if (option == 0)
	return;

    gaa_i_free_simple(option->type);
    gaa_i_free_simple(option->authority);
    if (option->value && option->i && option->i->freeval)
	option->i->freeval(option->value);
    gaa_l_free_gaaint_request_option(option->i);
    free(option);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Free the internal representation of a request option.  Called by
 *  gaa_l_free_request_option().
 *
 *  @param i
 *         input/output option to free
 */
static void
gaa_l_free_gaaint_request_option(gaaint_request_option *i)
{
    gaa_i_free_simple(i);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *
 *  Free a credential and its components.
 *
 *  @param cred
 *         input/output credential to free
 *
 *  @note
 *  This function calls the mechanism-specific cred_free callback function
 *  to free the raw credential.
 * 
 *  This function is automatically called to free any credential that's
 *  part of a security context being freed with gaa_free_sc().
 */
void
gaa_free_cred(gaa_cred *cred)
{
    if (cred == 0)
	return;
    gaa_free_sec_attrb(cred->grantor);
    gaa_free_sec_attrb(cred->principal);
    if (cred->mechinfo && cred->mechinfo->cred_free && cred->mech_spec_cred)
	cred->mechinfo->cred_free(cred->mech_spec_cred);
    /*
     * Do NOT free cred->mechinfo; that should live as long as the
     * security context in which it's defined.
     */
    switch(cred->type)
    {
    case GAA_IDENTITY:
    case GAA_GROUP_MEMB:
    case GAA_GROUP_NON_MEMB:
	gaa_free_identity_info(cred->info.id_info);
	break;
    case GAA_AUTHORIZED:
	gaa_free_authr_info(cred->info.authr_info);
	break;
    case GAA_ATTRIBUTES:
	gaa_free_attribute_info(cred->info.attr_info);
	break;
    default:
	;
    }
    free(cred);
}

/**
 *
 *  @ingroup gaa
 *
 *  Create a new attribute_info structure (to be used as part of a
 *  GAA_ATTRIBUTES credential).  This utility routine is meant to
 *  be used by GAA cred_eval callback functions.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param info
 *         output structure to create
 *  @param type
 *         input attribute type
 *  @param authority
 *         input attribute authority
 *  @param value
 *         input attribute value
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          info, type, authority, or value is null
 * 
 *  @note
 *  A structure created using this routine should be freed with
 *  gaa_free_attribute_info().  This will happen automatically
 *  if this structure is part of a credential freed with
 *  gaa_free_cred().
 */
gaa_status
gaa_new_attribute_info(gaa_ptr		    gaa,
		       gaa_attribute_info **info,
		       gaa_string_data	    type,
		       gaa_string_data	    authority,
		       gaa_string_data	    value)
{
    gaa_status status = GAA_S_SUCCESS;

    if (info == 0 || type == 0 || authority == 0 || value == 0)
    {
	gaacore_set_err("gaa_new_attribute_info: called with null info, type, authority, or value");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*info = (gaa_attribute_info *)malloc(sizeof(gaa_attribute_info))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    (*info)->type = 0;
    (*info)->authority = 0;
    (*info)->value = 0;
    (*info)->conditions = 0;
    if ((status = gaa_i_new_string(&(*info)->type, type)) != GAA_S_SUCCESS)
	goto end;
    if ((status =
	 gaa_i_new_string(&(*info)->authority, authority)) != GAA_S_SUCCESS)
	goto end;
    if ((status = gaa_i_new_string(&(*info)->value, value)) != GAA_S_SUCCESS)
	goto end;

    if (((*info)->conditions =
	 gaa_i_new_silo((gaa_freefunc)gaa_free_condition)) == 0)
    {
	status = GAA_STATUS(GAA_S_INTERNAL_ERR, 0);
	goto end;
    }
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_attribute_info(*info);
	*info = 0;
    }
    return(status);
}

/** gaa_free_attribute_info
 *
 *  @ingroup gaa
 *
 *  Free an attribute_info structure and its components.
 *
 *  @param info
 *         input/output attribute info to free
 *
 *  @note
 *  If a GAA_ATTRIBUTE credential is freed with gaa_free_cred(), this
 *  function will be called automatically to free the associated
 *  attribute info.
 */
void
gaa_free_attribute_info(gaa_attribute_info *info)
{
    if (info == 0)
	return;
    gaa_i_free_simple(info->type);
    gaa_i_free_simple(info->authority);
    gaa_i_free_simple(info->value);
    gaa_list_free(info->conditions);
    free(info);
}

/**
 *
 *  @ingroup gaa
 *
 *  Add a condition to a credential.  This utility function will most
 *  likely be used by GAA cred_eval callback functions.
 *
 *  @param cred
 *         input/output credential to add condition to
 *  @param cond
 *         input condition to add.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          cred or cond is null, or the credential is not one of the
 *          credential types that accepts conditions.
 *
 *  @note
 *  If the credential is freed with gaa_free_cred(), the condition will
 *  be freed at the same time.
 *
 */
gaa_status
gaa_add_cred_condition(gaa_cred	*	cred,
		       gaa_condition *	cond)
{
    if (! (cred && cond))
    {
	gaacore_set_err("gaa_add_identity_condition: called with null cred or condition");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    switch(cred->type)
    {
    case GAA_IDENTITY:
    case GAA_GROUP_MEMB:
    case GAA_GROUP_NON_MEMB:
	if (cred->info.id_info == 0 || cred->info.id_info->conditions == 0)
	{
	    gaacore_set_err("gaa_add_cred_condition: called with null info or condlist");
	    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
	}
	return(gaa_i_list_add_entry(cred->info.id_info->conditions, cond));
    case GAA_ATTRIBUTES:
	if (cred->info.id_info == 0 || cred->info.attr_info->conditions == 0)
	{
	    gaacore_set_err("gaa_add_cred_condition: called with null info or condlist");
	    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
	}
	return(gaa_i_list_add_entry(cred->info.attr_info->conditions, cond));
    default:
	    gaacore_set_err("gaa_add_cred_condition: bad cred tyep");
	    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
}

/**
 *
 *  @ingroup gaa
 *
 *  Add a right to a GAA_AUTHORIZED credential
 *
 *  @param cred
 *         input/output condition to add right to
 *  @param right
 *         input right
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          cred or right is null, or cred is not a GAA_AUTHORIZED credential.
 * 
 *  @note
 *  If cred is freed with gaa_free_cred, the right will be be freed at the
 *  same time.
 */
gaa_status
gaa_add_authr_right(gaa_cred *		cred,
		    gaa_policy_right *	right)
{
    if (! (cred && right))
    {
	gaacore_set_err("gaa_add_authr_right: called with null cred or right");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if (cred->type != GAA_AUTHORIZED)
    {
	gaacore_set_err("gaa_add_authr_right: not an authorization credential");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if (cred->info.authr_info == 0 || cred->info.authr_info->access_rights == 0)
    {
	gaacore_set_err("gaa_add_authr_right: null authr info or right list");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    return(gaa_i_list_add_entry(cred->info.authr_info->access_rights,
				  right));
}

/**
 *
 *  @ingroup gaa
 *
 *  Convert a request right value and authority into a string.  This
 *  function calls the request right val2str callback associated with
 *  the specified authority (or the default request right val2str
 *  callback).
 *
 *  @param gaa
 *         input gaa pointer
 *  @param authority
 *         input authority
 *  @param val
 *         input value
 *  @param buf
 *         input buffer -- should be large enough to hold the resulting
 *         string
 *  @param bsize
 *         input size of buf
 *
 *  @retval <string>
 *          character string representation of the value
 *  @retval 0
 *          No authinfo callback was found, or no val2str function was
 *          supplied by that callback.
 *
 *  @note
 *  This function may or may not result in the result string being
 *  written into buf, depending on the behavior of the callback function.
 */
char *
gaa_request_rightval_string(gaa_ptr	gaa,
			    char *	authority,
			    void *	val,
			    char *	buf,
			    int		bsize)
{
    gaaint_authinfo *ai;

    if ((ai = gaa_i_auth2authinfo(gaa, authority)) == 0 ||
	ai->rvinfo == 0 || ai->rvinfo->val2str == 0)
	return(0);
    return(ai->rvinfo->val2str(authority, val, buf, bsize, ai->params));
}

/**
 *
 *  @ingroup gaa
 *
 *  Convert a policy right value and authority into a string.  This
 *  function calls the policy right val2str callback associated with
 *  the specified authority (or the default policy right val2str
 *  callback).
 *
 *  @param gaa
 *         input gaa pointer
 *  @param authority
 *         input authority
 *  @param val
 *         input value
 *  @param buf
 *         input buffer -- should be large enough to hold the resulting
 *         string
 *  @param bsize
 *         input size of buf
 *
 *  @retval <string>
 *          character string representation of the value
 *  @retval 0
 *          No authinfo callback was found, or no val2str function was
 *          supplied by that callback.
 *
 *  @note
 *  This function may or may not result in the result string being
 *  written into buf, depending on the behavior of the callback function.
 */
char *
gaa_policy_rightval_string(gaa_ptr gaa, char *authority, void *val, char *buf, int bsize)
{
    gaaint_authinfo *ai;

    if ((ai = gaa_i_auth2authinfo(gaa, authority)) == 0 ||
	ai->pvinfo == 0 || ai->pvinfo->val2str == 0)
	return(0);
    return(ai->pvinfo->val2str(authority, val, buf, bsize, ai->params));
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  @ingroup gaa_c_static
 *
 *  Check to see whether two conditions are different.  Called by
 *  gaa_l_checkdiff_condlists() (and ultimately by gaa_l_checkdiff_creds()).
 *
 *  @param c1
 *         input condition to compare
 *  @param c2
 *         input condition to compare
 *
 *  @retval 0
 *          conditions are the same
 *  @retval 1
 *          conditions are different
 */
static int
gaa_l_checkdiff_conditions(gaa_condition *c1,
			   gaa_condition *c2)
{
    if ((c1 && ! c2) || (c2 && ! c1))
	return(1);
    if (! c1 && ! c2)
	return(0);
    if ((c1->type && ! c2->type) || (c2->type && ! c1->type))
	return(1);
    if (! c1->type && ! c2->type)
	return(0);
    if (strcmp(c1->type, c2->type))
	return(1);
    if ((c1->authority && ! c2->authority) || (c2->authority && ! c1->authority))
	return(1);
    if (! c1->authority && ! c2->authority)
	return(0);
    if (strcmp(c1->authority, c2->authority))
	return(1);
    if ((c1->value && ! c2->value) || (c2->value && ! c1->value))
	return(1);
    if (! c1->value && ! c2->value)
	return(0);
    if (strcmp(c1->value, c2->value))
	return(1);
    return(0);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Check to see whether two credentials are different.  Used by
 *  gaa_add_cred() to avoid adding the same credential twice.
 *
 *  @param cred1
 *         input credential to compare
 *  @param cred2
 *         input credential to compare
 *
 *  @retval 0
 *          credentials are the same
 *  @retval 1
 *          credentials are different
 */
static int
gaa_l_checkdiff_creds(void *cred1,
		      void *cred2)
{
    int status;
    gaa_cred *c1 = cred1;
    gaa_cred *c2 = cred2;

    if ((c1 && ! c2) || (c2 && ! c1))
	return(1);
    if (! c1 && ! c2)
	return(0);
    if (c1->type != c2->type)
	return(1);
    if (c1->mech_spec_cred != c2->mech_spec_cred)
	return(1);
    if (c1->mechinfo != c2->mechinfo)
	return(1);
    if (status = gaa_l_checkdiff_sec_attrb(c1->grantor, c2->grantor))
	return(status);
    if (status = gaa_l_checkdiff_sec_attrb(c1->principal, c2->principal))
	return(status);

    switch(c1->type)
    {
    case GAA_IDENTITY:
    case GAA_GROUP_MEMB:
    case GAA_GROUP_NON_MEMB:
	return(gaa_l_checkdiff_id_info(c1->info.id_info, c2->info.id_info));
    case GAA_AUTHORIZED:
	return(gaa_l_checkdiff_authr_info(c1->info.authr_info,
					    c2->info.authr_info));
    case GAA_ATTRIBUTES:
	return(gaa_l_checkdiff_attr_info(c1->info.attr_info,
					    c2->info.attr_info));
    case GAA_UNEVAL:
	return(0);
    default:
	return(1);
    }
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Check to see whether two identity info structures are different.  Called by
 *  gaa_l_checkdiff_creds().
 *
 *  @param i1
 *         input structure to compare
 *  @param i2
 *         input structure to compare
 *
 *  @retval 0
 *          structures are the same
 *  @retval 1
 *          structures are different
 */
static int
gaa_l_checkdiff_id_info(gaa_identity_info *i1,
			gaa_identity_info *i2)
{
    if ((i1 && ! i2) || (i2 && ! i1))
	return(1);
    if (! i1 && ! i2)
	return(0);

    return(gaa_l_checkdiff_condlists(i1->conditions, i2->conditions));
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Check to see whether two sec_attrb structures are different.  Called by
 *  gaa_l_checkdiff_creds().
 *
 *  @param a1
 *         input structure to compare
 *  @param a2
 *         input structure to compare
 *
 *  @retval 0
 *          structures are the same
 *  @retval 1
 *          structures are different
 */
static int
gaa_l_checkdiff_sec_attrb(gaa_sec_attrb *a1,
			  gaa_sec_attrb *a2)
{
    if ((a1 && ! a2) || (a2 && ! a1))
	return(1);
    if (! a1 && ! a2)
	return(0);
    if (a1->type != a2->type)
	return(1);

    if ((a1->authority && ! a2->authority) || (a2->authority && ! a1->authority))
	return(1);
    if (! a1->authority && ! a2->authority)
	return(0);
    if (strcmp(a1->authority, a2->authority))
	return(1);

    if ((a1->value && ! a2->value) || (a2->value && ! a1->value))
	return(1);
    if (! a1->value && ! a2->value)
	return(0);
    if (strcmp(a1->value, a2->value))
	return(1);
    return(0);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Check to see whether two authr_info structures are different.  Called by
 *  gaa_l_checkdiff_creds().
 *
 *  @param a1
 *         input structure to compare
 *  @param a2
 *         input structure to compare
 *
 *  @retval 0
 *          structures are the same
 *  @retval 1
 *          structures are different
 *
 *  @note
 *  In this implementation, this function always returns 1.
 */
static int
gaa_l_checkdiff_authr_info(gaa_authr_info *a1, gaa_authr_info *a2)
{
    return(1);
}

/**
 *
 *  @ingroup gaa_c_static
 *
 *  Check to see whether two attr_info structures are different.  Called by
 *  gaa_l_checkdiff_creds().
 *
 *  @param a1
 *         input structure to compare
 *  @param a2
 *         input structure to compare
 *
 *  @retval 0
 *          structures are the same
 *  @retval 1
 *          structures are different
 */
static int
gaa_l_checkdiff_attr_info(gaa_attribute_info *a1,
			  gaa_attribute_info *a2)
{
    if ((a1 && ! a2) || (a2 && ! a1))
	return(1);
    if (! a1 && ! a2)
	return(0);

    if ((a1->type && ! a2->type) || (a2->type && ! a1->type))
	return(1);
    if (! a1->type && ! a2->type)
	return(0);
    if (strcmp(a1->type, a2->type))
	return(1);

    if ((a1->authority && ! a2->authority) || (a2->authority && ! a1->authority))
	return(1);
    if (! a1->authority && ! a2->authority)
	return(0);
    if (strcmp(a1->authority, a2->authority))
	return(1);

    if ((a1->value && ! a2->value) || (a2->value && ! a1->value))
	return(1);
    if (! a1->value && ! a2->value)
	return(0);
    if (strcmp(a1->value, a2->value))
	return(1);

    return(gaa_l_checkdiff_condlists(a1->conditions, a2->conditions));
}


/**
 *
 *  @ingroup gaa_c_static
 *
 *  Check to see whether two condition lists are different.  Called by
 *  gaa_l_checkdiff_attr_info() and gaa_l_checkdiff_id_info().
 *
 *  @param l1
 *         input list to compare
 *  @param l2
 *         input list to compare
 *
 *  @retval 0
 *          lists are the same
 *  @retval 1
 *          lists are different
 */
static int
gaa_l_checkdiff_condlists(gaa_list_ptr l1,
			  gaa_list_ptr l2)
{
    int status;
    gaa_list_entry_ptr e1, e2;
    gaa_condition *cond1, *cond2;

    for (e1 = gaa_list_first(l1), e2 = gaa_list_first(l2); e1 && e2;
	 e1 = gaa_list_next(e1), e2 = gaa_list_next(e2))
    {
	cond1 = (gaa_condition *)gaa_list_entry_value(e1);
	cond2 = (gaa_condition *)gaa_list_entry_value(e2);
	if (status = gaa_l_checkdiff_conditions(cond1, cond2))
	    return(status);
    }
    if (e1 || e2)
	return(1);
    else
	return(0);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 *
 *  @ingroup gaa
 *
 *  Calls the appropriate mechanism-specific cred_verify function to
 *  verify the credential.  This utility routine will most often be 
 *  used in gaa cond_eval callback functions.
 *
 *  @param cred
 *         input credential to verify
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          cred is null, or no mechanism-specific cred_verify callback
 *          was found.
 */
gaa_status
gaa_verify_cred(gaa_cred *cred)
{
    if (cred == 0 || cred->mechinfo == 0 || cred->mechinfo->cred_verify == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    return(cred->mechinfo->cred_verify(cred, cred->mechinfo->param));
}

/**
 * Returns the parameter for the installed getpolicy plugin.
 *
 * @param gaa
 *        input -- the gaa pointer to inspect
 * @param param
 *        output  -- a pointer to the getpolicy callback's parameter.

 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa is null, or no getpolicy plugin is installed
 */

extern gaa_status
gaa_x_get_getpolicy_param(gaa_ptr gaa, void **param)
{
    if (gaa == 0 || gaa->getpolicy == 0)
	return(GAA_S_INVALID_ARG);
    *param = gaa->getpolicy->param;
    return(GAA_S_SUCCESS);
}

extern gaa_status
gaa_x_get_get_authorization_identity_param(gaa_ptr gaa, void **param)
{
    if (gaa == 0 || gaa->authorization_identity_callback == 0)
	return(GAA_S_INVALID_ARG);
    *param = gaa->authorization_identity_callback->param;
    return(GAA_S_SUCCESS);
}


/**
 * gaa_x_get_authorization_identity
 *
 * This is a hack and should go away.  The problem is that some applications
 * need to do a setuid() outside of GAA.
 *
 * @param gaa
 *        input -- the gaa pointer to inspect
 * @param identity_ptr
 *        output  -- the presumed external identity.  This will be malloc'd
 *        and should be freed by the caller.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          gaa or identity_ptr is null
 */

extern gaa_status
gaa_x_get_authorization_identity(gaa_ptr gaa, char **identity_ptr)
{
    if (gaa == 0 || identity_ptr == 0)
	return(GAA_S_INVALID_ARG);
    *identity_ptr = 0;
    if (gaa->authorization_identity_callback == 0)
    {
	return(GAA_S_SUCCESS);
    }
    if (gaa->authorization_identity_callback->func == 0)
    {
	return(GAA_S_SUCCESS);
    }
    return(gaa->authorization_identity_callback->func(
	       gaa,
	       identity_ptr,
	       gaa->authorization_identity_callback->param));
}
