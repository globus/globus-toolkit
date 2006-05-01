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

/** @defgroup gaa_authinfo_static "static routines from gaa_core/gaa_authinfo.c"
 */

static gaa_status
gaa_l_new_authinfo(gaaint_authinfo **ai, char *authority,
		   gaa_valinfo_ptr pvinfo, gaa_valinfo_ptr rvinfo,
		   gaa_valmatch_func match, void *params,
		   gaa_freefunc freeparams);


/** gaa_add_authinfo()
 *
 *  @ingroup gaa
 *
 *  Add an authinfo callback.  This callback will be used to interpret
 *  and compare policy right values.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param authority
 *         optional input authority that this callback applies to.  If
 *         authority is null, this is considered the default authinfo
 *         callback for any authority that does not have a specific
 *         authinfo callback.
 *  @param pvinfo
 *         input valinfo callback (see gaa_new_valinfo()) to be used for
 *         policy rights with this authority.
 *  @param rvinfo
 *         input valinfo callback (see gaa_new_valinfo()) to be used for
 *         request rights with this authority.
 *  @param match
 *         input callback function that takes a policy right and a
 *         request right, and determines whether the values match.
 *  @param params
 *         optional input callback parameters passed to pvinfo->copyval,
 *         rvinfo->copyval, pvinfo->newval, rvinfo->newval, pvinfo->val2str,
 *         rvinfo->val2str, and match whenever they're called.
 *  @param freeparams
 *         optional input function to free params when the gaa structure
 *         is freed.
 */
gaa_status
gaa_add_authinfo(gaa_ptr		gaa,
		 char *			authority,
		 gaa_valinfo_ptr	pvinfo,
		 gaa_valinfo_ptr	rvinfo,
		 gaa_valmatch_func	match,
		 void *			params,
		 gaa_freefunc		freeparams)
{
    gaaint_authinfo *			ai;
    gaa_status				status;

    if (gaa == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((status = gaa_l_new_authinfo(&ai, authority, pvinfo, rvinfo,
				       match, params,
				       freeparams)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_i_list_add_entry(gaa->authinfo, ai)) != GAA_S_SUCCESS)
	gaa_i_free_authinfo(ai);
    return(status);
}

/** gaa_i_find_authinfo()
 *
 *  @ingroup gaa_internal
 *
 *  Find authinfo associated with a policy right
 *
 *  @param gaa
 *         input gaa pointer
 *  @param right
 *         input policy right
 */
gaaint_authinfo *
gaa_i_find_authinfo(gaa_ptr		gaa,
		    gaa_policy_right *	right)
{
    if (right == 0)
	return(0);
    return(gaa_i_auth2authinfo(gaa, right->authority));
}

/** gaa_i_auth2authinfo()
 *
 *  @ingroup gaa_internal
 *
 *  Find the authinfo callback associated with the specified authority.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param authority
 *         input authority
 */
gaaint_authinfo *
gaa_i_auth2authinfo(gaa_ptr		gaa,
		    char *		authority)
{
    gaa_list_entry_ptr			ent;
    gaaint_authinfo *			ai;

    if (gaa == 0 || authority == 0)
	return(0);
    for (ent = gaa_list_first(gaa->authinfo); ent; ent = gaa_list_next(ent))
	if ((ai = (gaaint_authinfo *)gaa_list_entry_value(ent)) &&
	    ((ai->authority == 0) || (strcmp(ai->authority, authority) == 0)))
	    return(ai);
    return(0);
}

/** gaa_i_free_authinfo()
 *
 *  @ingroup gaa_internal
 *
 *  Free an authinfo structure.
 *
 *  @param ai
 *         input/output structure to free
 *
 *  @note
 *  This function is called by gaa_free_gaa() to free all authinfo
 *  callbacks associated with a gaa pointer.
 */
void
gaa_i_free_authinfo(gaaint_authinfo *ai)
{
    if (ai == 0)
	return;
    gaa_free_valinfo(ai->pvinfo);
    gaa_free_valinfo(ai->rvinfo);
    gaa_i_free_simple(ai->authority);
    free(ai);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_new_authinfo()
 *
 *  @ingroup gaa_authinfo_static
 *
 *  Create a new authinfo structure.
 *
 *  @param ai
 *         output structure to create
 *  @param authority
 *         input authority
 *  @param pvinfo
 *         input policy right valinfo
 *  @param rvinfo
 *         input request right valinfo
 *  @param match
 *         input callback function to match request rights to policy rights.
 *  @param params
 *         input callback param (to be passed to callback functions)
 *  @param freefunc
 *         input callback function to free params
 *
 *  @note
 *  See gaa_add_authinfo() for more details about the arguments to this
 *  function.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_new_authinfo(gaaint_authinfo **	ai,
		   char *		authority,
		   gaa_valinfo_ptr	pvinfo,
		   gaa_valinfo_ptr	rvinfo,
		   gaa_valmatch_func	match,
		   void *		params,
		   gaa_freefunc		freeparams)
{
    gaa_status status = GAA_S_SUCCESS;

    if (ai == 0 || match == 0 || pvinfo == 0 || rvinfo == 0)
    {
	gaacore_set_err("gaa_new_authinfo: called with null authinfo, match, pvinfo, or rvinfo");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*ai = (gaaint_authinfo *)malloc(sizeof(gaaint_authinfo))) == 0)
    {
	gaacore_set_err("gaa_authinfo: malloc failed");
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    (*ai)->pvinfo = pvinfo;
    (*ai)->rvinfo = rvinfo;
    (*ai)->match = match;
    (*ai)->params = params;
    (*ai)->freeparams = freeparams;
    (*ai)->authority = 0;
    if (authority &&
	((status =
	  gaa_i_new_string(&(*ai)->authority, authority)) != GAA_S_SUCCESS))
	goto end;
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_i_free_authinfo(*ai);
	*ai = 0;
    }
    return(status);
}


/** gaa_new_valinfo()
 *
 *  @ingroup gaa
 *
 *  Allocate a new valinfo structure and fill it in with the specified
 *  callback functions.
 *
 *  @param valinfo
 *         output valinfo pointer
 *  @param copyval
 *         input copyval callback function.  This callback is used by
 *         gaa_check_authorization() and gaa_inquire_policy_info() to
 *         create new policy entries.
 *  @param newval
 *         optional input newval callback function.  This callback is used by
 *         gaa_new_policy_right() and gaa_new_request_right() to translate
 *         a string value into the appropriate internal representation.
 *  @param freeval
 *         optional input freeval callback function.  This callback is used by
 *         gaa_free_request_right() and gaa_free_policy_right() to free
 *         right values.
 *  @param val2str
 *         optional input val2str callback function.  This callback is
 *         used by gaa_request_rightval_string() and
 *         gaa_policy_rightval_string() to translate a right value into
 *         a string.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          valinfo or copyval is null.
 */
gaa_status
gaa_new_valinfo(gaa_valinfo_ptr *	valinfo,
		gaa_copyval_func	copyval,
		gaa_string2val_func	newval,
		gaa_freefunc		freeval,
		gaa_val2string_func	val2str)
{
    if (valinfo == 0 || copyval == 0)
    {
	gaacore_set_err("gaa_new_valinfo: called with null valinfo or copyval");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((*valinfo = (gaaint_valinfo *)malloc(sizeof(gaaint_valinfo))) == 0)
    {
	gaacore_set_err("gaa_new_valinfo: malloc failed");
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }

    (*valinfo)->newval = newval;
    (*valinfo)->copyval = copyval;
    (*valinfo)->freeval = freeval;
    (*valinfo)->val2str = val2str;
    return(GAA_S_SUCCESS);
}

/** gaa_free_valinfo
 *
 *  @ingroup gaa
 *
 *  Free a valinfo structure and its components.
 *
 *  @param valinfo
 *         input/output structure to free
 *
 *  @note
 *  If a valinfo structure is part of an authinfo structure, then
 *  this function will be called automatically to free that
 *  valinfo structure when the authinfo structure is freed.
 */
void
gaa_free_valinfo(gaa_valinfo_ptr valinfo)
{
    gaa_i_free_simple(valinfo);
}

/** gaacore_has_matchrights_callback()
 *
 * @ingroup gaa_core
 *
 * Check whether a matchrights callback has been set for a gaa pointer.
 *
 * @param gaa
 *        input gaa to check.
 *
 * @retval 1
 *        a matchrights callback has been set.
 * @retval 0
 *        a matchrights callback has not been set.
 */
gaacore_has_matchrights_callback(gaa_ptr gaa)
{
    if (gaa == 0)
	return(-1);
    return(gaa->matchrights != 0);
}

/** gaacore_has_default_authinfo_callback()
 *
 * @ingroup gaa_core
 *
 * Check whether a default authinfo callback has been set for a gaa pointer.
 *
 * @param gaa
 *        input gaa to check.
 *
 * @retval 1
 *        a default authinfo callback has been set.
 * @retval 0
 *        a default authinfo callback has not been set.
 */
gaacore_has_default_authinfo_callback(gaa_ptr gaa)
{
    gaa_list_entry_ptr		ent;
    gaaint_authinfo *		ai;
 
    if (gaa == 0)
	return(-1);
    for (ent = gaa_list_first(gaa->authinfo); ent; ent = gaa_list_next(ent))
	if ((ai = (gaaint_authinfo *)gaa_list_entry_value(ent)) &&
	    (ai->authority == 0))
	    return(1);
    return(0);
}
