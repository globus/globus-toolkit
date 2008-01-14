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
#include "gaa_plugin.h"
#include <string.h>

/** gaa_plugin_default_matchrights()
 *
 * @ingroup gaa_plugin
 *
 * Finds the subset of a policy that matches a request right, and adds
 * that subset to an output policy.  This function is intended to be used
 * as a GAA matchrights callback function.
 *
 * @param gaa
 *        input gaa pointer
 * @param inpolicy
 *        input policy
 * @param right
 *        input request right
 * @param outpolicy
 *        output policy.
 * @param params
 *        This argument is ignored.
 * @retval GAA_S_SUCCESS
 *         Success
 * @retval GAA_S_INVALID_ARGS
 *         One of gaa, inpolicy, right, or outpolicy was null.
 */
gaa_status
gaa_plugin_default_matchrights(gaa_ptr		gaa,
			       gaa_policy *	inpolicy,
			       gaa_request_right *right,
			       gaa_policy *	outpolicy,
			       void *		params)
{
    gaa_list_entry_ptr			ent;
    gaa_policy_entry *			pent;
    struct authval *			pav;
    struct authval *			rav;
    int					status = GAA_S_SUCCESS;
    int					match;

    if (gaa == 0 || inpolicy == 0 || right == 0 || outpolicy == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    for (ent = gaa_list_first(inpolicy->entries); ent; ent = gaa_list_next(ent))
    {
	pent = (gaa_policy_entry *)gaa_list_entry_value(ent);
	if ((status = gaa_match_rights(gaa, right, pent->right,
				       &match)) != GAA_S_SUCCESS)
	    break;
	if (match)
	    if ((status = gaa_add_policy_entry(outpolicy, pent->right,
					       pent->priority,
					       pent->num)) != GAA_S_SUCCESS)
		break;
    }
    if (status != GAA_S_SUCCESS)
	gaa_clear_policy(outpolicy);
    return(status);
}

/** gaa_plugin_default_new_rval()
 *
 * @ingroup gaa_plugin
 *
 * Translate a character string into a request right value that will be
 * understood by gaa_plugin_default_matchrights().  This function is meant to be
 * used as a newval callback in GAA.
 *
 * \note
 * This function allocates space for val; that space should eventually
 * be freed using the standard C free() function.  If this function is
 * used as a newval callback in GAA, then free() should be installed
 * as the corresponding freeval callback.
 *
 * @param val
 *        output value pointer.
 * @param authority
 *        This argument is ignored.
 * @param valstr
 *        input value string
 * @param params
 *        This argument is ignored.
 * @retval GAA_S_SUCCESS
 *         Success
 * @retval GAA_S_INVALID_ARG
 *         One of val, authority, or valstr is null
 */
gaa_status
gaa_plugin_default_new_rval(void **val, char *authority, char *valstr, void *params)
{
    char **v = (char **)val;

    if (val == 0 || authority == 0 || valstr == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    if (*v = strdup(valstr))
	return(GAA_S_SUCCESS);
    else
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
}

/** gaa_plugin_default_new_pval()
 *
 * @ingroup gaa_plugin
 *
 * Translate a character string into a policy right value that will be
 * understood by gaa_plugin_default_matchrights().  The character string is
 * interpreted as a comma-separated list of rights.
 * This function is meant to be used as a newval callback in GAA.
 *
 * \note
 * This function allocates space for val; that space should eventually
 * be freed using the gaa_plugin_default_free_pval().  If this function is
 * used as a newval callback in GAA, then gaa_plugin_default_free_pval() should
 * be installed as the corresponding freeval callback.
 *
 * @param val
 *        output value pointer.
 * @param authority
 *        This argument is ignored.
 * @param valstr
 *        input value string
 * @param params
 *        This argument is ignored.
 * @retval GAA_S_SUCCESS
 *         Success
 * @retval GAA_S_INVALID_ARG
 *         One of val, authority, or valstr is null
 */
gaa_status
gaa_plugin_default_new_pval(void **		val,
		   char *		authority,
		   char *		valstr,
		   void *		params)
{
    char **				v = (char **)val;
    char **				newval;
    int					vsize = 0;
    int					vstep = 16;
    char *				start;
    char *				end;
    int					i;
    gaa_status				status = GAA_S_SUCCESS;
    char *				s1;
    char *				s2;

    if (val == 0 || authority == 0 || valstr == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((newval = (char **)malloc((vsize = vstep) * sizeof(char *))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));

    for (i = 0, start = valstr; *start; i++)
    {
	for (end = start; *end != '\0' && *end != ','; end++)
	    ;
	if ((i >= vsize-1) &&
	    ((newval = (char **)realloc(newval,
					(vsize += vstep) * sizeof(char *))) == 0))
	{
	    newval[i] = 0;
	    status = GAA_STATUS(GAA_S_SYSTEM_ERR, 0);
	    goto end;
	}
	if ((newval[i] = malloc(end - start + 1)) == 0)
	{
	    newval[i] = 0;
	    status = GAA_STATUS(GAA_S_SYSTEM_ERR, 0);
	    goto end;
	}
	for (s1 = newval[i], s2 = start; s2 < end; s1++, s2++)
	    *s1 = *s2;
	*s1 = '\0';
	start = (*end == '\0' ? end : (end+1));
    }
    newval[i] = 0;

 end:
    if (status == GAA_S_SUCCESS)
	*val = (void *)newval;
    else
    {
	gaa_plugin_default_free_pval(newval);
	*val = 0;
    }
    return(status);
}

/** gaa_plugin_default_copy_pval()
 *
 * @ingroup gaa_plugin
 *
 * Create a copy of a policy right value.  This function assumes that the old
 * policy value was created using gaa_plugin_default_new_pval(), and is intended
 * to be used as a copyval callback in GAA.
 *
 * \note
 * This function allocates space for val; that space should eventually
 * be freed using the gaa_plugin_default_free_pval().  If this function is
 * used as a newval callback in GAA, then gaa_plugin_default_free_pval() should
 * be installed as the corresponding freeval callback.
 *
 * @param newval
 *        output value pointer.
 * @param authority
 *        This argument is ignored.
 * @param oldval
 *        input value to copy
 * @param params
 *        This argument is ignored.
 * @retval GAA_S_SUCCESS
 *         Success
 * @retval GAA_S_INVALID_ARG
 *         One of newval, authority, or oldval is null
 */
gaa_status
gaa_plugin_default_copy_pval(void **		newval,
		    char *		authority,
		    void *		oldval,
		    void *		params)
{
    char **				oldv = oldval;
    char **				newv = 0;
    int					nvals;
    int					i;
    gaa_status				status = GAA_S_SUCCESS;

    if (newval == 0 || oldval == 0 || authority == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    for (nvals = 0; oldv[nvals]; nvals++)
	;
    if ((newv = (char **)malloc((nvals+1) * sizeof(char *))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    for (i = 0; i < nvals; i++)
	if ((newv[i] = strdup(oldv[i])) == 0) {
	    status = GAA_STATUS(GAA_S_SYSTEM_ERR, 0);
	    goto end;
	}
    newv[i] = 0;
 end:
    if (status == GAA_S_SUCCESS)
	*newval = newv;
    else
	gaa_plugin_default_free_pval(newv);
    return(status);
}

/** gaa_plugin_default_copy_rval()
 *
 * @ingroup gaa_plugin
 *
 * Create a copy of a request right value.  This function assumes that the old
 * policy value was created using gaa_plugin_default_new_rval(), and is intended
 * to be used as a copyval callback in GAA.
 *
 * \note
 * This function allocates space for newval; that space should eventually
 * be freed using the standard C free() function.  If this function is
 * used as a copyval callback in GAA, then free() should be installed
 * as the corresponding freeval callback.
 *
 * @param newval
 *        output value pointer.
 * @param authority
 *        This argument is ignored.
 * @param oldval
 *        input value to copy
 * @param params
 *        This argument is ignored.
 * @retval GAA_S_SUCCESS
 *         Success
 * @retval GAA_S_INVALID_ARG
 *         One of newval, authority, or oldval is null
 */
gaa_status
gaa_plugin_default_copy_rval(void **		newval,
		    char *		authority,
		    void *		oldval,
		    void *		params)
{
    char *oldv = oldval;

    if (newval == 0 || oldval == 0 || authority == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    return(gaa_plugin_default_new_rval(newval, authority, oldv, params));
}

/** gaa_plugin_default_valmatch()
 *
 * @ingroup gaa_plugin
 *
 * Determines whether a request right value (created with
 * gaa_plugin_default_new_rval() or gaa_plugin_default_copy_rval())
 * matches a policy right value (created with gaa_plugin_default_new_pval()
 * or gaa_plugin_default_copy_pval()); in other words, checks to see
 * whether the request right is in the list of rights that comprise the
 * policy right.
 * This function is intended to be used as a valmatch callback in GAA.
 *
 * @param authority
 *        This argument is ignored.
 * @param rval
 *        input request right value
 * @param pval
 *        input policy right value
 * @param params
 *        This argument is ignored.
 * @retval 1
 *         The request right value matches the policy right value
 * @retval 0
 *         The request right value does not match the policy right value
 */
gaa_status
gaa_plugin_default_valmatch(char *		authority,
		   void *		rval,
		   void *		pval,
		   void *		params)
{
    char *				rv = rval;
    char **				pv = pval;
    int					i;

    if (rv == 0 && pv == 0)
	return(1);
    if (rv == 0 || pv == 0)
	return(0);
    for (i = 0; pv[i]; i++)
	if (strcmp(rv, pv[i]) == 0)
	    return(1);
    return(0);
}

/** gaa_plugin_default_rval2str()
 *
 * @ingroup gaa_plugin
 *
 * Converts a request right value (created with gaa_plugin_default_new_rval()
 * or gaa_plugin_default_copy_rval()) into a string.
 * This function is meant to be used as a val2str callback in GAA.
 *
 * @param authority
 *        This argument is ignored.
 * @param val
 *        input value
 * @param buf
 *        output character buffer
 * @param bsize
 *        input size of buf
 * @param params
 *        This argument is ignored.
 * @retval
 *         The value, represented as a string.
 */
char *
gaa_plugin_default_rval2str(char *		authority,
		  void *		val,
		  char *		buf,
		  int			bsize,
		  void *		params)
{
    return((char *)val);
}

/** gaa_plugin_default_pval2str()
 *
 * @ingroup gaa_plugin
 *
 * Converts a policy right value (created with gaa_plugin_default_new_pval() or
 * gaa_plugin_default_copy_pval()) into a string (a comma-separated list
 * of values).
 * This function is meant to be used as a val2str callback in GAA.
 *
 * @param authority
 *        This argument is ignored.
 * @param val
 *        input value
 * @param buf
 *        output character buffer
 * @param bsize
 *        input size of buf
 * @param params
 *        This argument is ignored.
 * @retval
 *         The value, represented as a string.
 */
char *
gaa_plugin_default_pval2str(char *		authority,
		  void *		val,
		  char *		buf,
		  int			bsize,
		  void *		params)
{
    char **				vlist = (char **)val;
    char *				s;
    int					len;
    int					i;

    if (val == 0 || buf == 0 || bsize < 1)
	return(0);
    for (s = buf, i = 0; vlist[i]; i++) {
	if (s != buf) {
	    *s++ = ',';
	    bsize--;
	}
	strncpy(s, vlist[i], bsize);
	len = strlen(s);
	s += len;
	if ((bsize -= len) < 2)
	    break;
    }
    *s = '\0';
    return(buf);
}

/** gaa_plugin_default_free_pval()
 *
 * @ingroup gaa_plugin
 *   
 * Frees a policy value created with gaa_plugin_default_new_pval() or
 * gaa_plugin_default_copy_pval().  Suitable for use as a freeval callback
 * in GAA.
 *
 * @param pval
 *        policy value to free
 */
void
gaa_plugin_default_free_pval(void *		pval)
{
    char **				vlist = (char **)pval;
    int					i;

    if (pval) {
	for (i = 0; vlist[i]; i++)
	    free(vlist[i]);
	free(pval);
    }
}
