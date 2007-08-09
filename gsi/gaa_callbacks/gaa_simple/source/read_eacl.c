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

/**
 *
 * @ingroup gaa_simple
 *
 * Create a GAA policy from an extended access control list.  This function
 * is meant to be used as a GAA getpolicy callback function.
 *
 * @param gaa
 *        input gaa pointer
 * @param policy
 *        output policy pointer
 * @param object
 *        input name of the policy file (within the policy directory) to read.
 * @param params
 *        input (char **) pointer to name of policy directory.
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
gaa_simple_read_eacl(gaa_ptr		gaa,
		    gaa_policy **	policy,
		    gaa_string_data	object,
		    void *		params)
{
    gaa_status				status = GAA_S_SUCCESS;
    FILE *				infile = 0;
    char				buf[2048];
    char				ebuf[2048];
    char *				type = 0;
    char *				auth = 0;
    char *				val = 0;
    gaa_right_type			rtype;
    static int				i = 0;
    gaa_policy_right *			right = 0;
    gaa_condition *			cond = 0;
    int					pri = -1;
    int					num = -1;
    char *				s;
    char *				next = 0;
    char *				dirname = 0;

    if (gaa == 0 || policy == 0 || object == 0 || params == 0)
    {
	gaa_set_callback_err("gaa_simple_read_eacl: called with null gaa, policy, or eacldir pointer");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    if ((dirname = *(char **)params) == 0)
    {
	gaa_set_callback_err("gaa_simple_read_eacl: called with null eacldir");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    if (strlen(dirname) + strlen(object) + 2 >= sizeof(buf))
    {
	gaa_set_callback_err("gaa_simple_read_eacl: object name too long");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    sprintf(buf, "%s/%s", dirname, object);
    if ((infile = fopen(buf, "r")) == 0)
    {
	snprintf(ebuf, sizeof(ebuf), "gaa_simple_read_eacl: can't open %s\n",
		 buf);
	gaa_set_callback_err(ebuf);
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }

    if ((status = gaa_new_policy(policy)) != GAA_S_SUCCESS)
	return(status);

    while (fgets(buf, sizeof(buf), infile))
    {
	i++;
	type = buf;
	auth = val = 0;

	if ((type = gaautil_gettok(buf, &next)) == 0)
	    continue;		/* blank line */
	if (*type == '#')
	    continue;		/* comment */

	if ((auth = gaautil_gettok(next, &next)) && next)
	{
	    /* set value to auth, then skip to first char after auth token */
	    val = next;
	    while (isspace(*val))
		val++;
	    if (*val == '\0')
	    {
		/* no val token after whitespace after auth */
		val = 0;
	    } else {
		if (*val == '\"') {
		    val++;
		    for (s = val; *s != '\0'; s++)
			if (*s == '\"')
			    break;
		    if (*s == '\"')
			*s = '\0';
		    else
		    {
			snprintf(ebuf, sizeof(ebuf),
				 "gaa_simple_read_eacl: bad token (unbalanced quote) on line %d\n", i);
			gaa_set_callback_err(ebuf);
			continue;
		    }
		}
		else
		    for (s = val; *s != '\0'; s++)
			if (isspace(*s))
			{
			    *s = '\0';
			    break;
			}
	    }
	}
	if (strcasecmp(type, "pos_access_right") == 0)
	{
	    if (right) {
		if ((status = gaa_add_policy_entry((*policy), right, pri,
						   num)) != GAA_S_SUCCESS)
		{
		    snprintf(ebuf, sizeof(ebuf),
			     "gaa_simple_read_eacl: failed to add right at line %d: %s\n",
			     i, gaa_x_majstat_str(status));
		    gaa_set_callback_err(ebuf);
		    goto end;
		}
		right = 0;
	    }
	    if (auth == 0 || val == 0)
	    {
		snprintf(ebuf, sizeof(ebuf),
			 "gaa_simple_read_eacl: missing auth or val for right at line %d", i);
		gaa_set_callback_err(ebuf);
		continue;
	    }
	    gaa_new_policy_right(gaa, &right, gaa_pos_access_right, auth, val);
#ifdef TEST_ORDER
	    pri = num = -1;
#else /* TEST_ORDER */
	    num++;
#endif /* TEST_ORDER */
	}
	else if (strcasecmp(type, "neg_access_right") == 0)
	{
	    if (right)
	    {
		if ((status = gaa_add_policy_entry((*policy), right, pri,
						   num)) != GAA_S_SUCCESS)
		{
		    snprintf(ebuf, sizeof(ebuf),
			     "gaa_simple_read_eacl: failed to add right at line %d: %s\n",
			     i, gaa_x_majstat_str(status));
		    gaa_set_callback_err(ebuf);
		    goto end;
		}
		right = 0;
	    }
	    if (auth == 0 || val == 0)
	    {
		snprintf(ebuf, sizeof(ebuf),
			 "gaa_simple_read_eacl: missing auth or val for right at line %d", i);
		gaa_set_callback_err(ebuf);
		continue;
	    }
	    gaa_new_policy_right(gaa, &right, gaa_neg_access_right, auth, val);
#ifdef TEST_ORDER
	    pri = num = -1;
#else /* TEST_ORDER */
	    num++;
#endif /* TEST_ORDER */
	}
#ifdef TEST_ORDER
	else if (strcasecmp(type, "order") == 0)
	{
	    if (auth == 0 || val == 0)
	    {
		snprintf(ebuf, sizeof(ebuf), "missing pri or num for order at line %d", i);
		gaa_set_callback_err(ebuf);
		continue;
	    }
	    pri = atoi(auth);
	    num = atoi(val);
	}
#endif /* TEST_ORDER */
	else if (right == 0)
	{
	    snprintf(ebuf, sizeof(ebuf),
		     "gaa_simple_read_eacl: conditions come before rights on line %d\n", i);
	    gaa_set_callback_err(ebuf);
	    status = GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE, 0);
	    goto end;
	}
	else if (type)
	{
	    if ((status = gaa_new_condition(&cond, type, auth, val)) != GAA_S_SUCCESS)
		goto end;
	    if ((status = gaa_add_condition(right, cond)) != GAA_S_SUCCESS)
		goto end;
	}
    }
    if (right)
	if ((status = gaa_add_policy_entry((*policy), right, pri,
					   num)) != GAA_S_SUCCESS)
	{
	    snprintf(ebuf, sizeof(ebuf),
		     "gaa_simple_read_eacl: failed to add right at line %d: %s\n", i,
		     gaa_x_majstat_str(status));
	    gaa_set_callback_err(ebuf);
	    goto end;
	}
 end:
    if (infile)
	fclose(infile);
    return(status);
}
