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
#include "gaa_core.h"
#include "gaa_debug.h"

#define BSIZE 2048

static char *gaadebug_id_info_string(gaa_identity_info *id, char *out, int osize);
static char *gaadebug_authr_info_string(gaa_ptr gaa, gaa_authr_info *a, char *out, int osize);
static char *gaadebug_attr_info_string(gaa_attribute_info *a, char *out, int osize);

#ifdef USE_GAA_PRIVATE
static char *gaadebug_cond_eval_entry_string(char *out, int osize, gaaint_cond_eval_entry *ce);
#endif /* USE_GAA_PRIVATE */

char *
gaadebug_condstr_r(gaa_condition *cond, char *buf, int bsize)
{
    char *s;
    if (cond)
	snprintf(buf, bsize, "type=%s, auth=%s, val=\"%s\", status=%s",
		 (cond->type ? cond->type : ""),
		 (cond->authority ? cond->authority : ""),
		 (cond->value ? cond->value : ""),
		 gaacore_condstat2str(cond->status));
    else {
	strncpy(buf, "(null condition)", bsize);
	buf[bsize] = '\0';
    }
    return(buf);
}

char *
gaadebug_request_right_string(gaa_ptr gaa, char *out, int osize, gaa_request_right *right)
{
    void *cent;
    char *s;
    int len;

    if (out == 0)
	return(0);
    if (right == 0) {
	snprintf(out, osize, "Request right: (null)\n");
	return(out);
    }
    s = out;
    snprintf(s, osize, "Requested Right: %s ", right->authority);
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    gaa_request_rightval_string(gaa, right->authority, right->value, s, osize);
    return(out);
}

char *
gaadebug_policy_right_string(gaa_ptr gaa, char *out, int osize, gaa_policy_right *right)
{
    gaa_list_entry_ptr cent;
    char *s;
    int len;

    if (out == 0)
	return(out);
    if (right == 0) {
	snprintf(out, osize, "Policy Right: (null)\n");
	return(out);
    }

    s = out;
    snprintf(s, osize, "%s %s ", gaacore_right_type_to_string(right->type),
	     right->authority);

    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    gaa_policy_rightval_string(gaa, right->authority,
			       right->value, s, osize);
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);

    for (cent = gaa_list_first(right->conditions); cent; cent = gaa_list_next(cent)) {
	snprintf(s, osize, "\n\t");
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
	gaadebug_condstr_r((gaa_condition *)gaa_list_entry_value(cent), s,
			   osize);
	len = strlen(s);
	s += len;
	osize -= len;
	if (osize < 2)
	    return(out);
    }
    sprintf(s, "\n");
    return(out);
}

char *
gaadebug_policy_entry_string(gaa_ptr gaa, char *out, int osize, gaa_policy_entry *ent)
{
    char buf[BSIZE];
    int len;
    char *s;

    if (out == 0)
	return(0);
    if (ent == 0) {
	snprintf(out, osize, "(null entry)\n");
	return(out);
    }
    s = out;
    snprintf(s, osize, "\nEntry: pri %d num %d ", ent->priority, ent->num);
    len = strlen(s);
    s += len;
    osize -= len;
    if (osize < 2)
	return(out);
    gaadebug_policy_right_string(gaa, s, osize, ent->right);
    return(out);
}

char *
gaadebug_policy_string(gaa_ptr gaa, char *out, int osize, gaa_policy *policy)
{
    void *ent;
    char *s;
    int len;
    
    if (out == 0)
	return(0);
    if (policy == 0) {
	snprintf(out, osize, "(null policy)\n");
	return(out);
    }
    s = out;
    snprintf(s, osize, "Policy:\n");
    len = strlen(s);
    s += len;
    osize -= len;
    if (osize < 2)
	return(out);
    for (ent = gaa_list_first(policy->entries); ent; ent = gaa_list_next(ent)) {
	gaadebug_policy_entry_string(gaa, s, osize,
				     (gaa_policy_entry *)gaa_list_entry_value(ent));
	len = strlen(s);
	s += len;
	osize -= len;
	if (osize < 2)
	    return(out);
    }
    sprintf(s, "\n");
    return(out);
}

char *
gaadebug_sc_string(gaa_ptr gaa, gaa_sc_ptr sc, char *out, int osize)
{
    void *ent;
    gaa_list_ptr idlist;
    gaa_list_ptr glist;
    gaa_list_ptr nglist;
    gaa_status status;
    char *s;
    int len;

    if (out == 0)
	return(0);

    s = out;
    snprintf(s, osize, "Security context:\nIdentity credentials\n");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    if ((status = gaa_getcreds(gaa, sc, &idlist, GAA_IDENTITY)) != GAA_S_SUCCESS) {
	snprintf(s, osize, "gaa_getcreds failed: %s: %s\n",
		gaacore_majstat_str(status), gaa_get_err());
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    } else 
	for (ent = gaa_list_first(idlist); ent; ent = gaa_list_next(ent)) {
	    gaadebug_cred_string(s, osize, gaa,
				 (gaa_cred *)gaa_list_entry_value(ent));
	    len = strlen(s);
	    s += len;
	    if ((osize -= len) < 2)
		return(out);
	}
    
    snprintf(s, osize, "Group credentials\n");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    if ((status = gaa_getcreds(gaa, sc, &glist, GAA_GROUP_MEMB)) != GAA_S_SUCCESS) {
	snprintf(s, osize, "gaa_getcreds failed: %s: %s\n",
		 gaacore_majstat_str(status), gaa_get_err());
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    } else
	for (ent = gaa_list_first(glist); ent; ent = gaa_list_next(ent)) {
	    gaadebug_cred_string(s, osize, gaa,
				 (gaa_cred *)gaa_list_entry_value(ent));
	    len = strlen(s);
	    s += len;
	    if ((osize -= len) < 2)
		return(out);
	}
    snprintf(s, osize, "Group-non credentials\n");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    if ((status = gaa_getcreds(gaa, sc, &nglist, GAA_GROUP_NON_MEMB)) != GAA_S_SUCCESS) {
	snprintf(s, osize, "gaa_getcreds failed: %s: %s\n",
		 gaacore_majstat_str(status), gaa_get_err());
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    } else
	for (ent = gaa_list_first(nglist); ent; ent = gaa_list_next(ent)) {
	    gaadebug_cred_string(s, osize, gaa,
				 (gaa_cred *)gaa_list_entry_value(ent));
	    len = strlen(s);
	    s += len;
	    if ((osize -= len) < 2)
		return(out);
	}

    snprintf(s, osize, "Authorized credentials\n");
    if ((status = gaa_getcreds(gaa, sc, &nglist, GAA_AUTHORIZED)) != GAA_S_SUCCESS) {
	snprintf(s, osize, "gaa_getcreds failed: %s: %s\n",
		 gaacore_majstat_str(status), gaa_get_err());
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    } else
	for (ent = gaa_list_first(nglist); ent; ent = gaa_list_next(ent)) {
	    gaadebug_cred_string(s, osize, gaa,
				 (gaa_cred *)gaa_list_entry_value(ent));
	    len = strlen(s);
	    s += len;
	    if ((osize -= len) < 2)
		return(out);
	}


    snprintf(s, osize, "Attribute credentials\n");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    if ((status = gaa_getcreds(gaa, sc, &nglist, GAA_ATTRIBUTES)) != GAA_S_SUCCESS) {
	snprintf(s, osize, "gaa_getcreds failed: %s: %s\n",
		 gaacore_majstat_str(status), gaa_get_err());
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    } else
	for (ent = gaa_list_first(nglist); ent; ent = gaa_list_next(ent)) {
	    gaadebug_cred_string(s, osize, gaa,
				 (gaa_cred *)gaa_list_entry_value(ent));
	    len = strlen(s);
	    s += len;
	    if ((osize -= len) < 2)
		return(out);
	}

    snprintf(s, osize, "Unevaluated credentials\n");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    if ((status = gaa_getcreds(gaa, sc, &nglist, GAA_UNEVAL)) != GAA_S_SUCCESS) {
	snprintf(s, osize, "gaa_getcreds failed: %s: %s\n",
		 gaacore_majstat_str(status), gaa_get_err());
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    } else
	for (ent = gaa_list_first(nglist); ent; ent = gaa_list_next(ent)) {
	    gaadebug_cred_string(s, osize, gaa,
				 (gaa_cred *)gaa_list_entry_value(ent));
	    len = strlen(s);
	    s += len;
	    if ((osize -= len) < 2)
		return(out);
	}

    return(out);
}

#ifdef USE_GAA_PRIVATE
char *
gaadebug_gaa_string(char *out, int osize, gaa_ptr gaa)
{
    gaa_list_entry_ptr ent;
    char *s;
    int len;
    char buf[BSIZE];

    if (out == 0)
	return;
    s = out;
    snprintf(s, osize, "Condition callbacks\n");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    if (gaa == 0) {
	snprintf(s, osize, "(null gaa)\n");
	return(out);
    }
    for (ent = gaa_list_first(gaa->cond_callbacks); ent; ent = gaa_list_next(ent)) {
	gaadebug_cond_eval_entry_string(s, osize,
					(gaaint_cond_eval_entry *)gaa_list_entry_value(ent));
	len = strlen(out);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    }
    return(out);
}
#endif /* USE_GAA_PRIVATE */

char *
gaadebug_cred_string(char *out, int osize, gaa_ptr gaa, gaa_cred *cred)
{
    int len;
    char *s;
    gaa_list_entry_ptr ent;
    gaa_condition *cond;
    
    if (out == 0)
	return(0);
    if (cred == 0) {
	snprintf(out, osize, "(null)\n");
	return(out);
    }
    s = out;
    snprintf(s, osize, "%s cred: ", gaacore_cred_type_to_string(cred->type));
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    snprintf(s, osize, "grantor: ");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    gaadebug_sec_attrb_string(s, osize, cred->grantor);
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    snprintf(s, osize, "principal: ");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    gaadebug_sec_attrb_string(s, osize, cred->principal);
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    switch(cred->type) {
    case GAA_IDENTITY:
    case GAA_GROUP_MEMB:
    case GAA_GROUP_NON_MEMB:
	gaadebug_id_info_string(cred->info.id_info, s, osize);
	break;
    case GAA_AUTHORIZED:
	gaadebug_authr_info_string(gaa, cred->info.authr_info, s, osize);
	break;
    case GAA_ATTRIBUTES:
	gaadebug_attr_info_string(cred->info.attr_info, s, osize);
	break;
    }
    return(out);
}


static char *
gaadebug_id_info_string(gaa_identity_info *id, char *out, int osize)
{
    gaa_list_entry_ptr ent;
    gaa_condition *cond;
    char *s;
    int len;

    s = out;
    for (ent = gaa_list_first(id->conditions); ent; ent = gaa_list_next(ent))
	if (cond = (gaa_condition *)gaa_list_entry_value(ent)) {
	    snprintf(s, osize, "\tcond: ");
	    len = sizeof("\tcond: ") - 1;
	    s += len;
	    if ((osize -= len) < 2)
		return(out);
	    gaadebug_condstr_r(cond, s, osize);
	    len = strlen(s);
	    s += len;
	    if ((osize -= len) < 2)
		return(out);
	    snprintf(s, osize, "\n");
	    s++;
	    if (--osize < 2)
		return(out);
	}
    *s++ = '\n';
    *s++ = '\0';
    return(out);
}

#ifdef USE_GAA_PRIVATE
static char *
gaadebug_cond_eval_entry_string(char *out, int osize, gaaint_cond_eval_entry *ce)
{
    if (out == 0)
	return(out);
    if (ce == 0) {
	snprintf(out, osize, "(null)\n");
	return(out);
    }
    snprintf(out, osize, "type = \"%s\", auth = \"%s\"\n",
	    (ce->type ? ce->type : ""),
	    (ce->authority ? ce->authority : ""));
    return(out);
}
#endif /* USE_GAA_PRIVATE */

static char *
gaadebug_authr_info_string(gaa_ptr gaa, gaa_authr_info *a, char *out, int osize)
{
    gaa_list_entry_ptr ent;
    gaa_policy_right *right;
    char *s;
    int len;

    if (a) {
	for (s = out, ent = gaa_list_first(a->access_rights); ent; ent = gaa_list_next(ent))
	    if (right = (gaa_policy_right *)gaa_list_entry_value(ent)) {
		gaadebug_policy_right_string(gaa, s, osize, right);
		len = strlen(s);
		s += len;
		if (osize -= len < 2)
		    break;
	    }
    }
    return(out);
}


static char *
gaadebug_attr_info_string(gaa_attribute_info *a, char *out, int osize)
{
    gaa_list_entry_ptr ent;
    gaa_condition *cond;
    char *s = out;
    int len;

    if (a) {
	snprintf(s, osize, "type = \"%s\", auth = \"%s\", val = \"%s\"\n",
		(a->type ? a->type : ""),
		(a->value ? a->authority : ""),
		(a->value ? a->value : ""));
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
	for (ent = gaa_list_first(a->conditions); ent; ent = gaa_list_next(ent))
	    if (cond = (gaa_condition *)gaa_list_entry_value(ent)) {
		gaadebug_condstr_r(cond, s, osize);
		len = strlen(s);
		s += len;
		if ((osize -= len) < 2)
		    break;
	    }
    }
    return(out);
}

char *
gaadebug_sec_attrb_string(char *out, int osize, gaa_sec_attrb *a)
{
    if (out == 0)
	return(out);
    if (a == 0) {
	snprintf(out, osize, "(null)\n");
	return(out);
    }
    snprintf(out, osize, "type = \"%s\", auth = \"%s\", val = \"%s\"\n",
	    gaacore_cred_type_to_string(a->type),
	    (a->authority ? a->authority : ""),
	    (a->value ? a->value : ""));
    return(out);
}

/** gaadebug_answer_string()
 * 
 *  Express the answer in a string.
 *
 *  @param gaa
 *         input gaa pointer
 *  @param out
 *         output string
 *  @param osize
 *         input maximum size of out string
 *  @param ans
 *         input answer
 *
 *  @retval <some_string>
 *          answer string returned on success
 *  @retval 0
 *          failure
 *
 *  @note
 *          In a multithreaded environment, the starting and ending times
 *          in the string may be incorrect (because this function relies on
 *          gmtime, which does not appear to be thread-safe).
 */
char *
gaadebug_answer_string(gaa_ptr gaa, char *out, int osize, gaa_answer *ans)
{
    gaa_list_entry_ptr ent;
    gaa_policy_right *right;
    int len;
    char *s;

    if (out == 0)
	return(0);
    if (ans == 0) {
	snprintf(out, osize, "(null answer)\n");
	return(out);
    }
    s = out;

    snprintf(s, osize, "Answer:\n");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    snprintf(s, osize, "start time: ");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    if (ans->valid_time && ans->valid_time->start_time)
    {
	strftime(s, osize, "%a %b %d %I:%M:%S %Z %Y",
		 localtime(&ans->valid_time->start_time));
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    }
    snprintf(s, osize, "\n  end time: ");
    len = strlen(s);
    s += len;
    if ((osize -= len) < 2)
	return(out);
    if (ans->valid_time && ans->valid_time->end_time)
    {
	strftime(s, osize, "%a %b %d %I:%M:%S %Z %Y",
		 localtime(&ans->valid_time->end_time));
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    }
    snprintf(s, osize, "\n");
    len = 1;
    s++;
    if ((osize -= len) < 2)
	return(out);
    for (ent = gaa_list_first(ans->rights); ent; ent = gaa_list_next(ent)) {
	right = (gaa_policy_right *)gaa_list_entry_value(ent);
	gaadebug_policy_right_string(gaa, s, osize, right);
	len = strlen(s);
	s += len;
	if ((osize -= len) < 2)
	    return(out);
    }
    return(out);
}
