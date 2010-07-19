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
#include "gaa_test_utils.h"
#include "gaa_debug.h"
#include <string.h>
#ifdef notdef
#include <libxml/parser.h>
#endif /* notdef */

char *
process_msg(gaa_ptr gaa, gaa_sc_ptr *sc, char *inbuf, char *outbuf, int outbsize, char **users, gaa_policy_ptr *policy)
{
    char *what;

    *outbuf = '\0';
    if (what = strtok(inbuf, " \t\n")) {
	if (strcasecmp(what, "assert") == 0)
	    process_assert(gaa, *sc, users, outbuf, outbsize);
	else if (strcasecmp(what, "getpolicy") == 0)
	    process_getpolicy(gaa, policy, outbuf, outbsize);
	else if (strcasecmp(what, "request") == 0) {
	    if (inbuf = strtok(0, "\n"))
		process_request(gaa, *sc, *policy, inbuf, outbuf, outbsize);
	}
	else if (strcasecmp(what, "print") == 0)
	    process_print(gaa, *sc, policy, outbuf, outbsize);
	else if (strcasecmp(what, "inquire") == 0)
	    process_inquire(gaa, *sc, policy, outbuf, outbsize);
	else if (strcasecmp(what, "clear") == 0)
	    process_clear(sc);
	else if (strcasecmp(what, "pull") == 0)
	    process_pull(gaa, *sc, outbuf, outbsize);
	else if (strcasecmp(what, "get_authz_id") == 0)
	    process_get_authz_id(gaa, outbuf, outbsize);
#ifdef notdef
	else if (strcasecmp(what, "verify_xml_sig") == 0)
	    process_saml_verify_xml_sig(inbuf, outbuf, outbsize);
#endif /* notdef */
	else
	    snprintf(outbuf, outbsize, "huh?\n");
    }
    return(outbuf);
}

gaa_status
process_assert(gaa_ptr gaa, gaa_sc_ptr sc, char **users, char *outbuf, int outbsize)
{
    char *name;
    gaa_status status = GAA_S_SUCCESS;

    if (name = strtok(0, " \t\n")) {
	*users = name;
	if ((status = gaa_pull_creds(gaa, sc, GAA_ANY, 0)) != GAA_S_SUCCESS)
	    snprintf(outbuf, outbsize, "pull_creds failed: %s (%s)\n",
		     gaacore_majstat_str(status),
		     gaa_get_err());
    }
    return(status);
}

gaa_status
process_pull(gaa_ptr gaa, gaa_sc_ptr sc, char *out, int osize)
{
    char *mech = 0;
    char *tstr = 0;
    gaa_cred_type type;
    char *s;
    int len;
    gaa_status status;

    struct slist {
	char *name;
	gaa_cred_type val;
    };

    struct slist types[] = {
	{"identity", GAA_IDENTITY},
	{"group", GAA_GROUP_MEMB},
	{"group-non", GAA_GROUP_NON_MEMB},
	{"authorized", GAA_AUTHORIZED},
	{"attributes", GAA_ATTRIBUTES},
	{"uneval", GAA_UNEVAL},
	{"any", GAA_ANY},
	{0, GAA_UNEVAL}
    };
    struct slist *sl;

    if (mech = strtok(0, " \t\n"))
	tstr = strtok(0, "\t\n");
    if (mech && (strcmp(mech, "0") == 0))
	mech = 0;
    if (tstr) {
	for (sl = types; sl->name; sl++)
	    if (strcasecmp(sl->name, tstr) == 0) {
		type = sl->val;
		break;
	    }
	if (sl->name == 0) {
	    s = out;
	    snprintf(s, osize, "Invalid cred type; please choose one of");
	    len = strlen(s);
	    s += len;
	    osize -= len;
	    for (sl = types; sl->name; sl++) {
		snprintf(s, osize, " %s", sl->name);
		len = strlen(s);
		s += len;
		osize -= len;
	    }
	    snprintf(s, osize, "\n");
	    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
	}
    } else
	type = GAA_ANY;

    if ((status = gaa_pull_creds(gaa, sc, type, mech)) != GAA_S_SUCCESS)
	snprintf(out, osize, "pull_creds failed: %s (%s)\n",
		gaacore_majstat_str(status), gaa_get_err());
    return(status);
}

gaa_status
process_getpolicy(gaa_ptr gaa, gaa_policy_ptr *policy, char *outbuf, int outbsize)
{
    char *object;
    gaa_status status;

    if ((object = strtok(0, "\t\n")) == 0) {
	fprintf(stderr, "no object specified\n");
	return(GAA_STATUS(GAA_S_NO_MATCHING_ENTRIES, 0));
    }
    gaa_clear_policy(*policy);
    if ((status = gaa_get_object_policy_info(object, gaa, policy)) != GAA_S_SUCCESS)
	snprintf(outbuf, outbsize, "gaa_get_object_policy_info failed: %s (%s)\n",
		gaacore_majstat_str(status), gaa_get_err());
    return(status);
}

gaa_status
process_request(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr policy, char *inbuf, char *outbuf, int outbsize)
{
    char *auth;
    char *val;
    gaa_status status;
    gaa_list_ptr list = 0;
    gaa_request_right *right;
    gaa_answer_ptr answer;
    char *statstr;
    char *str;
    char *s1;
    int len;

    str = inbuf;
    while (str && *str) {
	if (s1 = strpbrk(str, ";\n"))
	    *s1++ = '\0';
	if ((auth = strtok(str, " \t\n")) == 0)
	    continue;
	if (strcasecmp(auth, "end") == 0)
	    break;
	if ((val = strtok(0, " \t\n")) == 0) {
	    snprintf(outbuf, outbsize, "No value specified\n");
	    break;
	}
	if (list == 0)
	    list = gaa_new_req_rightlist();
	if ((status = gaa_new_request_right(gaa, &right, auth, val)) != GAA_S_SUCCESS) {
	    snprintf(outbuf, outbsize, "gaa_new_request_right failed: %s (%s)\n",
		    gaacore_majstat_str(status), gaa_get_err());
	    return(status);
	}
	if ((status = gaa_add_request_right(list, right)) != GAA_S_SUCCESS) {
	    snprintf(outbuf, outbsize, "gaa_add_request_right failed: %s (%s)\n",
		    gaacore_majstat_str(status), gaa_get_err());
	    return(status);
	}
	str = s1;
    }
    if ((status = gaa_new_answer(&answer)) != GAA_S_SUCCESS) {
	snprintf(outbuf, outbsize, "gaa_new_answer failed: %s (%s)\n",
		gaacore_majstat_str(status), gaa_get_err());
	return(status);
    }
    status = gaa_check_authorization(gaa, sc, policy, list, answer);
    if (status == GAA_C_YES)
	statstr = "GAA_C_YES";
    else
	statstr = gaacore_majstat_str(status);
    switch(status) {
    case GAA_C_YES:
    case GAA_C_NO:
    case GAA_C_MAYBE:
	snprintf(outbuf, outbsize, "%s -- Detailed answer:\n", statstr);
	len = strlen(outbuf);
	str = outbuf + len;
	outbsize -= len;
	gaadebug_answer_string(gaa, str, outbsize, answer);
	break;
    default:
	snprintf(outbuf, outbsize,
		 "gaa_check_authorization returned %s: %s\n", statstr,
	       gaa_get_err());
    }
    return(status);
}

void
process_print(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize)
{
    char *what;

    if ((what = strtok(0, " \t\n")) == 0)
	snprintf(outbuf, outbsize, "Print what?\n");
    else if (strcasecmp(what, "sc") == 0)
	gaadebug_sc_string(gaa, sc, outbuf, outbsize);
    else if (strcasecmp(what, "policy") == 0) {
	if (policy)
	    gaadebug_policy_string(gaa, outbuf, outbsize, *policy);
	else
	    snprintf(outbuf, outbsize, "(null policy)\n");
    } else
	snprintf(outbuf, outbsize, "Print what?\n");
}

gaa_status
process_inquire(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize)
{
    gaa_status status;
    gaa_list_ptr orights;
    gaa_list_entry_ptr ent;
    gaa_policy_right *pright;
    char *str;
    int len;

    if (policy == 0) {
	snprintf(outbuf, outbsize, "(null policy)\n");
	return(GAA_S_SUCCESS);
    }
    if ((status = gaa_inquire_policy_info(gaa, sc, *policy, &orights)) != GAA_S_SUCCESS) {
	snprintf(outbuf, outbsize, "gaa_inquire_policy_info failed: %s: %s\n",
		gaacore_majstat_str(status), gaa_get_err());
	return(status);
    }

    str = outbuf;
    snprintf(outbuf, outbsize, "policy info:\n");
    len = strlen(str);
    str += len;
    if ((outbsize -= len) < 2)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    for (ent = gaa_list_first(orights); ent; ent = gaa_list_next(ent)) {
	pright = (gaa_policy_right *)gaa_list_entry_value(ent);
	str = gaadebug_policy_right_string(gaa, str, outbsize, pright);
	len = strlen(str);
	str += len;
	if ((outbsize -= len) < 2)
	    return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    }
    return(status);
}

gaa_status
process_clear(gaa_sc_ptr *sc)
{
    gaa_free_sc(*sc);
    return(gaa_new_sc(sc));
}

int
init_sc(gaa_ptr gaa, gaa_sc_ptr *sc, void *context)
{
    gaa_cred *cred;
    /*
     * context is gss_ctx_id_t -- but I don't want to have to include
     * all the gss stuff here.
     */

    if (gaa_new_sc(sc) != GAA_S_SUCCESS)
	return(-1);
    if (gaa_new_cred(gaa, *sc, &cred, "gss", context,
		     GAA_IDENTITY, 1, 0) != GAA_S_SUCCESS)
	return(-1);

    if (gaa_add_cred(gaa, *sc, cred) != GAA_S_SUCCESS)
	return(-1);
    return(0);
}

gaa_status
process_get_authz_id(gaa_ptr gaa, char *outbuf, int outbsize)
{
    gaa_status status;
    char *idbuf = 0;

    status = gaa_x_get_authorization_identity(gaa, &idbuf);
    if (idbuf == 0)
	strncpy(outbuf, "(null)\n", outbsize);
    else
	snprintf(outbuf, outbsize, "%s\n", idbuf);
    return(status);
}

#ifdef notdef
gaa_status
process_saml_verify_xml_sig(filename, outbuf, outbsize)
{
    char *str;
    int len;
    xmlDocPtr doc;

    if (filename == 0) {
	snprintf(outbuf, outbsize, "(null filename)\n");
	return(GAA_S_SUCCESS);
    }
    xmlInitParser();
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    doc = xmlParseFile(filename);

    if (gaa_simple_i_xml_sig_ok(doc, outbuf, outbsize)) {
	printf("signature is okay\n");
    } else {
	printf("signature is bad\n");
    }
}
#endif /* notdef */
