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

#include <string.h>
#include "globus_auth.h"
#include "globus_auth_error.h"
#include "gaa.h"
#include "gaa_core.h"
#include "gaa_utils.h"
#include "gaa_debug.h"

char *
process_msg(globus_authorization_handle_t handle, char *inbuf, char *outbuf, int outbsize, char **users)
{
    char *what;

    *outbuf = '\0';
    if (what = strtok(inbuf, " \t\n")) {
    if (strcasecmp(what, "assert") == 0)
        process_assert(handle->gaa, handle->gaa_sc, users, outbuf, outbsize);
    else if (strcasecmp(what, "getpolicy") == 0)
        process_getpolicy(handle, outbuf, outbsize);
    else if (strcasecmp(what, "request") == 0) {
        if (inbuf = strtok(0, "\n"))
        process_request(handle, inbuf, outbuf, outbsize);
    }
    else if (strcasecmp(what, "print") == 0)
        process_print(handle->gaa, handle->gaa_sc, &handle->policy, outbuf, outbsize);
    else if (strcasecmp(what, "inquire") == 0)
        process_inquire(handle->gaa, handle->gaa_sc, &handle->policy, outbuf, outbsize);
    else if (strcasecmp(what, "clear") == 0)
        process_clear(&handle->gaa_sc);
    else if (strcasecmp(what, "pull") == 0)
        process_pull(handle->gaa, handle->gaa_sc, outbuf, outbsize);
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
process_getpolicy(globus_authorization_handle_t handle, char *outbuf, int outbsize)
{
    char *object;

    if ((object = strtok(0, "\t\n")) == 0) {
    fprintf(stderr, "no object specified\n");
    return(GAA_STATUS(GAA_S_NO_MATCHING_ENTRIES, 0));
    }

    globus_authorization_handle_set_policy_source(handle,object);
    return 0;
}

gaa_status
process_request(globus_authorization_handle_t handle, char *inbuf, char *outbuf, int outbsize) {
    char *auth;
    /*char *dval;*/
    char * object;
    char * action;

    /*gaa_status status;
    gaa_list_ptr list = 0;
    gaa_request_right *right;
    gaa_answer_ptr answer;*/
    
    char *statstr;
    char *str;
    char *s1;
    int len;
    char *errstr;
    globus_result_t result;
#ifdef DEBUG    
    fprintf(stderr,"input: %s\n",inbuf);
#endif
    str = inbuf;
    while (str && *str) {
    #ifdef DEBUG    
        fprintf(stderr,"remaining: %s\n",str);
    #endif
    if (s1 = strpbrk(str, ";\n"))
        *s1++ = '\0';
    if ((auth = strtok(str, " \t\n")) == 0)
        continue;
    if (strcasecmp(auth, "end") == 0)
        break;
    if ((action = strtok(0, " \t\n")) == 0) {
        snprintf(outbuf, outbsize, "No action specified\n");
        continue;
    }
    if ((object = strtok(0, " \t\n")) == 0) {
        snprintf(outbuf, outbsize, "No value specified\n");
        break;
    }
/*
    if (list == 0)
        list = gaa_new_req_rightlist();
    if ((status = gaa_new_request_right(gaa, &right, auth, action)) != GAA_S_SUCCESS) {
        snprintf(outbuf, outbsize, "gaa_new_request_right failed: %s (%s)\n",
            gaacore_majstat_str(status), gaa_get_err());
        return(status);
    }
    if ((status = gaa_add_request_right(list, right)) != GAA_S_SUCCESS) {
        snprintf(outbuf, outbsize, "gaa_add_request_right failed: %s (%s)\n",
            gaacore_majstat_str(status), gaa_get_err());
        return(status);
    }
*/
    result = globus_authorization_eval(handle,object,auth,action);

    str = s1;
    }
    /*if ((status = gaa_new_answer(&(handle->answer))) != GAA_S_SUCCESS) {
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
    */
    errstr = 0;
    if (result==GLOBUS_SUCCESS)
        statstr = "GLOBUS_SUCCESS";
    else if ( globus_result_get_error_string(result, &errstr) 
                    == GLOBUS_SUCCESS){
                    
        statstr = (char *)malloc(strlen(errstr)+1);
        strncpy(statstr, errstr, strlen(errstr)+1);
    }

    snprintf(outbuf, outbsize, "%s -- Detailed answer:\n", statstr);
    
    if(errstr) free(errstr);
    
    #ifdef DEBUG
        len = strlen(outbuf);
        str = outbuf + len;
        outbsize -= len;
        gaadebug_answer_string(handle->gaa, str, outbsize, handle->debug_answer);
    #endif

    return(0);
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

