/*
 * Copyright 2009 The Board of Trustees of the University
 * of Illinois.  See the LICENSE file for detailed license information.
 *
 * Portions, specifically myproxy_log_usage_stats(), myproxy_usage_stats_init(),
 * myproxy_usage_stats_close(), myproxy_usage_ent_s, myproxy_usage_tag_e and
 * TAG #defines were based on those from Usage Metrics portions of:
 * gridftp/server/source/globus_i_gfs_log.c
 *
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

#include "myproxy_common.h"

#ifdef HAVE_GLOBUS_USAGE

static globus_list_t *myproxy_usage_handle_list = NULL;

#define MYPROXY_USAGE_ID 11
#define MYPROXY_USAGE_VER 0

#define MYPROXY_DEFAULT_TAGLIST "VvtrlLB"
#define MYPROXY_ALL_TAGLIST "VvtrlLBIuU"
#define MYPROXY_TAGCOUNT 25

typedef enum myproxy_usage_tag_e
{
    MYPROXY_USAGE_MAJOR_VER      = 'V',
    MYPROXY_USAGE_MINOR_VER      = 'v',
    MYPROXY_USAGE_TASK_CODE      = 't',
    MYPROXY_USAGE_RET_CODE       = 'r',
    MYPROXY_USAGE_REQ_LIFETIME   = 'l',
    MYPROXY_USAGE_CRED_LIFETIME  = 'L',
    MYPROXY_USAGE_INFO_BITS      = 'B',
    MYPROXY_USAGE_CLIENTIP       = 'I',
    MYPROXY_USAGE_USERNAME       = 'u',
    MYPROXY_USAGE_USERDN         = 'U'
    /* !! ADD to ALL_TAGLIST above, and to the invocation of
          globus_usage_stats_send() below when adding here. */
} myproxy_usage_tag_t;

typedef struct myproxy_usage_ent_s
{
    globus_usage_stats_handle_t         handle;
    char *                              target;
    char *                              taglist;
} myproxy_usage_ent_t;


globus_result_t
myproxy_usage_stats_init(myproxy_server_context_t *context)
{
    globus_result_t                     result;
    char *                              target_str = NULL;
    char *                              ptr = ptr;
    char *                              target = NULL;
    char *                              entry = NULL;
    globus_list_t *                     list = NULL;
    myproxy_usage_ent_t *               usage_ent = NULL;

    if (context->disable_usage_stats)
	return GLOBUS_SUCCESS;

    result = globus_module_activate(GLOBUS_USAGE_MODULE);
    if (result != GLOBUS_SUCCESS)
    {
           verror_put_string("ERROR: couldn't activate USAGE module");
           return result;
    }

    if (!context->usage_stats_target ||
        !strcasecmp(context->usage_stats_target, "default"))
        target_str = strdup(CILOGON_COLLECTOR);
    else
        target_str = strdup(context->usage_stats_target);

    if (target_str == NULL)
    {
        verror_put_string("ERROR: strdup failure for target_str");
        goto error;
    }
    myproxy_debug("Processing usage_stats_target (%s)\n", target_str);

    if(target_str && (strchr(target_str, ',') || strchr(target_str, '!')))
    {
        target = target_str;

        do {
            usage_ent = (myproxy_usage_ent_t *) malloc(sizeof(myproxy_usage_ent_t));
            if (usage_ent == NULL)
            {
                verror_put_string("ERROR: couldn't allocate for myproxy_usage_ent_t");
                goto error;
            }

            if ((ptr = strchr(target, ',')) != NULL)
                *ptr = '\0';

            entry = strdup(target);
            if (entry == NULL)
            {
                verror_put_string("ERROR: strdup failure for target");
                goto error;
            }

            if (ptr)
                target = ptr + 1;
            else
                target = NULL;

            if((ptr = strchr(entry, '!')) != NULL)
            {
                *ptr = '\0';
                usage_ent->taglist = strdup(ptr + 1);
                if (usage_ent->taglist == NULL)
                {
                    verror_put_string("ERROR: strdup failure for taglist");
                    goto error;
                }
                if(strlen(usage_ent->taglist) > MYPROXY_TAGCOUNT)
                {
                    usage_ent->taglist[MYPROXY_TAGCOUNT + 1] = '\0';
                }
            }
            else
            {
                usage_ent->taglist = strdup(MYPROXY_DEFAULT_TAGLIST);
                if (usage_ent->taglist == NULL)
                {
                    verror_put_string("ERROR: couldn't allocate for taglist");
                    goto error;
                }
            }
            
            if(strcasecmp(usage_ent->taglist, "default") == 0)
            {
                free(usage_ent->taglist);
                usage_ent->taglist = strdup(MYPROXY_DEFAULT_TAGLIST);
                if (usage_ent->taglist == NULL)
                {
                    verror_put_string("ERROR: couldn't allocate for taglist");
                    goto error;
                }
            }                
            else if(strcasecmp(usage_ent->taglist, "all") == 0)
            {
                free(usage_ent->taglist);
                usage_ent->taglist = strdup(MYPROXY_ALL_TAGLIST);
                if (usage_ent->taglist == NULL)
                {
                    verror_put_string("ERROR: couldn't allocate for taglist");
                    goto error;
                }
            }
            
            usage_ent->target = entry;

            globus_list_insert(&myproxy_usage_handle_list, usage_ent);
        }
        while(target != NULL);

        free(target_str);
    }
    else
    {
        usage_ent = (myproxy_usage_ent_t *) malloc(sizeof(myproxy_usage_ent_t));
        if (usage_ent == NULL)
        {
             verror_put_string("ERROR: couldn't allocate for usage_ent");
             goto error;
        }

        usage_ent->target = target_str;
        usage_ent->taglist = strdup(MYPROXY_DEFAULT_TAGLIST);
        if (usage_ent->taglist == NULL)
        {
             verror_put_string("ERROR: couldn't allocate for taglist");
             goto error;
        }

        globus_list_insert(&myproxy_usage_handle_list, usage_ent);
    }

    result = GLOBUS_SUCCESS;
    for(list = myproxy_usage_handle_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        usage_ent = (myproxy_usage_ent_t *) globus_list_first(list);

        usage_ent->handle = NULL;
        if (globus_usage_stats_handle_init(
            &usage_ent->handle,
            MYPROXY_USAGE_ID,
            MYPROXY_USAGE_VER,
            usage_ent->target) != GLOBUS_SUCCESS)
        {
            myproxy_log("usage_stats: not initialized (%s) (%s)",
                     usage_ent->target?:"NULL",
                     usage_ent->taglist?:"NULL");
            result = GLOBUS_FAILURE;
        } else
            myproxy_log("usage_stats: initialized (%s) (%s)",
                     usage_ent->target?:"NULL",
                     usage_ent->taglist?:"NULL");
    }

    return result;

error:
    if (target_str)
    {
        free(target_str); 
        target_str = NULL;
    }
    if (entry)
    {
        free(target_str); 
        target_str = NULL;
    }
    return GLOBUS_FAILURE;
}

void
myproxy_usage_stats_close(myproxy_server_context_t *context)
{
    globus_list_t *list;

    if (context->disable_usage_stats)
	return;

    list = myproxy_usage_handle_list;
    
    while(!globus_list_empty(list))
    {
        myproxy_usage_ent_t *usage_ent;
        
        usage_ent = (myproxy_usage_ent_t *) 
            globus_list_remove(&list, list);
    
        if(usage_ent)
        {
            if(usage_ent->handle)
            {
                globus_usage_stats_handle_destroy(usage_ent->handle);
            }
            if(usage_ent->target)
            {
                free(usage_ent->target);
            }
            if(usage_ent->taglist)
            {
                free(usage_ent->taglist);
            }
            free(usage_ent);
        }
    }
    myproxy_usage_handle_list = NULL;
}

static void
myproxy_log_usage_stats(
    int                                 task_code,
    int                                 ret_code,
    int                                 req_lifetime,
    int                                 cred_lifetime,
    char *                              info_bits,
    char *                              clientip,
    char *                              username,
    char *                              userdn)
{
    char                                major_ver_b[10];
    char                                minor_ver_b[10];
    char                                task_b[10];
    char                                ret_b[10];
    char                                req_lt_b[256];
    char                                cred_lt_b[256];
    globus_result_t                     result;
    globus_list_t *                     list;
    myproxy_usage_ent_t *               usage_ent;
    char *                              keys[MYPROXY_TAGCOUNT];
    char *                              values[MYPROXY_TAGCOUNT];
    char *                              ptr;
    char *                              key;
    char *                              value;
    int                                 i = 0;
    char *                              save_taglist = NULL;

    for(list = myproxy_usage_handle_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        usage_ent = (myproxy_usage_ent_t *) globus_list_first(list);

        if(!usage_ent || usage_ent->handle == NULL)
            continue;
        
        if(save_taglist == NULL || 
            strcmp(save_taglist, usage_ent->taglist) != 0)
        {
            save_taglist = usage_ent->taglist;
            
            ptr = usage_ent->taglist;
            i = 0;
            while(ptr && *ptr)
            {
                switch(*ptr)
                {
                  case MYPROXY_USAGE_MAJOR_VER:
                    key = "MAJOR_VER";
                    sprintf(major_ver_b, "%d", MYPROXY_VERSION_MAJOR);
                    value = major_ver_b;
                    break;
    
                  case MYPROXY_USAGE_MINOR_VER:
                    key = "MINOR_VER";
                    sprintf(minor_ver_b, "%d", MYPROXY_VERSION_MINOR);
                    value = minor_ver_b;
                    break;
    
                  case MYPROXY_USAGE_TASK_CODE:
                    key = "TASK";
                    sprintf(task_b, "%d", task_code);
                    value = task_b;
                    break;
    
                  case MYPROXY_USAGE_RET_CODE:
                    key = "RET";
                    sprintf(ret_b, "%d", ret_code);
                    value = ret_b;
                    break;
    
                  case MYPROXY_USAGE_REQ_LIFETIME:
                    key = "REQ_LTIME";
                    sprintf(req_lt_b, "%d", req_lifetime);
                    value = req_lt_b;
                    break;
    
                  case MYPROXY_USAGE_CRED_LIFETIME:
                    key = "CRED_LTIME";
                    sprintf(cred_lt_b, "%d", cred_lifetime);
                    value = cred_lt_b;
                    break;
    
                  case MYPROXY_USAGE_INFO_BITS:
                    key = "BITS";
                    value = info_bits;
                    break;
    
                  case MYPROXY_USAGE_CLIENTIP:
                    key = "CLIENTIP";
                    value = clientip?:"";
                    break;
    
                  case MYPROXY_USAGE_USERNAME:
                    key = "USER";
                    value = username?:"";
                    break;
    
                  case MYPROXY_USAGE_USERDN:
                    key = "USERDN";
                    value = userdn?:"";
                    break;
    
                  default:
                    key = NULL;
                    value = NULL;
                    break;
                }
                
                if(key != NULL && value != NULL)
                {
                    keys[i] = key;
                    values[i] = value;
                    i++;
                }
                
                ptr++;
            }
        }

#ifdef HAVE_GLOBUS_USAGE_SEND_ARRAY
        result = globus_usage_stats_send_array(
            usage_ent->handle, i, keys, values);
#else
        if (i)
            result = globus_usage_stats_send(
                usage_ent->handle, i,
                i>0?keys[0]:NULL, i>0?values[0]:NULL,
                i>1?keys[1]:NULL, i>1?values[1]:NULL,
                i>2?keys[2]:NULL, i>2?values[2]:NULL,
                i>3?keys[3]:NULL, i>3?values[3]:NULL,
                i>4?keys[4]:NULL, i>4?values[4]:NULL,
                i>5?keys[5]:NULL, i>5?values[5]:NULL,
                i>6?keys[6]:NULL, i>6?values[6]:NULL,
                i>7?keys[7]:NULL, i>7?values[7]:NULL,
                i>8?keys[8]:NULL, i>8?values[8]:NULL,
                i>9?keys[9]:NULL, i>9?values[9]:NULL);
#endif
        
    }
    
    return;
}
#endif /* HAVE_GLOBUS_USAGE */

void
myproxy_send_usage_metrics(myproxy_socket_attrs_t *attrs,
                           myproxy_server_peer_t *client,
                           myproxy_server_context_t *context,
                           myproxy_request_t *request,
                           myproxy_creds_t *creds,
                           myproxy_response_t *response,
                           int success_flag)
{
#ifdef HAVE_GLOBUS_USAGE
    char info_bits[32];
    char *alloced_userdn = NULL;
    char *userdn = NULL;

    if (context->disable_usage_stats)
	return;

    /* Determine userdn */
    if (request->command_type != MYPROXY_GET_PROXY)
        userdn = client->name;
    else if (context->usage.credentials_exist)
        userdn = creds->owner_name;
    else
        if (user_dn_lookup(request->username, &alloced_userdn, context))
            userdn = "";
        else
            userdn = alloced_userdn;

    sprintf(info_bits, "%d%d%d%d%d%d%d%d%d",
            context->usage.pam_used?1:0,
            context->usage.sasl_used?1:0,
            context->usage.cred_pphrase_used?1:0,
            context->usage.trusted_retr?1:0,
            context->usage.certauthz_used?1:0,
            context->usage.pubcookie_used?1:0,
            request->want_trusted_certs?1:0,
            context->usage.trustroots_sent?1:0,
            context->usage.ca_used?1:0);

    myproxy_log_usage_stats(request->command_type,
                            success_flag,
                            request->proxy_lifetime,
                            response->info_creds?response->info_creds->lifetime:0,
                            info_bits,
                            context->usage.client_ip,
                            request->username,
                            userdn);

    if (alloced_userdn)
        free(alloced_userdn);
#endif /* HAVE_GLOBUS_USAGE */
}
