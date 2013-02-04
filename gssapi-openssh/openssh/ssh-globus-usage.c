/*
 * Copyright 2009 The Board of Trustees of the University
 * of Illinois.  See the LICENSE file for detailed license information.
 *
 * Portions, specifically log_usage_stats(), ssh_usage_stats_init(),
 * ssh_usage_stats_close(), ssh_usage_ent_s, ssh_usage_tag_e and
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

#include "includes.h"

#ifdef HAVE_GLOBUS_USAGE

#include <stdarg.h>
#include <unistd.h> 

#include "log.h"
#include "ssh-globus-usage.h"

static globus_list_t *usage_handle_list = NULL;

#define SSH_GLOBUS_USAGE_ID 12
#define SSH_GLOBUS_USAGE_VER 0

#define SSH_GLOBUS_DEFAULT_TAGLIST "VvMm"
#define SSH_GLOBUS_ALL_TAGLIST     "VvMmIuU"
#define SSH_GLOBUS_TAGCOUNT 25

typedef enum ssh_usage_tag_e
{
    SSH_GLOBUS_USAGE_SSH_VER        = 'V',
    SSH_GLOBUS_USAGE_SSL_VER        = 'v',
    SSH_GLOBUS_USAGE_METHOD         = 'M',
    SSH_GLOBUS_USAGE_MECHANISM      = 'm',
    SSH_GLOBUS_USAGE_CLIENTIP       = 'I',
    SSH_GLOBUS_USAGE_USERNAME       = 'u',
    SSH_GLOBUS_USAGE_USERDN         = 'U'
    /* !! ADD to ALL_TAGLIST above and to globus_usage_stats_send()
          invocation below when adding here */
} ssh_usage_tag_t;

typedef struct ssh_usage_ent_s
{
    globus_usage_stats_handle_t         handle;
    char *                              target;
    char *                              taglist;
} ssh_usage_ent_t;


globus_result_t
ssh_usage_stats_init(int disable_usage_stats, char *usage_stats_targets)
{
    globus_result_t                     result;
    char *                              target_str = NULL;
    char *                              ptr = ptr;
    char *                              target = NULL;
    char *                              entry = NULL;
    globus_list_t *                     list = NULL;
    ssh_usage_ent_t *               usage_ent = NULL;

    if (disable_usage_stats)
	return GLOBUS_SUCCESS;

    result = globus_module_activate(GLOBUS_USAGE_MODULE);
    if (result != GLOBUS_SUCCESS)
    {
        error("ERROR: couldn't activate USAGE STATS module");
        return result;
    }

    if (!usage_stats_targets ||
        !strcasecmp(usage_stats_targets, "default"))
        target_str = strdup(CILOGON_COLLECTOR);
    else
        target_str = strdup(usage_stats_targets);

    if (target_str == NULL)
    {
        error("ERROR: strdup failure for target_str");
        goto error;
    }
    debug("Processing usage_stats_target (%s)\n", target_str);

    if(target_str && (strchr(target_str, ',') || strchr(target_str, '!')))
    {
        target = target_str;

        do {
            usage_ent = (ssh_usage_ent_t *) malloc(sizeof(ssh_usage_ent_t));
            if (usage_ent == NULL)
            {
                error("ERROR: couldn't allocate for ssh_usage_ent_t");
                goto error;
            }

            if ((ptr = strchr(target, ',')) != NULL)
                *ptr = '\0';

            entry = strdup(target);
            if (entry == NULL)
            {
                error("ERROR: strdup failure for target");
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
                    error("ERROR: strdup failure for taglist");
                    goto error;
                }
                if(strlen(usage_ent->taglist) > SSH_GLOBUS_TAGCOUNT)
                {
                    usage_ent->taglist[SSH_GLOBUS_TAGCOUNT + 1] = '\0';
                }
            }
            else
            {
                usage_ent->taglist = strdup(SSH_GLOBUS_DEFAULT_TAGLIST);
                if (usage_ent->taglist == NULL)
                {
                    error("ERROR: couldn't allocate for taglist");
                    goto error;
                }
            }
            
            if(strcasecmp(usage_ent->taglist, "default") == 0)
            {
                free(usage_ent->taglist);
                usage_ent->taglist = strdup(SSH_GLOBUS_DEFAULT_TAGLIST);
                if (usage_ent->taglist == NULL)
                {
                    error("ERROR: couldn't allocate for taglist");
                    goto error;
                }
            }                
            else if(strcasecmp(usage_ent->taglist, "all") == 0)
            {
                free(usage_ent->taglist);
                usage_ent->taglist = strdup(SSH_GLOBUS_ALL_TAGLIST);
                if (usage_ent->taglist == NULL)
                {
                    error("ERROR: couldn't allocate for taglist");
                    goto error;
                }
            }
            
            usage_ent->target = entry;

            globus_list_insert(&usage_handle_list, usage_ent);
        }
        while(target != NULL);

        free(target_str);
    }
    else
    {
        usage_ent = (ssh_usage_ent_t *) malloc(sizeof(ssh_usage_ent_t));
        if (usage_ent == NULL)
        {
             error("ERROR: couldn't allocate for usage_ent");
             goto error;
        }

        usage_ent->target = target_str;
        usage_ent->taglist = strdup(SSH_GLOBUS_DEFAULT_TAGLIST);
        if (usage_ent->taglist == NULL)
        {
             error("ERROR: couldn't allocate for taglist");
             goto error;
        }

        globus_list_insert(&usage_handle_list, usage_ent);
    }

    result = GLOBUS_SUCCESS;
    for(list = usage_handle_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        usage_ent = (ssh_usage_ent_t *) globus_list_first(list);

        usage_ent->handle = NULL;
        if (globus_usage_stats_handle_init(
            &usage_ent->handle,
            SSH_GLOBUS_USAGE_ID,
            SSH_GLOBUS_USAGE_VER,
            usage_ent->target) != GLOBUS_SUCCESS)
        {
            error("USAGE-STATS: Error initializing (%s) (%s)",
                     usage_ent->target?:"NULL",
                     usage_ent->taglist?:"NULL");
            result = GLOBUS_FAILURE;
        } else
            debug("USAGE-STATS: Initialized (%s) (%s)", usage_ent->target?:"NULL",
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
ssh_usage_stats_close(int disable_usage_stats)
{
    globus_list_t *list;

    if (disable_usage_stats)
	return;

    list = usage_handle_list;
    
    while(!globus_list_empty(list))
    {
        ssh_usage_ent_t *usage_ent;
        
        usage_ent = (ssh_usage_ent_t *) 
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
    usage_handle_list = NULL;
}

static void
log_usage_stats(char *ssh_release, const char *ssl_release,
                char *method, char *mechanism, const char *clientip,
                char *username, char *userdn)
{
    globus_result_t                     result;
    globus_list_t *                     list;
    ssh_usage_ent_t *                   usage_ent;
    char *                              keys[SSH_GLOBUS_TAGCOUNT];
    char *                              values[SSH_GLOBUS_TAGCOUNT];
    char *                              ptr;
    char *                              key;
    char *                              value;
    int                                 i = 0;
    char *                              save_taglist = NULL;

    for(list = usage_handle_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        usage_ent = (ssh_usage_ent_t *) globus_list_first(list);

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
                  case SSH_GLOBUS_USAGE_SSH_VER:
                    key = "SSH_VER";
                    value = ssh_release;
                    break;
    
                  case SSH_GLOBUS_USAGE_SSL_VER:
                    key = "SSL_VER";
                    value = (char *) ssl_release;
                    break;
    
                  case SSH_GLOBUS_USAGE_METHOD:
                    key = "METHOD";
                    value = method;
                    break;
    
                  case SSH_GLOBUS_USAGE_MECHANISM:
                    key = "MECH";
                    value = mechanism?:"";
                    break;
    
                  case SSH_GLOBUS_USAGE_CLIENTIP:
                    key = "CLIENTIP";
                    value = (char *) clientip?:"";
                    break;
    
                  case SSH_GLOBUS_USAGE_USERNAME:
                    key = "USER";
                    value = username?:"";
                    break;
    
                  case SSH_GLOBUS_USAGE_USERDN:
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
                i>6?keys[6]:NULL, i>6?values[6]:NULL);
#endif /* HAVE_GLOBUS_USAGE_SEND_ARRAY */
    }
    
    return;
}
#endif /* HAVE_GLOBUS_USAGE */

void
ssh_globus_send_usage_metrics(char *ssh_release, const char *ssl_release,
                              char *method, char *mechanism, const char *client_ip,
                              char *username, char *userdn)
{
#ifdef HAVE_GLOBUS_USAGE

    log_usage_stats(ssh_release, ssl_release, method, mechanism,
                    client_ip, username, userdn);

#endif /* HAVE_GLOBUS_USAGE */
}
