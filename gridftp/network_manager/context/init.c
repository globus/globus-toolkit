/*
 * Copyright 1999-2014 University of Chicago
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

/**
 * @file context/init.c
 * @brief globus_net_manager_context_init()
 */

#include "globus_net_manager_context.h"


static 
globus_result_t
globus_l_net_manager_context_load_entry(
    const char *                            name,
    globus_i_net_manager_context_entry_t ** entry)
{
    globus_extension_handle_t               ext_handle;
    globus_net_manager_t *                  loaded_manager;
    char *                                  dll_name = NULL;
    globus_i_net_manager_context_entry_t *  ent;
    int                                     rc;
    globus_result_t                         result = GLOBUS_SUCCESS;
    GlobusNetManagerName(globus_l_net_manager_context_load_entry);

    /* is module already in registry? */
    loaded_manager = (globus_net_manager_t *) globus_extension_lookup(
        &ext_handle, GLOBUS_NET_MANAGER_REGISTRY, (void *) name);
    if(loaded_manager == NULL)
    {
        /* load and activate the dll */
        dll_name = globus_common_create_string(
            "globus_net_manager_%s", name);

        rc = globus_extension_activate(dll_name);        
        if(rc != GLOBUS_SUCCESS)
        {
            result = GlobusNetManagerErrorManager(
                rc, name, "attempting to activate module.");
            goto error_activate;
        }
    
        /* now module should be in registry */
        loaded_manager = (globus_net_manager_t *) globus_extension_lookup(
            &ext_handle, GLOBUS_NET_MANAGER_REGISTRY, (void *) name);
        if(loaded_manager == NULL)
        {
            result = GlobusNetManagerErrorManager(
                rc, name, "attempting to load activated module.");
            goto error_activate;
        }
    }
    ent = globus_calloc(1, sizeof(globus_i_net_manager_context_entry_t));
    ent->manager = loaded_manager;
    ent->ext_handle = ext_handle;
    ent->name = strdup(name);
    ent->dll_name = dll_name;
    
    *entry = ent;
    return GLOBUS_SUCCESS;
    
error_activate:
    globus_free(dll_name);
    *entry = NULL;
    return result;
}



globus_result_t
globus_net_manager_context_init(
    globus_net_manager_context_t *      context,
    const globus_net_manager_attr_t *   attrs)
{
    globus_i_net_manager_context_t *    ctx;
    globus_net_manager_attr_t *         attr;
    globus_result_t                     result;
    int                                 i;
    int                                 j;
    int                                 max_attr_count;
    int                                 attrnum;
    char *                              current_scope = NULL;
    globus_i_net_manager_context_entry_t *  ent = NULL;
    GlobusNetManagerName(globus_net_manager_context_init);
    
    if(context == NULL || attrs == NULL || attrs[0].scope == NULL)
    {
        result = GlobusNetManagerErrorParameter("No parameter may be NULL.");
        goto error_no_attr;
    }
    
    ctx = globus_calloc(1, sizeof(globus_i_net_manager_context_t));
    if(ctx == NULL)
    {
        result = GlobusNetManagerErrorMemory("context");
        goto error_ctx_mem;
    }
    for(max_attr_count = 0; 
        attrs[max_attr_count].scope != NULL;
        max_attr_count++);
    
    for(i = 0; attrs[i].scope != NULL; i++)
    {
        /* start of a new manager entry */
        if(strcmp(attrs[i].scope, "net_manager") == 0 && 
            strcmp(attrs[i].name, "manager") == 0)
        {
            ent = NULL;
            attrnum = 0;
            current_scope = attrs[i].value;

            result = globus_l_net_manager_context_load_entry(
                attrs[i].value, &ent);
            if(result)
            {
                goto error_load;
            }

            ent->attrs = calloc(
                max_attr_count, sizeof(globus_net_manager_attr_t));
            for(j = 0; attrs[j].scope != NULL; j++)
            {
                if(strcmp(attrs[j].scope, "global") == 0)
                {
                    result = globus_net_manager_attr_init(
                            &ent->attrs[attrnum++],
                            attrs[j].scope,
                            attrs[j].name,
                            attrs[j].value);
                    if(result)
                    {
                        goto error_attr;
                    }
                }
            }
            ent->attrs[attrnum] = globus_net_manager_null_attr;
            
            globus_list_insert(&ctx->managers, ent);
        }
        /* attrs for the current manager entry */
        else if(current_scope && strcmp(attrs[i].scope, current_scope) == 0)
        {
            result = globus_net_manager_attr_init(
                    &ent->attrs[attrnum++],
                    attrs[i].scope,
                    attrs[i].name,
                    attrs[i].value);
            if(result)
            {
                goto error_attr;
            }
            ent->attrs[attrnum] = globus_net_manager_null_attr;
        }
        /* unrelated scope */
        else
        {
            ent = NULL;
            attrnum = 0;
            current_scope = attrs[i].value;
        }
    }
    
    *context = ctx;
    return GLOBUS_SUCCESS;
    
error_attr:
error_load:
    free(ctx);
error_ctx_mem:
error_no_attr:
    if (context)
    {
        *context = NULL;
    }

    return result;
}


