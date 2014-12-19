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
 * @file context/post_listen.c
 * @brief globus_net_manager_context_post_listen()
 */

#include "globus_net_manager_context.h"

globus_result_t
globus_net_manager_context_post_listen(
    globus_net_manager_context_t        context,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const globus_net_manager_attr_t    *attr_array,
    char                              **local_contact_out,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_i_net_manager_context_t *    ctx = context;
    globus_list_t *                     list;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_net_manager_attr_t *         tmp_attr_array = NULL;
    char *                              tmp_local_contact = NULL;
    globus_i_net_manager_context_entry_t * ent;
    GlobusNetManagerName(globus_net_manager_context_post_listen);
    
    if(!ctx || !task_id || !transport || !attr_array || !attr_array_out ||
        !local_contact || !local_contact_out)
    {
        result = GlobusNetManagerErrorParameter("No parameter may be NULL.");
        goto error_bad_args;
    }
    
    for(list = ctx->managers; 
        !globus_list_empty(list) && result == GLOBUS_SUCCESS; 
        list = globus_list_rest(list))
    {            
        ent = globus_list_first(list);
        
        if(ent->manager->post_listen)
        {   
            globus_net_manager_attr_t *     ret_attr_array = NULL;
            char *                          ret_local_contact = NULL;
            
            result = ent->manager->post_listen(
                ent->manager,
                ent->attrs,
                task_id,
                transport,
                tmp_local_contact ? tmp_local_contact : local_contact,
                tmp_attr_array ? tmp_attr_array : attr_array,
                &ret_local_contact,
                &ret_attr_array);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusNetManagerErrorManager(
                    result, ent->manager->name, "post_listen");
            }
                
            if(ret_attr_array != NULL)
            {
                globus_net_manager_attr_array_delete(tmp_attr_array);
                tmp_attr_array = ret_attr_array;
            }
            if(ret_local_contact != NULL)
            {
                if(tmp_local_contact)
                {
                    globus_free(tmp_local_contact);
                }
                tmp_local_contact = ret_local_contact;
            }
        }
    }
    
    *attr_array_out = tmp_attr_array;
    *local_contact_out = tmp_local_contact;

    return result;

error_bad_args:
    return result;
}
