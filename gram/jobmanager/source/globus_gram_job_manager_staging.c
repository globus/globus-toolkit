/*
 * Copyright 1999-2009 University of Chicago
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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gram_job_manager_staging.c GRAM Job Manager Staging Tracking
 *
 * CVS Information:
 *
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */

#include "globus_gram_job_manager.h"
#include "globus_rsl_assist.h"

#include <string.h>

static
int
globus_l_gram_job_manager_staging_add_pair(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_value_t *                from,
    globus_rsl_value_t *                to,
    const char *                        type);

static
globus_bool_t
globus_l_gram_job_manager_staging_match(
    void *                              datum,
    void *                              arg);

static
void
globus_l_gram_job_manager_staging_free_all(
    globus_gram_jobmanager_request_t *  request);

static
int
globus_l_gram_staging_list_read_state(
    globus_gram_jobmanager_request_t *  request,
    FILE *                              fp,
    char *                              buffer,
    globus_gram_job_manager_staging_type_t
                                        staging_type,
    globus_list_t **                    staging_list);
#endif

int
globus_gram_job_manager_staging_create_list(
    globus_gram_jobmanager_request_t *  request)
{
    int                                 i;
    int                                 rc;
    globus_rsl_value_t *                from;
    globus_rsl_value_t *                to;
    globus_rsl_t *                      tmp_rsl;
    globus_list_t *                     list;
    globus_list_t *                     pairs;
    char *                              can_stage_list[] =
    {
        GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_PARAM,
        GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_SHARED_PARAM,
        GLOBUS_GRAM_PROTOCOL_FILE_STAGE_OUT_PARAM,
        NULL
    };

    if(request->jm_restart)
    {
        return GLOBUS_SUCCESS;
    }
    tmp_rsl = globus_rsl_parse(request->rsl_spec);
    globus_rsl_assist_attributes_canonicalize(tmp_rsl);

    for(i = 0; can_stage_list[i] != NULL; i++)
    {
        list = globus_rsl_param_get_values(tmp_rsl, can_stage_list[i]);

        if(!list)
        {
            continue;
        }

        while(!globus_list_empty(list))
        {
            pairs = globus_rsl_value_sequence_get_value_list(
                    globus_list_first(list));
            list = globus_list_rest(list);

            if(globus_list_size(pairs) != 2)
            {
                switch(i)
                {
                  case 0:
                    rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_IN;
                    break;
                  case 1:
                    rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_IN_SHARED;
                    break;
                  case 2:
                    rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_OUT;
                    break;
                }
                goto failed_adding_exit;
            }

            from = globus_list_first(pairs);
            to = globus_list_first(globus_list_rest(pairs));

            rc = globus_l_gram_job_manager_staging_add_pair(
                    request,
                    from,
                    to,
                    can_stage_list[i]);

            if(rc != GLOBUS_SUCCESS)
            {
                goto failed_adding_exit;
                
            }
        }
    }
    globus_rsl_free_recursive(tmp_rsl);

    return GLOBUS_SUCCESS;
failed_adding_exit:
    globus_rsl_free_recursive(tmp_rsl);
    globus_l_gram_job_manager_staging_free_all(request);
    return rc;
}
/* globus_gram_job_manager_staging_create_list() */

int
globus_gram_job_manager_staging_remove(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_job_manager_staging_type_t
                                        type,
    char *                              from,
    char *                              to)
{
    globus_gram_job_manager_staging_info_t 
                                        query;
    globus_gram_job_manager_staging_info_t *
                                        item;
    globus_list_t **                    list;
    globus_list_t *                     node;
    const char *                        typestr = "";

    switch(type)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN:
          typestr = "file_stage_in";
          break;
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED:
          typestr = "file_stage_in_shared";
          break;
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT:
          typestr = "file_stage_out";
          break;
    }

    globus_gram_job_manager_request_log(
            request,
            "JM: Finished staging (%s = (%s %s))\n",
            typestr,
            from,
            to);

    query.evaled_from = from;
    query.evaled_to = to;
    query.type = type;

    switch(type)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN:
        list = &request->stage_in_todo;
        break;
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED:
        list = &request->stage_in_shared_todo;
        break;
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT:
        list = &request->stage_out_todo;
        break;
    }

    node = globus_list_search_pred(
            *list,
            globus_l_gram_job_manager_staging_match,
            &query);

    if(node)
    {
        item = globus_list_remove(list, node);

        globus_rsl_value_free_recursive(item->from);
        globus_rsl_value_free_recursive(item->to);
        free(item->evaled_from);
        free(item->evaled_to);
        free(item);

        globus_gram_job_manager_request_log(
            request,
            "JM: successfully removed (%s = (%s %s)) from todo list\n",
            typestr,
            from,
            to);
    }
    else
    {
        globus_gram_job_manager_request_log(
            request,
            "JM: strange... (%s = (%s %s)) wasn't in the todo list\n",
            typestr,
            from,
            to);
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_staging_remove() */

int
globus_gram_job_manager_staging_write_state(
    globus_gram_jobmanager_request_t *  request,
    FILE *                              fp)
{
    globus_list_t *                     tmp_list;
    globus_gram_job_manager_staging_info_t *
                                        info;
    char *                              tmp_str;
    int                                 rc;

    rc = fprintf(fp, "%d\n", globus_list_size(request->stage_in_todo));

    if (rc < 0)
    {
        return GLOBUS_FAILURE;
    }

    tmp_list = request->stage_in_todo;
    while(!globus_list_empty(tmp_list))
    {
        info = globus_list_first(tmp_list);
        tmp_list = globus_list_rest(tmp_list);

        tmp_str = globus_rsl_value_unparse(info->from);
        rc = fprintf(fp, "%s\n", tmp_str);
        free(tmp_str);
        if (rc < 0)
        {
            return GLOBUS_FAILURE;
        }

        tmp_str = globus_rsl_value_unparse(info->to);
        rc = fprintf(fp, "%s\n", tmp_str);
        free(tmp_str);
        if (rc < 0)
        {
            return GLOBUS_FAILURE;
        }
    }
    rc = fprintf(fp, "%d\n", globus_list_size(request->stage_in_shared_todo));
    if (rc < 0)
    {
        return GLOBUS_FAILURE;
    }
    tmp_list = request->stage_in_shared_todo;
    while(!globus_list_empty(tmp_list))
    {
        info = globus_list_first(tmp_list);
        tmp_list = globus_list_rest(tmp_list);

        tmp_str = globus_rsl_value_unparse(info->from);
        rc = fprintf(fp, "%s\n", tmp_str);
        free(tmp_str);
        if (rc < 0)
        {
            return GLOBUS_FAILURE;
        }

        tmp_str = globus_rsl_value_unparse(info->to);
        rc = fprintf(fp, "%s\n", tmp_str);
        free(tmp_str);
        if (rc < 0)
        {
            return GLOBUS_FAILURE;
        }
    }
    rc = fprintf(fp, "%d\n", globus_list_size(request->stage_out_todo));
    if (rc < 0)
    {
        return GLOBUS_FAILURE;
    }
    tmp_list = request->stage_out_todo;
    while(!globus_list_empty(tmp_list))
    {
        info = globus_list_first(tmp_list);
        tmp_list = globus_list_rest(tmp_list);

        tmp_str = globus_rsl_value_unparse(info->from);
        rc = fprintf(fp, "%s\n", tmp_str);
        free(tmp_str);

        if (rc < 0)
        {
            return GLOBUS_FAILURE;
        }

        tmp_str = globus_rsl_value_unparse(info->to);
        rc = fprintf(fp, "%s\n", tmp_str);
        free(tmp_str);
        if (rc < 0)
        {
            return GLOBUS_FAILURE;
        }
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_staging_write_state() */

int
globus_gram_job_manager_staging_read_state(
    globus_gram_jobmanager_request_t *  request,
    FILE *                              fp)
{
    int                                 rc = GLOBUS_SUCCESS;
    char *                              buffer;
    size_t                              buffer_len;
    long                                offset;

    offset = ftell(fp);
    if (fseek(fp, 0, SEEK_END) < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

        goto out;
    }

    buffer_len = ftell(fp) - offset;

    if (fseek(fp, offset, SEEK_SET) < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

        goto out;
    }

    buffer = malloc(buffer_len+1);
    if (buffer == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto out;
    }

    rc = globus_l_gram_staging_list_read_state(
        request,
        fp,
        buffer,
        GLOBUS_GRAM_JOB_MANAGER_STAGE_IN,
        &request->stage_in_todo);

    if (rc != GLOBUS_SUCCESS)
    {
        goto free_buffer_out;
    }

    rc = globus_l_gram_staging_list_read_state(
        request,
        fp,
        buffer,
        GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED,
        &request->stage_in_shared_todo);

    if (rc != GLOBUS_SUCCESS)
    {
        goto free_buffer_out;
    }

    rc = globus_l_gram_staging_list_read_state(
        request,
        fp,
        buffer,
        GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT,
        &request->stage_out_todo);

free_buffer_out:
    free(buffer);
out:
    return rc;
}
/* globus_gram_job_manager_staging_read_state() */

static
int
globus_l_gram_job_manager_staging_add_pair(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_value_t *                from,
    globus_rsl_value_t *                to,
    const char *                        type)
{
    int                                 rc;
    globus_gram_job_manager_staging_info_t *
                                        info;

    info = calloc(
            1,
            sizeof(globus_gram_job_manager_staging_info_t));
    if(!info)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto info_calloc_failed;
    }

    info->from = globus_rsl_value_copy_recursive(from);
    info->to = globus_rsl_value_copy_recursive(to);

    if(strcmp(type, GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_PARAM) == 0)
    {
        info->type = GLOBUS_GRAM_JOB_MANAGER_STAGE_IN;
    }
    else if(strcmp(type, GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_SHARED_PARAM)== 0)
    {
        info->type = GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED;

    }
    else if(strcmp(type, GLOBUS_GRAM_PROTOCOL_FILE_STAGE_OUT_PARAM) == 0)
    {
        info->type = GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT;
    }

    rc = globus_gram_job_manager_rsl_evaluate_value(
            request,
            info->from,
            &info->evaled_from);

    if(!info->evaled_from)
    {
        if(rc == GLOBUS_SUCCESS)
        {
            /* Not a literal after a successful eval */
            switch(info->type)
            {
              case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN:
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_IN;
                break;
              case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED:
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_IN_SHARED;
                break;
              case GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT:
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_OUT;
                break;
            }
        }

        goto eval_from_failed;
    }
    rc = globus_gram_job_manager_rsl_evaluate_value(
            request,
            info->to,
            &info->evaled_to);

    if(!info->evaled_to)
    {
        if(rc == GLOBUS_SUCCESS)
        {
            /* Not a literal after a successful eval */
            switch(info->type)
            {
              case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN:
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_IN;
                break;
              case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED:
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_IN_SHARED;
                break;
              case GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT:
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_OUT;
                break;
            }
        }

        goto eval_to_failed;
    }

    switch(info->type)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN:
        globus_list_insert(&request->stage_in_todo, info);
        break;
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED:
        globus_list_insert(&request->stage_in_shared_todo, info);
        break;
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT:
        globus_list_insert(&request->stage_out_todo, info);
        break;
    }

    return GLOBUS_SUCCESS;

eval_to_failed:
    free(info->evaled_from);
eval_from_failed:
    free(info);
info_calloc_failed:
    return rc;
}
/* globus_l_gram_job_manager_staging_add_url() */

static
globus_bool_t
globus_l_gram_job_manager_staging_match(
    void *                              datum,
    void *                              arg)
{
    globus_gram_job_manager_staging_info_t *
                                        item;
    globus_gram_job_manager_staging_info_t *
                                        query;

    item = datum;
    query = arg;

    globus_assert(item->type == query->type);

    if((strcmp(item->evaled_from, query->evaled_from) == 0) &&
       (strcmp(item->evaled_to, query->evaled_to) == 0))
    {
        return GLOBUS_TRUE;
    }
    else
    {
        return GLOBUS_FALSE;
    }
}
/* globus_l_gram_job_manager_staging_match() */

static
void
globus_l_gram_job_manager_staging_free_all(
    globus_gram_jobmanager_request_t *  request)
{
    globus_gram_job_manager_staging_info_t *
                                        info;

    while(!globus_list_empty(request->stage_in_todo))
    {
        info = globus_list_remove(&request->stage_in_todo,
                                  request->stage_in_todo);

        globus_rsl_value_free_recursive(info->from);
        globus_rsl_value_free_recursive(info->to);
        free(info->evaled_from);
        free(info->evaled_to);
        free(info);
    }
    while(!globus_list_empty(request->stage_in_shared_todo))
    {
        info = globus_list_remove(&request->stage_in_shared_todo,
                                  request->stage_in_shared_todo);

        globus_rsl_value_free_recursive(info->from);
        globus_rsl_value_free_recursive(info->to);
        free(info->evaled_from);
        free(info->evaled_to);
        free(info);
    }
    while(!globus_list_empty(request->stage_out_todo))
    {
        info = globus_list_remove(&request->stage_out_todo,
                                  request->stage_out_todo);

        globus_rsl_value_free_recursive(info->from);
        globus_rsl_value_free_recursive(info->to);
        free(info->evaled_from);
        free(info->evaled_to);
        free(info);
    }
}
/* globus_l_gram_job_manager_staging_free_all() */

/**
 * Read a list of staging pairs from the state file
 *
 * @param request
 *     Job request associated with the state file (used for
 *     RSL evaluation)
 * @param fp
 *     State file opened for reading
 * @param buffer
 *     Buffer containing the state file data
 * @param staging_type
 *     Type of staging list to read
 * @param staging_list
 *     List to insert the staging work into.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE
 *     Error reading state file
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Out of memory
 */
static
int
globus_l_gram_staging_list_read_state(
    globus_gram_jobmanager_request_t *  request,
    FILE *                              fp,
    char *                              buffer,
    globus_gram_job_manager_staging_type_t
                                        staging_type,
    globus_list_t **                    staging_list)
{
    int                                 rc = GLOBUS_SUCCESS;
    int                                 i, tmp_list_size;
    globus_gram_job_manager_staging_info_t *
                                        info;

    if (fscanf(fp, "%[^\n]%*c", buffer) < 1)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

        goto out;
    }
    tmp_list_size = atoi(buffer);

    for(i = 0; i < tmp_list_size; i++)
    {
        info = calloc(
                1,
                sizeof(globus_gram_job_manager_staging_info_t));
        if (info == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto out;
        }

        info->type = staging_type;

        if(fscanf(fp, "%[^\n]%*c", buffer) < 1)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

            goto free_info_out;
        }
        rc = globus_gram_job_manager_rsl_parse_value(
                request, buffer, &info->from);
        if (rc != GLOBUS_SUCCESS)
        {
            goto free_info_out;
        }

        if(fscanf(fp, "%[^\n]%*c", buffer) < 1)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;

            goto free_info_from_out;
        }
        rc = globus_gram_job_manager_rsl_parse_value(
                request, buffer, &info->to);
        if (rc != GLOBUS_SUCCESS)
        {
            goto free_info_from_out;
        }

        rc = globus_gram_job_manager_rsl_evaluate_value(
                request,
                info->from,
                &info->evaled_from);

        if (rc != GLOBUS_SUCCESS)
        {
            goto free_info_to_out;
        }

        rc = globus_gram_job_manager_rsl_evaluate_value(
                request,
                info->to,
                &info->evaled_to);
        if (rc != GLOBUS_SUCCESS)
        {
            goto free_info_evaled_from_out;
        }

        globus_list_insert(staging_list, info);
    }

    if (rc != GLOBUS_SUCCESS)
    {
free_info_evaled_from_out:
        free(info->evaled_from);
free_info_to_out:
        free(info->to);
free_info_from_out:
        free(info->from);
free_info_out:
        free(info);
    }
out:
    return rc;
}
/* globus_l_gram_staging_list_read_state() */
