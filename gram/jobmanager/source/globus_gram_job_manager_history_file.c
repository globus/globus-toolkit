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

#include "globus_gram_job_manager.h"

#include <string.h>

/**
 * Determine the name of the job history file for this job request
 *
 * @param request
 *     Job to create file name for. The request's @a job_history_file member
 *     is modified by this function.
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 */
int
globus_gram_job_manager_history_file_set(
    globus_gram_jobmanager_request_t *  request)
{
    int                                 rc = GLOBUS_SUCCESS;

    if (! request->config->job_history_dir)
    {
        request->job_history_file = NULL;
        goto no_history;
    }

    request->job_history_file = globus_common_create_string(
             "%s/history.%s-%s_%s",
             request->config->job_history_dir,
             request->config->hostname,
             request->config->jobmanager_type,
             request->uniq_id );
    
    if (request->job_history_file == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto history_file_malloc_failed;
    }

history_file_malloc_failed:
no_history:
    return rc;
}
/* globus_gram_job_manager_history_file_set() */

/**
 * Create job or update the job history file
 *
 * @param request
 *     Job to create or update the job history file for. If the file exists,
 *     information about the new job state is appended to it. Otherwise, 
 *     the file is created and information about the RSL, job contact, and
 *     client identity are recorded along with the new job state data.
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 */
int
globus_gram_job_manager_history_file_create(
    globus_gram_jobmanager_request_t *  request)
{
    FILE *                              history_fp;
    char *                              status_str;
    unsigned long                       timestamp;

    globus_gram_job_manager_request_log(
            request,
            "JM: in globus_gram_job_manager_history_file_create()\n");

    timestamp = time(0);

    if(!request->config->job_history_dir)
    {
        return GLOBUS_SUCCESS;
    }

    switch(request->status)
    {
      case GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING:
        status_str = "PENDING    ";
        break;
      case GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE:
        status_str = "ACTIVE     ";
        break;
      case GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED:
        if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT)
            status_str = "JOBMANAGER_STOP";
        else
            status_str = "FAILED     ";
        break;
      case GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE:
        status_str = "DONE       ";
        break;
      case GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED:
        status_str = "SUSPENDED  ";
        break;
      case GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED:
        status_str = "UNSUBMITTED ";
        break;
      case GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN:
        status_str = "STAGE_IN    ";
        break;
      case GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_OUT:
        status_str = "STAGE_OUT   ";
        break;
      default:
        status_str = "UNKNOWN     ";
        break;
    }

    if(access(request->job_history_file, F_OK) == 0)
    {
        /* the file exists, so just append a line which has the
         * job status and timestamp
         */
        history_fp = fopen(request->job_history_file, "a+");

        if(history_fp == NULL)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: Failed opening job history file %s\n",
                    request->job_history_file);
            return GLOBUS_FAILURE;
        }
        fprintf(history_fp, "%s\t%10ld\n", status_str,timestamp);
    }
    else if((history_fp = fopen(request->job_history_file, "w")) == NULL)
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: Failed opening job history file %s\n",
                request->job_history_file);

        return GLOBUS_FAILURE;
    }
    else
    {
        fprintf(history_fp, "%s\n%s\n%s\n%s\t%10ld\n",
                request->rsl_spec,
                request->job_contact,
                request->config->subject,
                status_str,timestamp);
    }
    fclose(history_fp);

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_history_file_create() */
