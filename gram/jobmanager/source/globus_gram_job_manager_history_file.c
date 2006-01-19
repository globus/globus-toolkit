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

#include "globus_gram_job_manager.h"

#include <string.h>

int
globus_gram_job_manager_history_file_set(
    globus_gram_jobmanager_request_t *  request)
{
    char                           my_host[MAXHOSTNAMELEN];

    globus_libc_gethostname(my_host, sizeof(my_host));

    if(request->job_history_file)
    {
        globus_libc_free(request->job_history_file);
        request->job_history_file = NULL;
    }

    if(request->job_history_dir)
    {
        request->job_history_file = globus_libc_malloc(
                strlen(request->job_history_dir) +
                strlen(my_host) +
                strlen(request->jobmanager_type) +
                strlen(request->uniq_id) + 12);
  
        sprintf( request->job_history_file,
                 "%s/history.%s-%s_%s",
                 request->job_history_dir,
                 my_host,
                 request->jobmanager_type,
                 request->uniq_id );
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_history_file_set() */

int
globus_gram_job_manager_history_file_create(
    globus_gram_jobmanager_request_t *  request)
{
    FILE *                              history_fp;
    char *                              status_str;
    struct stat                         statbuf;
    unsigned long                       timestamp;

    globus_gram_job_manager_request_log(
            request,
            "JM: in globus_gram_job_manager_history_file_create()\n");

    timestamp = time(0);

    if(!request->job_history_dir)
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

    if(stat(request->job_history_file, &statbuf) == 0)
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
                request->globus_id,
                status_str,timestamp);
    }
    fclose(history_fp);

    return GLOBUS_SUCCESS;
}

