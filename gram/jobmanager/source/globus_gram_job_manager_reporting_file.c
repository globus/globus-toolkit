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

enum
{
    GLOBUS_GRAM_JOB_MANAGER_REPORTING_FILE_SECONDS = 600,
    GLOBUS_GRAM_JOB_MANAGER_REPORTING_CLEANUP_PERIOD = 60
};

static
void
globus_l_gram_job_manager_reporting_file_cleaner(
    void *				callback_arg);

int
globus_gram_job_manager_reporting_file_set(
    globus_gram_jobmanager_request_t *	request)
{
    if(request->job_reporting_file)
    {
	globus_libc_free(request->job_reporting_file);
	request->job_reporting_file = NULL;
    }

    if(request->job_reporting_dir)
    {
	request->job_reporting_file = globus_libc_malloc(
		strlen(request->job_reporting_dir) +
		strlen(request->rdn) +
		strlen(request->logname) +
		strlen(request->uniq_id) + 4);

	sprintf(request->job_reporting_file,
		"%s/%s_%s.%s",
		request->job_reporting_dir,
		request->rdn,
		request->logname,
		request->uniq_id);
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_reporting_file_set() */

int
globus_gram_job_manager_reporting_file_create(
    globus_gram_jobmanager_request_t *	request)
{
    FILE *				status_fp;
    char * 				status_str;
    struct stat				statbuf;

    globus_gram_job_manager_request_log(
	    request,
	    "JM: in globus_gram_job_manager_reporting_file_create()\n");

    if ((!request->publish_jobs) ||
        (request->job_reporting_file == NULL))
    {
        globus_gram_job_manager_request_log(
	   request,
	   "JM: not reporting job information\n");

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

    if(stat(request->job_reporting_file, &statbuf) == 0)
    {
	/* The job file exists, so just update the first line (job state) */
	status_fp = fopen(request->job_reporting_file, "r+");

	if(status_fp == NULL)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "JM: Failed opening job reporting file %s\n",
		    request->job_reporting_file);
	    return GLOBUS_FAILURE;
	}
	fprintf(status_fp, "%s\n", status_str);
    }
    else if((status_fp = fopen(request->job_reporting_file, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: Failed opening job reporting file %s\n",
		request->job_reporting_file);

	return GLOBUS_FAILURE;
    }
    else
    {
        fprintf(status_fp, "%s\n%s\n%s\n%s\n%s\n",
                status_str,
                request->rsl_spec,
                request->job_contact,
                request->job_id,
                request->globus_id);
    }
    fclose(status_fp);

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_reporting_file_create() */

int
globus_gram_job_manager_reporting_file_remove(
    globus_gram_jobmanager_request_t *	request)
{
    globus_gram_job_manager_request_log(
	    request,
	    "JM: in globus_gram_job_manager_reporting_file_remove()\n");

    if(request->job_reporting_file == NULL)
    {
	return GLOBUS_SUCCESS;
    }
    else
    {
	remove(request->job_reporting_file);
	globus_libc_free(request->job_reporting_file);
	request->job_reporting_file = NULL;
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_reporting_file_remove() */

int
globus_gram_job_manager_reporting_file_start_cleaner(
    globus_gram_jobmanager_request_t *	request)
{
    globus_reltime_t			period;
    globus_reltime_t			delay;

    GlobusTimeReltimeSet(period,
	                 GLOBUS_GRAM_JOB_MANAGER_REPORTING_CLEANUP_PERIOD,
			 0);
    GlobusTimeReltimeSet(delay,
	                 GLOBUS_GRAM_JOB_MANAGER_REPORTING_CLEANUP_PERIOD,
			 0);

    globus_callback_register_periodic(
	    &request->reporting_file_cleanup_timer,
	    &delay,
	    &period,
	    globus_l_gram_job_manager_reporting_file_cleaner,
	    request);

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_reporting_file_start_cleaner() */

int
globus_gram_job_manager_reporting_file_stop_cleaner(
    globus_gram_jobmanager_request_t *	request)
{
    globus_callback_unregister(request->reporting_file_cleanup_timer,
                               NULL,
			       NULL,
			       NULL);
    request->reporting_file_cleanup_timer = GLOBUS_HANDLE_TABLE_NO_HANDLE;

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_reporting_file_stop_cleaner() */

static
void
globus_l_gram_job_manager_reporting_file_cleaner(
    void *				callback_arg)
{
    time_t				now;
    DIR *				status_dir;
    globus_gram_jobmanager_request_t *	request;
    char *				query_str;
    struct dirent *			dir_entry = NULL;
    char *				stat_file_path;
    struct stat				statbuf;

    request = callback_arg;

    globus_mutex_lock(&request->mutex);

    if(request->job_reporting_dir == NULL)
    {
	goto error_exit;
    }

    status_dir = globus_libc_opendir(request->job_reporting_dir);
    if(status_dir == NULL)
    {
	goto error_exit;
    }

    now = time(NULL);

    query_str = globus_libc_malloc(strlen(request->logname) + 3);

    sprintf(query_str, "_%s.", request->logname);

    for(globus_libc_readdir_r(status_dir, &dir_entry);
	dir_entry != NULL;
	globus_libc_free(dir_entry),
	globus_libc_readdir_r(status_dir, &dir_entry))
    {
	if(strstr(dir_entry->d_name, query_str) != NULL)
	{
	    stat_file_path =
		globus_libc_malloc(
			strlen(request->job_reporting_dir) +
			strlen(dir_entry->d_name) + 2);
	    sprintf(stat_file_path,
		    "%s/%s",
		    request->job_reporting_dir,
		    dir_entry->d_name);

	    if(stat(stat_file_path, &statbuf) == 0)
	    {
		if(now - statbuf.st_mtime >
			GLOBUS_GRAM_JOB_MANAGER_REPORTING_FILE_SECONDS)
		{
		    globus_gram_job_manager_request_log(
			    request,
			    "JM: status file has not been modified "
			    "in %d seconds\n",
			    GLOBUS_GRAM_JOB_MANAGER_REPORTING_FILE_SECONDS);

                    if (remove(stat_file_path) != 0)
                    {
                        globus_gram_job_manager_request_log(
				request,
				"JM: Cannot remove old status file --> %s\n",
				stat_file_path);
                    }
                    else
                    {
                        globus_gram_job_manager_request_log(
				request,
                                "JM: Removed old status file --> %s\n",
                                stat_file_path);
                    }
		}
	    }
	    globus_libc_free(stat_file_path);
	}
    }
    if(dir_entry != NULL)
    {
	globus_libc_free(dir_entry);
    }
    globus_libc_closedir(status_dir);

  error_exit:
    globus_mutex_unlock(&request->mutex);
}
/* globus_gram_job_manager_reporting_file_cleaner() */
