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

static
int
globus_l_gram_job_manager_state_file_lock(
    int					fd);

/**
 * Compute the name of the state file to use for this job request.
 *
 * Sets the value of the @a job_state_file member of the request structure.
 *
 * @param request
 *        The request to modify.
 */
void
globus_gram_job_manager_state_file_set(
    globus_gram_jobmanager_request_t *	request)
{
    char				buffer[1024];
    char 				my_host[MAXHOSTNAMELEN];

    globus_libc_gethostname(my_host, sizeof(my_host));

    if(request->job_state_file_dir == GLOBUS_NULL)
    {
	sprintf(buffer, "%s/tmp/gram_job_state/%s.%s.%s",
		request->globus_location,
		request->logname ? request->logname : "globus",
		my_host,
		request->uniq_id);
    }
    else
    {
	sprintf(buffer, "%s/job.%s.%s", request->job_state_file_dir, my_host,
		request->uniq_id);
    }

    request->job_state_file = (char *) globus_libc_strdup (buffer);

    sprintf(buffer, "%s.lock", request->job_state_file);
    request->job_state_lock_file = (char *) globus_libc_strdup( buffer );
}
/* globus_gram_job_manager_state_file_set() */

int
globus_gram_job_manager_state_file_write(
    globus_gram_jobmanager_request_t *	request)
{
    int					rc = GLOBUS_SUCCESS;
    FILE *				fp;
    char				tmp_file[1024];

    if ( request->job_state_lock_file != NULL &&
	 request->job_state_lock_fd < 0 )
    {
	globus_gram_job_manager_request_log(request,
				"JM: Creating and locking state lock file\n");

	request->job_state_lock_fd = open( request->job_state_lock_file,
					   O_RDWR | O_CREAT,
					   S_IRUSR | S_IWUSR );
	if ( request->job_state_lock_fd < 0 )
	{
	    globus_gram_job_manager_request_log(request,
			"JM: Failed to open state lock file '%s', errno=%d\n",
			request->job_state_lock_file, errno);

	    return GLOBUS_FAILURE;
	}

	rc = globus_l_gram_job_manager_state_file_lock(
						request->job_state_lock_fd );
	if ( rc != GLOBUS_SUCCESS )
	{
	    globus_gram_job_manager_request_log(request,
			"JM: Failed to lock state lock file '%s', errno=%d\n",
			request->job_state_lock_file, errno);
	    /* unlink here? */
	    close( request->job_state_lock_fd );
	    return GLOBUS_FAILURE;
	}
    }

    /*
     * We want the file update to be "atomic", so create a new temp file,
     * write the new information, close the new file, then rename the new
     * file on top of the old one. The rename is the atomic update action.
     */

    strcpy( tmp_file, request->job_state_file );
    strcat( tmp_file, ".tmp" );

    globus_gram_job_manager_request_log(request, "JM: Writing state file\n");

    fp = fopen( tmp_file, "w" );
    if ( fp == NULL )
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: Failed to open state file %s, errno=%d\n",
		tmp_file,
		errno);

	return GLOBUS_FAILURE;
    }

    rc = fprintf(fp, "%s\n", request->job_contact ? request->job_contact : " ");
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%4d\n", (int) request->jobmanager_state);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%4d\n", (int) request->status);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%4d\n", request->failure_code);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->job_id ? request->job_id : " ");
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->rsl_spec);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->cache_tag);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->jobmanager_type);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%d\n", request->two_phase_commit);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->scratchdir ? request->scratchdir : " ");
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%lu\n", (unsigned long) request->seg_last_timestamp);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%lu\n", (unsigned long) request->creation_time);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%lu\n", (unsigned long) request->queued_time);
    if (rc < 0)
    {
        goto error_exit;
    }

    globus_gram_job_manager_output_write_state(request, fp);
    globus_gram_job_manager_staging_write_state(request,fp);

    fclose( fp );

    rc = rename( tmp_file, request->job_state_file );
    if (rc != 0)
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: Failed to rename state file\n");
	rc = GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;

error_exit:
    fclose(fp);
    remove(tmp_file);
    return GLOBUS_FAILURE;
}
/* globus_gram_job_manager_state_file_write() */

int
globus_gram_job_manager_state_file_read(
    globus_gram_jobmanager_request_t *	request)
{
    FILE *				fp;
    char *                              buffer = NULL;
    size_t                              file_len;
    struct stat				statbuf;
    int					rc;
    int					i;
    unsigned long                       tmp_timestamp;

    globus_gram_job_manager_request_log(
	    request,
	    "JM: Attempting to read state file %s\n",
	    request->job_state_file);

    if (stat(request->job_state_file, &statbuf) != 0)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_NO_STATE_FILE;
    }
    file_len = (size_t) statbuf.st_size;
    buffer = malloc(file_len+1);
    if (buffer == NULL)
    {
        goto exit;
    }

    /* Try to obtain a lock on the state lock file */
    if ( request->job_state_lock_file != NULL &&
	 request->job_state_lock_fd < 0 )
    {
	globus_gram_job_manager_request_log(request,
				"JM: Locking state lock file\n");

	request->job_state_lock_fd = open( request->job_state_lock_file,
					   O_RDWR );
	if ( request->job_state_lock_fd < 0 )
	{
	    globus_gram_job_manager_request_log(request,
			"JM: Failed to open state lock file '%s', errno=%d\n",
			request->job_state_lock_file, errno);

	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;

            goto free_buffer_exit;
	}

	rc = globus_l_gram_job_manager_state_file_lock(
						request->job_state_lock_fd );
	if ( rc != GLOBUS_SUCCESS )
	{
	    if ( rc == GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE )
	    {
		globus_gram_job_manager_request_log(request,
			"JM: State lock file is locked, old jm is still alive\n");
		fp = fopen( request->job_state_file, "r" );
		if(fp)
		{
		    fgets( buffer, file_len, fp );
		    buffer[strlen(buffer)-1] = '\0';
		    request->old_job_contact = globus_libc_strdup(buffer);
		    fclose(fp);
		}
	    }
	    else
	    {
		globus_gram_job_manager_request_log(request,
			"JM: Failed to lock state lock file '%s', errno=%d\n",
			request->job_state_lock_file, errno);
	    }

	    /* unlink here? */
	    close( request->job_state_lock_fd );

            free(buffer);

	    return rc;
	}
    }

    fp = fopen( request->job_state_file, "r" );
    if(!fp)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_NO_STATE_FILE;
    }

    if(fgets( buffer, file_len, fp )  == NULL)
    {
        goto error_exit;
    }
    /* job contact string */
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    request->restart_state = atoi( buffer );
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    globus_gram_job_manager_request_set_status_time(request,
		atoi( buffer ), statbuf.st_mtime);
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    request->failure_code = atoi( buffer );

    if(fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    if(strcmp(buffer, " ") != 0)
    {
	request->job_id = globus_libc_strdup( buffer );
    }
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    request->rsl_spec = globus_libc_strdup( buffer );
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    request->cache_tag = globus_libc_strdup( buffer );
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    if((sscanf(buffer,"%d",&i)) < 1)
    {
	/* The last line we grabbed was the jobmanager_type. Now we
	 * need to grab the two_phase_commit number. Older jobmanagers
	 * don't print the jobmanager_type to the state file, hence
	 * the check above.
	 */
	if(fgets( buffer, file_len, fp ) == NULL)
        {
            goto error_exit;
        }
	buffer[strlen(buffer)-1] = '\0';
    }
    request->two_phase_commit = atoi(buffer);
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    if(strcmp(buffer, " ") != 0)
    {
	/*
	 * Need to set the RSL substitution before reading the staging
	 * state---otherwise we may get an RSL evaluation error
	 */
	request->scratchdir = globus_libc_strdup(buffer);
	globus_symboltable_insert(
		&request->symbol_table,
		"SCRATCH_DIRECTORY",
		request->scratchdir);
    }
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    sscanf(buffer, "%lu", &tmp_timestamp);
    request->seg_last_timestamp = (time_t) tmp_timestamp;

    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    sscanf(buffer, "%lu", &tmp_timestamp);
    request->creation_time = (time_t) tmp_timestamp;
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    sscanf(buffer, "%lu", &tmp_timestamp);
    request->queued_time = (time_t) tmp_timestamp;

    rc = globus_gram_job_manager_output_read_state(request, fp);
    if(rc != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    rc = globus_gram_job_manager_staging_read_state(request,fp);
    if(rc != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    fclose(fp);

    free(buffer);

    return GLOBUS_SUCCESS;
error_exit:
    fclose(fp);
free_buffer_exit:
    if (buffer != NULL)
    {
        free(buffer);
    }
exit:
    return GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;
}

static
int
globus_l_gram_job_manager_state_file_lock(
    int					fd)
{
    int rc;
#if 0
    while( (rc = flock( fd, LOCK_EX | LOCK_NB )) < 0 )
    {
	if ( errno == EWOULDBLOCK )
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE;
	    break;
	}
	else if ( errno != EINTR )
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE
	    break;
	}
    }
#else
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    while( (rc = fcntl( fd, F_SETLK, &fl )) < 0 )
    {
	if ( errno == EACCES || errno == EAGAIN )
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE;
	    break;
	}
	else if ( errno != EINTR )
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;
	    break;
	}
    }
#endif
    return rc;
}
/* globus_l_gram_job_manager_state_file_lock() */

int
globus_gram_job_manager_state_file_find_all(
    globus_gram_jobmanager_request_t *	request)
{
    int                                 rc = GLOBUS_SUCCESS;
    char                                buffer[1024];
    char *                              pattern;
    char                                my_host[MAXHOSTNAMELEN];
    DIR *                               dp;
    struct dirent *                     de;
    long                                id[2];
    globus_gram_jobmanager_request_t *  new_request;

    globus_gram_job_manager_request_log(request,
            "JM: Creating restart requests for all saved jobs\n");

    globus_libc_gethostname(my_host, sizeof(my_host));

    dp = opendir(request->job_state_file_dir);
    if (dp == NULL)
    {
        return GLOBUS_SUCCESS;
    }

    pattern = globus_common_create_string("job.%s.%%ld.%%ld%%n",
            my_host);

	sprintf(buffer, "%s/job.%s.%s", request->job_state_file_dir, my_host,
		request->uniq_id);
    if (pattern == NULL)
    {
        closedir(dp);
        return GLOBUS_SUCCESS;
    }

    while ((de = readdir(dp)) != NULL)
    {
        int n;
        int p;

        globus_gram_job_manager_request_log(request,
                "JM: Checking for file %s\n",
                de->d_name);

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
        {
            globus_gram_job_manager_request_log(request,
                    "JM: Skipping %s: ./.. check\n", de->d_name);

            continue;
        }

        p = sscanf(de->d_name, pattern, &id[0], &id[1], &n);

        if (p < 2)
        {
            globus_gram_job_manager_request_log(request,
                    "JM: Skipping %s: scanf failure\n", de->d_name);
            continue;
        }

        globus_gram_job_manager_request_log(request,
                "JM: .lock check: %s\n", de->d_name + n);
        if (strcmp(de->d_name + n, ".lock") == 0)
        {
            globus_gram_job_manager_request_log(request,
                    "JM: Skipping %s: .lock check\n", de->d_name);
            continue;
        }

        rc = globus_gram_job_manager_request_copy(&new_request, request);
        if (rc != GLOBUS_SUCCESS)
        {
            break;
        }
        new_request->jm_restart = globus_common_create_string(
                "https://%s:0/%ld/%ld",
                my_host, id[0], id[1]);
        globus_gram_job_manager_request_log(request,
                "JM: Created fake restart url: %s\n",
                new_request->jm_restart);
        globus_list_insert(&request->restart_jms, new_request);
    }
    closedir(dp);
    free(pattern);

    globus_gram_job_manager_request_log(request,
            "JM: Will try to process %d jobs\n", 
            (int) globus_list_size(request->restart_jms));

    return rc;
}
/* globus_gram_job_manager_state_file_find_all() */
