#include "globus_gram_job_manager.h"

#include <string.h>

enum
{
    GRAM_JOB_MANAGER_TTL_LIMIT = 60
};

static
globus_bool_t
globus_l_gram_job_manager_state_file_read(
    globus_abstime_t *			time_stop,
    void *				user_arg);

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
}
/* globus_gram_job_manager_state_file_set() */

int
globus_gram_job_manager_state_file_write(
    globus_gram_jobmanager_request_t *	request)
{
    int					rc = GLOBUS_SUCCESS;
    long				new_ttl;
    FILE *				fp;
    char				tmp_file[1024];

    /*
     * We want the file update to be "atomic", so create a new temp file,
     * write the new information, close the new file, then rename the new
     * file on top of the old one. The rename is the atomic update action.
     */

    strcpy( tmp_file, request->job_state_file );
    strcat( tmp_file, ".tmp" );

    globus_gram_job_manager_request_log(request, "JM: Writing state file\n");

    new_ttl = time(NULL) + GRAM_JOB_MANAGER_TTL_LIMIT;
    request->ttl_limit = new_ttl;

    fp = fopen( tmp_file, "w" );
    if ( fp == NULL )
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: Failed to open state file %s\n",
		tmp_file);

	return GLOBUS_FAILURE;
    }

    fprintf(fp, "%4d\n", (int) request->jobmanager_state);
    fprintf(fp, "%4d\n", (int) request->status);
    fprintf(fp, "%4d\n", request->failure_code);
    fprintf(fp, "%10ld\n", new_ttl);
    fprintf(fp, "%s\n", request->job_id ? request->job_id : " ");
    fprintf(fp, "%s\n", request->rsl_spec);
    fprintf(fp, "%s\n", request->cache_tag);
    fprintf(fp, "%s\n", request->scratchdir ? request->scratchdir : " ");

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
}
/* globus_gram_job_manager_state_file_write() */

int
globus_gram_job_manager_state_file_read(
    globus_gram_jobmanager_request_t *	request)
{
    long				curr_time;
    FILE *				fp;
    char				buffer[8192];
    struct stat				statbuf;
    globus_reltime_t			delay;

    globus_gram_job_manager_request_log(
	    request,
	    "JM: Attempting to read state file %s\n",
	    request->job_state_file);

    curr_time = time(NULL);

    if (stat(request->job_state_file, &statbuf) != 0)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_NO_STATE_FILE;
    }

    fp = fopen( request->job_state_file, "r" );
    if ( fp == NULL )
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;
    }

    fscanf( fp, "%[^\n]%*c", buffer );
    request->restart_state = atoi( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    request->status = atoi( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    request->failure_code = atoi( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    request->read_ttl = atoi( buffer );

    fclose(fp);

    if(request->read_ttl > curr_time)
    {
	globus_gram_job_manager_request_log(request,
		      "JM: state file TTL hasn't expired yet. Waiting...\n");
	GlobusTimeReltimeSet(delay, request->read_ttl - curr_time + 1, 0);
    }
    else
    {
	GlobusTimeReltimeSet(delay, 0, 0);
    }
    globus_callback_register_oneshot(
	    &request->poll_timer,
	    &delay,
	    globus_l_gram_job_manager_state_file_read,
	    request,
	    NULL,
	    NULL);

    return GLOBUS_SUCCESS;
}

static
globus_bool_t
globus_l_gram_job_manager_state_file_read(
    globus_abstime_t *			time_stop,
    void *				user_arg)
{
    globus_gram_jobmanager_request_t *	request;
    FILE *				fp;
    char				buffer[8192];
    struct stat				statbuf;
    long				new_ttl;
    globus_bool_t			event_registered;

    request = user_arg;

    globus_mutex_lock(&request->mutex);

    /* If a state change occurred before we got to read the
     * state file, then just process state changes.
     */
    if(request->jobmanager_state !=
	    GLOBUS_GRAM_JOB_MANAGER_STATE_READ_STATE_FILE)
    {
	goto state_machine_exit;
    }
    if (stat(request->job_state_file, &statbuf) != 0)
    {
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_NO_STATE_FILE;
	goto state_machine_exit;
    }
    fp = fopen( request->job_state_file, "r" );
    if(!fp)
    {
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_NO_STATE_FILE;
	goto state_machine_exit;
    }
    fscanf( fp, "%[^\n]%*c", buffer );
    request->restart_state = atoi( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    request->status = atoi( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    request->failure_code = atoi( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    new_ttl = atoi( buffer );

    if (new_ttl != request->read_ttl)
    {
	globus_gram_job_manager_request_log(request,
		      "JM: TTL was renewed! Old JM is still around.\n");
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE;
	goto close_fp_exit;
    }

    globus_gram_job_manager_request_log(request,
		  "JM: TTL has expired. Proceeding with restart.\n");

    fscanf( fp, "%[^\n]%*c", buffer );
    if(strcmp(buffer, " ") != 0)
    {
	request->job_id = strdup( buffer );
    }
    fscanf( fp, "%[^\n]%*c", buffer );
    request->rsl_spec = strdup( buffer );
    fscanf( fp, "%[^\n]%*c", buffer );
    request->cache_tag = strdup( buffer );
    fscanf( fp, "%[^\n]%*c", buffer);
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

    globus_gram_job_manager_output_read_state(request, fp);
    globus_gram_job_manager_staging_read_state(request,fp);

close_fp_exit:
    fclose(fp);

state_machine_exit:
    do
    {
	event_registered = globus_gram_job_manager_state_machine(request);
    }
    while(!event_registered);
    globus_mutex_unlock(&request->mutex);

    return event_registered;
}
/* globus_gram_job_manager_state_file_read() */

int
globus_gram_job_manager_state_file_update(
    globus_gram_jobmanager_request_t *	request)
{
    FILE *				fp;
    char				buffer[16];

    /*
     * We're doing a single write, which is atomic enough, so don't bother
     * with creating a new file and renaming it over the old one.
     */

    sprintf(buffer,
	    "%4d\n%4d\n%4d\n",
	    request->restart_state ? request->restart_state
	                           : request->jobmanager_state,
	    request->status,
	    (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
		? request->failure_code
		: 0);

    fp = fopen( request->job_state_file, "r+" );
    if ( fp == NULL )
        return GLOBUS_FAILURE;

    fprintf( fp, "%s", buffer );
    fclose( fp );

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_state_file_update() */
