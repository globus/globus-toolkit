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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <utime.h>

/* Module Specific Types */
typedef void (*globus_gram_job_manager_script_callback_t)(
    void *				arg,
    globus_gram_jobmanager_request_t *	request,
    int					failure_code,
    int					starting_state,
    const char *			variable,
    const char *			value);

typedef struct
{
    globus_byte_t			return_buf[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    globus_gram_job_manager_script_callback_t
					callback;
    void *				callback_arg;
    globus_gram_jobmanager_request_t *	request;
    FILE *				pipe;
    globus_io_handle_t			pipe_handle;
    int					starting_jobmanager_state;
    char *				script_arg_file;
    globus_gram_protocol_handle_t	protocol_handle;
}
globus_gram_job_manager_script_context_t;

/* Module Specific Prototypes */
static
void
globus_l_gram_job_manager_script_read(
    void *				user_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes);

static
void
globus_l_gram_job_manager_default_done(
    void *				arg,
    globus_gram_jobmanager_request_t *	request,
    int					failure_code,
    int					starting_state,
    const char *			variable,
    const char *			value);

static
void
globus_l_gram_job_manager_query_done(
    void *				arg,
    globus_gram_jobmanager_request_t *	request,
    int					failure_code,
    int					starting_jobmanager_state,
    const char *			variable,
    const char *			value);

static
int
globus_l_gram_request_validate(
    globus_gram_jobmanager_request_t *	request);

static
int
globus_l_gram_job_manager_print_rsl_value(
    FILE *				fp,
    globus_rsl_value_t *		globus_rsl_value_ptr);

static
int
globus_l_gram_job_manager_print_rsl(
    FILE *				fp,
    globus_rsl_t *			ast_node);

static
int
globus_l_gram_job_manager_script_write_description(
    FILE *				fp,
    globus_gram_jobmanager_request_t *	request,
    ...);

static
char *
globus_l_gram_job_manager_script_prepare_param(
    const char *			param);

static
void
globus_l_gram_job_manager_print_staging_list(
    globus_gram_jobmanager_request_t *	request,
    FILE *				fp,
    globus_gram_job_manager_staging_type_t
    					type);

static
void
globus_l_gram_job_manager_script_staged_done(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_job_manager_staging_type_t
    					type,
    const char *			value);

/**
 * Begin execution of a job manager script
 */
static
int
globus_l_gram_job_manager_script_run(
    globus_gram_jobmanager_request_t *	request,
    const char *			script_cmd,
    char *				script_arg_file,
    globus_gram_protocol_handle_t	protocol_handle,
    globus_gram_job_manager_script_callback_t
    					callback,
    void *				callback_arg)
{
    globus_gram_job_manager_script_context_t *
					script_context;
    globus_result_t			result;
    char *				pipe_cmd;

    pipe_cmd = globus_common_create_string(
            "%s/libexec/globus-job-manager-script.pl -m %s -f %s -c %s",
	    request->config->globus_location,
	    request->config->jobmanager_type,
	    script_arg_file,
	    script_cmd);

    script_context = malloc(
	    sizeof(globus_gram_job_manager_script_context_t));

    script_context->return_buf[0] = '\0';
    script_context->callback = callback;
    script_context->callback_arg = callback_arg;
    script_context->request = request;
    script_context->starting_jobmanager_state = request->jobmanager_state;
    script_context->script_arg_file = globus_libc_strdup(script_arg_file);
    script_context->protocol_handle = protocol_handle;

    globus_gram_job_manager_request_log(request,
                          "JMI: cmd = %s\n", script_cmd);

    script_context->pipe = popen(pipe_cmd, "r");

    if(script_context->pipe == NULL)
    {
	globus_gram_job_manager_request_log(
		request,
		"JMI: Cannot popen shell file\n");
        request->failure_code =
	    GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_JOBMANAGER_SCRIPT;

	goto popen_failed;
    }

    setbuf(script_context->pipe, NULL);

    result = globus_io_file_posix_convert(
	    fileno(script_context->pipe),
	    GLOBUS_NULL,
	    &script_context->pipe_handle);
    if(result != GLOBUS_SUCCESS)
    {
	goto posix_convert_failed;
    }

    result = globus_io_register_read(
	    &script_context->pipe_handle,
	    &script_context->return_buf[0],
	    sizeof(script_context->return_buf),
	    1,
	    globus_l_gram_job_manager_script_read,
	    script_context);

    free(pipe_cmd);

    if(result != GLOBUS_SUCCESS)
    {
	goto register_read_failed;
    }
    return GLOBUS_SUCCESS;

register_read_failed:
posix_convert_failed:
    pclose(script_context->pipe);
popen_failed:

    free(pipe_cmd);
    free(script_context);

    return GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_JOBMANAGER_SCRIPT;
}
/* globus_l_gram_job_manager_script_run() */

static
void
globus_l_gram_job_manager_script_read(
    void *				user_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes)
{
    globus_gram_jobmanager_request_t *	request;
    globus_gram_job_manager_script_context_t *
					script_context;
    globus_object_t *			err;
    char *				script_variable;
    char *				script_variable_end;
    unsigned char *			script_value;
    globus_bool_t			eof = GLOBUS_FALSE;
    char *				p;
    int					failure_code = 0;

    if(result)
    {
	err = globus_error_get(result);
	eof = GLOBUS_TRUE;

	if(globus_io_eof(err))
	{
	    globus_object_free(err);
	    err = GLOBUS_NULL;
	}
	else
	{
	    failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
    }
    else
    {
	err = GLOBUS_NULL;
    }

    script_context = user_arg;
    request = script_context->request;

    while((p = memchr(script_context->return_buf, '\n', nbytes)) != NULL)
    {
	*p = '\0';

	script_variable = (char *) script_context->return_buf;

	while(*script_variable && isspace(*script_variable))
	{
	    script_variable++;
	}
	script_variable_end = script_variable;

	while(*script_variable_end && *script_variable_end != ':')
	{
	    script_variable_end++;
	}
	*script_variable_end = '\0';

	script_value = (unsigned char *) script_variable_end+1;

	script_context->callback(
		script_context->callback_arg,
		request,
		failure_code,
		script_context->starting_jobmanager_state,
		script_variable,
		(char *) script_value);

	globus_gram_job_manager_request_log(
		request,
		"JMI: while return_buf = %s = %s\n",
		script_variable, script_value);

	/*
	 * We need to log the batch job ID to the accounting file.
	 */

	if(strcmp(script_variable, "GRAM_SCRIPT_JOB_ID") == 0)
	{
	    const char * gk_jm_id_var = "GATEKEEPER_JM_ID";
	    const char * gk_jm_id  = globus_libc_getenv(gk_jm_id_var);
	    const char * gk_peer   = globus_libc_getenv("GATEKEEPER_PEER");
	    const char * globus_id = globus_libc_getenv("GLOBUS_ID");
	    uid_t uid = getuid();
	    gid_t gid = getgid();
	    const char *user = request->config->logname;

	    globus_gram_job_manager_request_acct(
		request, "%s %s for %s on %s\n", gk_jm_id_var,
		gk_jm_id  ? gk_jm_id  : "none",
		globus_id ? globus_id : "unknown",
		gk_peer   ? gk_peer   : "unknown");

	    globus_gram_job_manager_request_acct(
		request, "%s %s mapped to %s (%u, %u)\n", gk_jm_id_var,
		gk_jm_id  ? gk_jm_id  : "none",
		user, uid, gid);

	    globus_gram_job_manager_request_acct(
		request, "%s %s has %s %s manager type %s\n", gk_jm_id_var,
		gk_jm_id  ? gk_jm_id  : "none",
		script_variable, script_value,
                request->config->jobmanager_type);
	}

	nbytes -= (p + 1 - ((char *)&script_context->return_buf[0]));
	if(nbytes > 0)
	{
	    memmove(&script_context->return_buf[0],
		    p + 1, 
		    nbytes);
	}
	else
	{
	    script_context->return_buf[0] = '\0';
	}
    }

    if(! eof)
    {
	result = globus_io_register_read(
		&script_context->pipe_handle,
		&script_context->return_buf[nbytes],
		sizeof(script_context->return_buf) - nbytes,
		1,
		globus_l_gram_job_manager_script_read,
		script_context);

	if(result != GLOBUS_SUCCESS)
	{
	    failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else
	{
	    /* New callback registered successfully */
	    return;
	}
    }
    
    pclose(script_context->pipe);
    remove(script_context->script_arg_file);
    free(script_context->script_arg_file);

    script_context->callback(
	    script_context->callback_arg,
	    request,
	    failure_code,
	    script_context->starting_jobmanager_state,
	    NULL,
	    NULL);

    free(script_context);
}
/* globus_l_gram_job_manager_script_read() */

/**
 * Submit a job request to a local scheduler.
 *
 * This function submits the passed job request to the local scheduler
 * script. 
 *
 * @param request
 *        The request containing the job description and related information.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a failure code if the
 * job could not be submitted. If successful, this function will call
 * into the state machine once the job submission result has happened.
 */
int
globus_gram_job_manager_script_submit(
    globus_gram_jobmanager_request_t *  request)
{
    char * script_cmd = "submit";
    FILE * script_arg_fp;
    char * stdout_filename = GLOBUS_NULL;
    char * stderr_filename = GLOBUS_NULL;
    int rc;
    int                                 script_arg_fd;
    char                                template[] = "/tmp/gram_submitXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_submit()\n" );

    request->poll_frequency = 10;

    /*
     * create a file that will be used to pass all parameters to and
     * amongst the globus_gram_script_<scheduler>_* scripts.
     */
    if (request->local_stdout != GLOBUS_NULL)
    {
        stdout_filename = request->local_stdout;
    }
    else
    {
        stdout_filename = "/dev/null";
    }

    if (request->local_stderr != GLOBUS_NULL)
    {
        stderr_filename = request->local_stderr;
    }
    else
    {
        stderr_filename = "/dev/null";
    }

    globus_gram_job_manager_request_log(request,
          "JMI: local stdout filename = %s.\n", stdout_filename);
    globus_gram_job_manager_request_log(request,
          "JMI: local stderr filename = %s.\n", stderr_filename);

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );
        close(script_arg_fd);
        remove(template);
	return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    "stdout", 's', stdout_filename,
	    "stderr", 's', stderr_filename,
	    NULL);

    fclose(script_arg_fp);

    /*
     * used to test job manager functionality without actually submitting
     * job
     */
    if (request->dry_run)
    {
        globus_gram_job_manager_request_log(request,
                "JMI: This is a dry run!!\n");
        remove(template);
        return GLOBUS_GRAM_PROTOCOL_ERROR_DRYRUN;
    }

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc);

        return rc;
    }

    globus_gram_job_manager_request_log(request,
            "JMI: returning with success\n" );

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_submit() */



/**
 * Set job request status and fire callback so it registers
 *
 * Avoids actually locking request if possible.
 */
static
int
local_globus_set_status(
    globus_gram_jobmanager_request_t *    request,
    globus_gram_protocol_job_state_t      status)
{
    if( ! request )
        return GLOBUS_FAILURE;

    if(request->status != status)
    {
        globus_mutex_lock(&request->mutex);
        globus_gram_job_manager_request_set_status(request, status);
        request->unsent_status_change = GLOBUS_TRUE;
        globus_mutex_unlock(&request->mutex);
    }

    {
    /* Globus expects the callback to fire. Force it to
     * run instantly. */
        globus_reltime_t delay;
        GlobusTimeReltimeSet(delay, 0, 0);
        globus_callback_register_oneshot(
            &request->poll_timer,
            &delay,
            globus_gram_job_manager_state_machine_callback,
            request);
    }
    return GLOBUS_SUCCESS;
}
/* local_globus_set_status() */


/**
 * Modified job_contact in place to remove the port.
 */
static void job_contact_strip_port(
    char * job_contact)
{
    char * first_end;
    char * second_begin;

    if( job_contact == 0 )
        return;

    first_end = strrchr( job_contact, ':' );
    if( first_end == 0 ) /* malformed job_contact? */
        return;

    second_begin = strchr( first_end, '/' );
    if( second_begin == 0 ) /* malformed job_contact? */
        return;

    memmove(first_end, second_begin, strlen(second_begin) + 1);
}



/**
 * Try to poll status of job request using Condor grid_manager_monitor_agent
 *
 * If the Condor grid_manager_monitor_agent is running on the machine, this
 * function retrieve job request status using that, otherwise it fails. 
 * Expected to be called exclusively from globus_gram_job_manager_script_poll.
 */
int
globus_gram_job_manager_script_poll_fast(
    globus_gram_jobmanager_request_t *    request)
{
    int i;
    char * grid_monitor_output = 0;
    char * grid_monitor_files[3] = { NULL, NULL, NULL };
                /* Path is $GLOBUS_LOCATION/GRID_MONITOR_LOCATION$UID */
    const char * GRID_MONITOR_LOCATION_1 = "/tmp/grid_manager_monitor_agent_log.";
    const char * GRID_MONITOR_LOCATION_2 = "/tmp/gram_job_state/grid_manager_monitor_agent_log.";
    const char * WHITESPACE = " \t";
    uid_t this_uid = geteuid();
    struct stat stat_results;
    FILE * grid_monitor_file = 0;
    int rc;
    time_t MAX_MONITOR_FILE_AGE = (60*5); /* seconds */
    char line[1024];
    char line_job_contact[1024];
    int return_val = GLOBUS_FAILURE;
    time_t status_file_last_update = 0;
    const int DEBUG_FAST_POLL = 0; /* Set to 1 for extra log info */
    char * job_contact_match = 0;

    if( ! request ||
        ! request->config->globus_location ||
        !request->job_contact)
    {
        goto FAST_POLL_EXIT_FAILURE;
    }

    if(this_uid > 999999)
    {
    /* UIDs this large are unlikely, but if they occur the buffer
     * isn't large enough to handle it
     */
        goto FAST_POLL_EXIT_FAILURE;
    }

    /* The grid monitor's job status file can be in one of two places.
     * We want to check both.
     */
    grid_monitor_files[0] = globus_common_create_string(
            "%s%s%d",
            request->config->globus_location,
            GRID_MONITOR_LOCATION_1,
            (int)this_uid);
    if( ! grid_monitor_files[0])
    {
        goto FAST_POLL_EXIT_FAILURE;
    }

    grid_monitor_files[1] = globus_common_create_string(
            "%s%s%d",
            request->config->globus_location,
            GRID_MONITOR_LOCATION_2,
            (int)this_uid);
    if( ! grid_monitor_files[1])
    {
        goto FAST_POLL_EXIT_FAILURE;
    }

    for ( i = 0; grid_monitor_files[i]; i++ )
    {
	grid_monitor_output = grid_monitor_files[i];

	grid_monitor_file = fopen(grid_monitor_output, "r");

	if( ! grid_monitor_file )
	{
	    /* No monitor file?  That's acceptable, silently fail */
	    continue;
	}

	rc = stat(grid_monitor_output, &stat_results);
	if( rc != 0 ) {
	    fclose(grid_monitor_file);
	    grid_monitor_file = NULL;
	    continue;
	}

	if(stat_results.st_uid != this_uid ||
	   !S_ISREG(stat_results.st_mode)
	   /* TODO: test for world writable (bad)?  Is such a test logical on AFS? */
	   )
	{
	    globus_gram_job_manager_request_log(request,
		"JMI: poll_fast: Monitoring file %s looks untrustworthy.\n",
		grid_monitor_output);
	    fclose(grid_monitor_file);
	    grid_monitor_file = NULL;
	    continue;
	}

	if( (stat_results.st_mtime + MAX_MONITOR_FILE_AGE) < time(NULL) )
	{
	    globus_gram_job_manager_request_log(request,
		"JMI: poll_fast: Monitoring file %s looks out of date.\n",
		grid_monitor_output);
	    fclose(grid_monitor_file);
	    grid_monitor_file = NULL;
	    continue;
	}

	break;
    }
    if ( grid_monitor_file == NULL ) {
	goto FAST_POLL_EXIT_FAILURE;
    }

    /* If we got this far, we've decided we trust the file */

    /* Read the first line, which is two timestamps as seconds since epoch.
     * The first one is start time of last query pass, the second is finish. */
    if( ! fgets(line, sizeof(line), grid_monitor_file) )
    {
        globus_gram_job_manager_request_log(request,
            "JMI: poll_fast: Job state file %s malformed, missing first line\n",
            grid_monitor_output);
        goto FAST_POLL_EXIT_FAILURE;
    }
    if( ! feof(grid_monitor_file) && line[strlen(line) - 1] != '\n')
    {
        globus_gram_job_manager_request_log(request,
            "JMI: poll_fast: Job state file %s malformed, first line too long\n",
            grid_monitor_output);
        goto FAST_POLL_EXIT_FAILURE;
    }

    status_file_last_update = atoi(line);
    if(status_file_last_update < request->status_update_time) {
        /* We somehow got a status update more recent than the status file.
         * Most likely we successfully executed a traditional poll faster than
         * the status script processed things.  This status file is fresh
         * enough, so we should switch over to using that, we want to avoid
         * firing off a traditional poll.  So, leave the existing status in
         * place and report a successful poll. */
        globus_gram_job_manager_request_log(request,
            "JMI: poll_fast: **** Job state file %s older than my last "
            "known status.  Using last known status. (%d < %d)\n",
            grid_monitor_output,
            status_file_last_update, request->status_update_time);
        local_globus_set_status(request, request->status);
        return_val = GLOBUS_SUCCESS;
        goto FAST_POLL_EXIT;
    }

    job_contact_match = malloc(strlen(request->job_contact) + 1);
    strcpy(job_contact_match, request->job_contact);
    job_contact_strip_port(job_contact_match);

    if(DEBUG_FAST_POLL)
    {
        globus_gram_job_manager_request_log(request,
            "JMI: poll_fast: ******* seeking: %s in %s\n", job_contact_match,
            grid_monitor_output);
    }
    /* TODO: First pass.  Improve with binary search of file to make
     * scanning large files fast. Still this is probably plenty fast
     * enough for fairly large runs. */
    while( 1 )
    {
        size_t len = 0;
        char * line_bit = line;
        if( ! fgets(line, sizeof(line), grid_monitor_file) )
        {
            globus_gram_job_manager_request_log(request,
                "JMI: poll_fast: ******** "
                "Failed to find %s\n", job_contact_match);
            /* end of file (or error), job isn't in file.  It might just not
             * have been noticed yet.  Silently skip */
            goto FAST_POLL_EXIT_FAILURE;
        }
        if( ! feof(grid_monitor_file) && line[strlen(line) - 1] != '\n')
        {
            globus_gram_job_manager_request_log(request,
                "JMI: poll_fast: Monitoring file looks corrupt, "
                "lines are too long.  "
                "Reverting to normal polling\n");
            goto FAST_POLL_EXIT_FAILURE;
        }

        len = strcspn(line_bit, WHITESPACE);
        if(len == 0)
        {
            globus_gram_job_manager_request_log(request,
                "JMI: poll_fast: Monitoring file looks corrupt, "
                "line doesn't start with job contact string.  "
                "Reverting to normal polling\n");
            goto FAST_POLL_EXIT_FAILURE;
        }

        /* So long as sizeof(line_job_contact) == sizeof(line),
         * this is safe */
        memcpy(line_job_contact, line, len);
        line_job_contact[len] = 0;
        job_contact_strip_port(line_job_contact);

        if( strcmp(line_job_contact, job_contact_match) != 0 )
        {
            if(DEBUG_FAST_POLL)
            {
                globus_gram_job_manager_request_log(request,
                    "JMI: poll_fast:          no match: %s\n",
                    line);
            }
            continue;
        }

        line_bit += len;

        len = strspn(line_bit, WHITESPACE);
        if(len == 0)
        {
            globus_gram_job_manager_request_log(request,
                "JMI: poll_fast: Monitoring file looks corrupt, "
                "missing whitespace field seperator.  "
                "Reverting to normal polling\n");
            goto FAST_POLL_EXIT_FAILURE;
        }

        line_bit += len;

        /* Found exact match, read status */
        len = strspn(line_bit, "0123456789");
        if(len == 0)
        {
            /* No digits!? */
            globus_gram_job_manager_request_log(request,
                "JMI: poll_fast: Monitoring file looks corrupt, "
                "non numeric status.  "
                "Reverting to normal polling\n");
            goto FAST_POLL_EXIT_FAILURE;
        }

        local_globus_set_status(request, atoi(line_bit));

        if(DEBUG_FAST_POLL)
        {
            globus_gram_job_manager_request_log(request,
                "JMI: poll_fast: ******** "
                "OK. found %s (%s)\n", job_contact_match, line_job_contact);
        }

        return_val = GLOBUS_SUCCESS;
        goto FAST_POLL_EXIT;
    }

FAST_POLL_EXIT_FAILURE:
    return_val = GLOBUS_FAILURE;

FAST_POLL_EXIT:
    if(grid_monitor_file) 
        fclose(grid_monitor_file);
    for ( i = 0; grid_monitor_files[i]; i++ ) {
        free(grid_monitor_files[i]);
    }
    if( job_contact_match )
        free(job_contact_match);

    globus_gram_job_manager_request_log(request,
        "JMI: poll_fast: returning %d = %s\n", return_val,
        (return_val == GLOBUS_FAILURE) ?
            "GLOBUS_FAILURE (try Perl scripts)" :
            "GLOBUS_SUCCESS (skip Perl scripts)");
    return return_val;
}
/* globus_gram_job_manager_script_poll_fast() */







/**
 * Poll the status of a job request.
 *
 * This function invokes a scheduler-specific program to determine
 * the current status of the job request. The job status field of
 * the requst structure will be updated with the new status.
 *
 * @param request
 *        The request containing the job description.
 * @return GLOBUS_GRAM_JOBMANAGER_STATUS_UNCHANGED or
 * GLOBUS_GRAM_JOBMANAGER_STATUS_CHANGED depending whether the job status
 * is the same as the result from the value of request's status field. This
 * field will be updated if the job's status has changed.
 */
int 
globus_gram_job_manager_script_poll(
    globus_gram_jobmanager_request_t *	request)
{
    char *				script_cmd = "poll";
    int					rc;
    FILE *				script_arg_fp;
    char *				stdout_filename = "/dev/null";
    char *				stderr_filename = "/dev/null";
    int 				script_arg_fd;
    char                                template[]="/tmp/gram_pollXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    /* Keep the state file's timestamp up to date so that
     * anything scrubbing the state files of old and dead
     * processes leaves it alone
     */ 
    if(request->job_state_file)
    {
        utime(request->job_state_file, NULL);
    }

    /* Keep the state file's timestamp up to date so that
     * anything scrubbing the state files of old and dead
     * processes leaves it alone */
    if(request->job_state_file)
        utime(request->job_state_file, NULL);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_poll()\n" );

    if (request->local_stdout != GLOBUS_NULL)
    {
        stdout_filename = request->local_stdout;
    }
    if (request->local_stderr != GLOBUS_NULL)
    {
        stderr_filename = request->local_stderr;
    }

    globus_gram_job_manager_request_log(request,
          "JMI: local stdout filename = %s.\n", stdout_filename);
    globus_gram_job_manager_request_log(request,
          "JMI: local stderr filename = %s.\n", stderr_filename);

    globus_gram_job_manager_request_log(request,
	"JMI: poll: seeking: %s\n", request->job_contact);
    if( globus_gram_job_manager_script_poll_fast(request) == GLOBUS_SUCCESS )
    {
        return(GLOBUS_SUCCESS);
    }

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );
        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
        request->failure_code =
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        close(script_arg_fd);
        remove(template);

        return(GLOBUS_FAILURE);
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    "stdout", 's', stdout_filename,
	    "stderr", 's', stderr_filename,
	    NULL);

    fclose(script_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: poll returning with error: %d\n", rc);
        remove(template);

        return rc;
    }

    globus_gram_job_manager_request_log(request,
            "JMI: returning with success\n" );

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_poll() */

/**
 * Cancel a GRAM job.
 *
 * This function invokes a scheduler-specific program which cancels the
 * job.
 *
 * @param request
 *        The job request containing information about the job to be cancelled.
 */
int
globus_gram_job_manager_script_cancel(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_job_manager_query_t *	query)
{
    FILE *				script_arg_fp;
    char *				script_cmd = "cancel";
    int					rc;
    int 				script_arg_fd;
    char                                template[]="/tmp/gram_cancelXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_script_cancel()\n" );

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template);
        close(script_arg_fd);
        remove(template);
	return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    NULL);

    fclose(script_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_query_done,
		query);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc);
        remove(template);

        return rc;
    }

    globus_gram_job_manager_request_log(request,
            "JMI: returning with success\n" );

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_cancel() */

/**
 * Send a signal to a job scheduler
 *
 * @param request
 *        The job request containing information about the job to
 *        signal. The signal and signal_arg data are used by
 *        this function.
 */
int
globus_gram_job_manager_script_signal(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_job_manager_query_t *	query)
{
    FILE *				signal_arg_fp;
    char *				script_cmd = "signal";
    int					rc;
    int                                 script_arg_fd;
    char                                template[]="/tmp/gram_signalXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_signal()\n" );

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((signal_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram signal script argument file. %s\n",
              template );

        close(script_arg_fd);
        remove(template);
        return(GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED);
    }

    /*
     * add the signal and signal_arg to the script arg file
     */
    globus_l_gram_job_manager_script_write_description(
	    signal_arg_fp,
	    request,
	    "jobid", 's', request->job_id,
	    "signal", 'd', query->signal,
	    "signalarg", 's', query->signal_arg,
	    NULL);
	    

    fclose(signal_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_query_done,
		query);

    if(rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc);
        remove(template);

	return rc;
    }
    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_signal() */

int 
globus_gram_job_manager_script_make_scratchdir(
    globus_gram_jobmanager_request_t *	request,
    const char *			scratch_dir)
{
    char *				script_cmd = "make_scratchdir";
    int					rc;
    FILE *				script_arg_fp;
    int 				script_arg_fd;
    char                                template[]="/tmp/gram_make_scratchdirXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        close(script_arg_fd);
        remove(template);

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    "scratchdirbase", 's', request->config->scratch_dir_base,
	    "scratchdir", 's', scratch_dir,
	    NULL);

    fclose(script_arg_fp);

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_script_make_scratchdir()\n" );

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        remove(template);
        return rc;
    }

    globus_gram_job_manager_request_log(request,
            "JMI: returning with success\n" );

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_make_scratchdir() */

int 
globus_gram_job_manager_script_rm_scratchdir(
    globus_gram_jobmanager_request_t *	request)
{
    char *				script_cmd = "remove_scratchdir";
    int					rc;
    FILE *				script_arg_fp;
    char *				scratch_dir;
    int				        script_arg_fd;
    char                                template[]="/tmp/gram_rm_scratchdirXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    if (!request->scratchdir)
	return(GLOBUS_FAILURE);

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        close(script_arg_fd);
        remove(template);

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    scratch_dir = globus_l_gram_job_manager_script_prepare_param(
	    request->scratchdir);

    fprintf(script_arg_fp,
	    "$description = { scratchdirectory => ['%s'] };\n",
	    scratch_dir);

    free(scratch_dir);

    fclose(script_arg_fp);

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_rm_scratchdir()\n" );

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc);
        remove(template);

        return rc;
    }

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_rm_scratchdir() */

int 
globus_gram_job_manager_script_stage_in(
    globus_gram_jobmanager_request_t *	request)
{
    char *				script_cmd = "stage_in";
    FILE *				script_arg_fp;
    int					rc;
    int  				script_arg_fd;
    char                                template[]="/tmp/gram_stage_inXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_script_stage_in()\n" );

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );
        close(script_arg_fd);
        remove(template);

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    NULL);
	    
    fclose(script_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc );
        remove(template);

        return rc;
    }

    globus_gram_job_manager_request_log(request,
	    "JMI: returning with success\n" );
    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_stage_in() */

int 
globus_gram_job_manager_script_stage_out(
    globus_gram_jobmanager_request_t *	request)
{
    char *				script_cmd = "stage_out";
    FILE *				script_arg_fp;
    int					rc;
    int                                 script_arg_fd;
    char                                template[]="/tmp/gram_stage_outXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_script_stage_out()\n" );

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );
        close(script_arg_fd);
        remove(template);
        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    NULL);

    fclose(script_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc );
        remove(template);

        return rc;
    }

    globus_gram_job_manager_request_log(request,
	    "JMI: returning with success\n" );
    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_stage_out() */

int 
globus_gram_job_manager_script_file_cleanup(
    globus_gram_jobmanager_request_t *	request)
{
    char *				script_cmd = "file_cleanup";
    FILE *				script_arg_fp;
    int					rc;
    int				        script_arg_fd;
    char                                template[]="/tmp/gram_file_cleanupXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_script_file_cleanup()\n" );

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );
        close(script_arg_fd);
        remove(template);

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    NULL);

    fclose(script_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc );
        remove(template);

        return rc;
    }

    globus_gram_job_manager_request_log(request,
	    "JMI: returning with success\n" );
    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_file_cleanup() */

int 
globus_gram_job_manager_script_cache_cleanup(
    globus_gram_jobmanager_request_t *	request)
{
    char *				script_cmd = "cache_cleanup";
    int					rc;
    FILE *				script_arg_fp;
    int				        script_arg_fd;
    char                                template[] = "/tmp/gram_cache_cleanupXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        close(script_arg_fd);
        remove(template);
        return(GLOBUS_FAILURE);
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    NULL);

    fclose(script_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc);
        remove(template);

        return rc;
    }

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_cache_cleanup() */

int 
globus_gram_job_manager_script_remote_io_file_create(
    globus_gram_jobmanager_request_t *	request)
{
    char *				script_cmd = "remote_io_file_create";
    int					rc;
    FILE *				script_arg_fp;
    int				        script_arg_fd;
    char                                template[] = "/tmp/gram_remote_ioXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );
        close(script_arg_fd);
        remove(template);

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    NULL);

    fclose(script_arg_fp);

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_script_remote_io_file_create()\n" );

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc);
        remove(template);

        return rc;
    }

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_remote_io_file_create() */

int 
globus_gram_job_manager_script_proxy_relocate(
    globus_gram_jobmanager_request_t *	request)
{
    char *				script_cmd = "proxy_relocate";
    int					rc;
    FILE *				script_arg_fp;
    int 				script_arg_fd;
    char  				template[] = "/tmp/gram_proxy_relXXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;

    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );
        close(script_arg_fd);
        remove(template);

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    NULL);

    fclose(script_arg_fp);

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_script_proxy_relocate()\n" );

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc);
        remove(template);

        return rc;
    }

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_proxy_relocate() */

int 
globus_gram_job_manager_script_proxy_update(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_job_manager_query_t *	query)
{
    char *				script_cmd = "proxy_update";
    int					rc;
    FILE *				script_arg_fp;
    int				        script_arg_fd;
    char                                template[]="/tmp/gram_proxy_updateXXXXXX";

    if (!request)
        return(GLOBUS_FAILURE);

    rc = globus_l_gram_request_validate(request);

    if (rc != GLOBUS_SUCCESS)
        return rc;


    if ((script_arg_fd = mkstemp(template)) < 0)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    if ((script_arg_fp = fdopen(script_arg_fd, "w")) == NULL)
    {
	globus_gram_job_manager_request_log(request,
              "JMI: Failed to open gram script argument file. %s\n",
              template );
        close(script_arg_fd);
        remove(template);

        return GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }

    globus_l_gram_job_manager_script_write_description(
	    script_arg_fp,
	    request,
	    NULL);

    fclose(script_arg_fp);

    globus_gram_job_manager_request_log(request,
          "JMI: in globus_gram_job_manager_script_proxy_update()\n" );

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		template,
		GLOBUS_HANDLE_TABLE_NO_HANDLE,
		globus_l_gram_job_manager_query_done,
		query);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(request,
              "JMI: returning with error: %d\n", rc);
        remove(template);

        return rc;
    }

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_script_proxy_update() */

/**
 * Completion callback for done and poll scripts.
 *
 * This is called when a line of output containing a variable:value
 * pair is read from the script's execution.
 */
static
void
globus_l_gram_job_manager_default_done(
    void *				arg,
    globus_gram_jobmanager_request_t *	request,
    int					failure_code,
    int					starting_jobmanager_state,
    const char *			variable,
    const char *			value)
{
    int					script_status;

    globus_mutex_lock(&request->mutex);

    if(failure_code)
    {
	request->failure_code = failure_code;
    }
    if(!variable)
    {
	while(!globus_gram_job_manager_state_machine(request));
    }
    else if(strcmp(variable, "GRAM_SCRIPT_JOB_STATE") == 0)
    {
	script_status = atoi(value);

	if(script_status < 0)
	{
	    request->failure_code = 
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else if(globus_i_gram_job_manager_script_valid_state_change(
		    request, script_status))
	{
        globus_gram_job_manager_request_set_status(request, script_status);
	    request->unsent_status_change = GLOBUS_TRUE;
	}
    }
    else if(strcmp(variable, "GRAM_SCRIPT_ERROR") == 0)
    {
	script_status = atoi(value);

	if(request->jobmanager_state == starting_jobmanager_state)
	{
	    globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	    if(script_status <= 0)
	    {
		request->failure_code = 
		    GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	    }
	    else
	    {
		request->failure_code = script_status;
	    }
	    request->unsent_status_change = GLOBUS_TRUE;
	}
    }
    else if(strcmp(variable, "GRAM_SCRIPT_JOB_ID") == 0)
    {
        if(value != NULL && strlen(value) > 0)
	{
	    request->job_id = globus_libc_strdup(value);
	}
    }
    else if(strcmp(variable, "GRAM_SCRIPT_JOB_ACCT_INFO") == 0)
    {
        if(value != NULL && strlen(value) > 0)
        {
            const char *gk_jm_id_var = "GATEKEEPER_JM_ID";
            const char *gk_jm_id = globus_libc_getenv(gk_jm_id_var);
	    const char *v = value;
	    char *buf = malloc(strlen(value) + 1);
	    char *b = buf;
	    char c;

	    while ((*b++ = ((c = *v++) != '\\') ? c :
		           ((c = *v++) != 'n' ) ? c : '\n'))
	    {
	    }

            globus_gram_job_manager_request_acct(
		request, "%s %s summary:\n%s\nJMA -- end of summary\n", gk_jm_id_var,
		gk_jm_id ? gk_jm_id : "none", buf);

	    free(buf);
        }
    }
    else if(strcmp(variable, "GRAM_SCRIPT_SCRATCH_DIR") == 0)
    {
	request->scratchdir = globus_libc_strdup(value);
    }
    else if(strcmp(variable, "GRAM_SCRIPT_X509_USER_PROXY") == 0)
    {
	request->x509_user_proxy = globus_libc_strdup(value);
    }
    else if(strcmp(variable, "GRAM_SCRIPT_STAGED_IN") == 0)
    {
	globus_l_gram_job_manager_script_staged_done(
		request,
		GLOBUS_GRAM_JOB_MANAGER_STAGE_IN,
		value);
    }
    else if(strcmp(variable, "GRAM_SCRIPT_STAGED_IN_SHARED") == 0)
    {
	globus_l_gram_job_manager_script_staged_done(
		request,
		GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED,
		value);
    }
    else if(strcmp(variable, "GRAM_SCRIPT_STAGED_OUT") == 0)
    {
	if(request->jobmanager_state == starting_jobmanager_state)
	{
    	    globus_l_gram_job_manager_script_staged_done(
		    request,
		    GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT,
		    value);
	}
    }
    else if(strcmp(variable, "GRAM_SCRIPT_REMOTE_IO_FILE") == 0)
    {
	request->remote_io_url_file = globus_libc_strdup(value);
    }
    else if(strncmp(variable, "GRAM_SCRIPT_GT3", 15) == 0)
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: GT3 extended error message: %s:%s\n",
		variable,
		value ? value : "");
    }
    else if(request->jobmanager_state == starting_jobmanager_state)
    {
	globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	request->failure_code = 
	    GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	request->unsent_status_change = GLOBUS_TRUE;
    }

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_default_done() */

/**
 * Completion callback for query-initiated scripts
 */
static
void
globus_l_gram_job_manager_query_done(
    void *				arg,
    globus_gram_jobmanager_request_t *	request,
    int					failure_code,
    int					starting_jobmanager_state,
    const char *			variable,
    const char *			value)
{
    int					script_status;
    globus_gram_job_manager_query_t *	query;

    query = arg;

    globus_mutex_lock(&request->mutex);

    if(failure_code)
    {
	request->failure_code = failure_code;
    }
    if(!variable)
    {
	while(!globus_gram_job_manager_state_machine(request));
    }
    else if(strcmp(variable, "GRAM_SCRIPT_ERROR") == 0)
    {
	script_status = atoi(value);

	if(script_status <= 0)
	{
	    query->failure_code = 
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else
	{
	    query->failure_code = script_status;
	}
    }
    else if(strcmp(variable, "GRAM_SCRIPT_JOB_STATE") == 0)
    {
	script_status = atoi(value);

	if(script_status <= 0)
	{
	    query->failure_code = 
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else if((query->type == GLOBUS_GRAM_JOB_MANAGER_CANCEL ||
		query->signal == GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_CANCEL) &&
		(globus_i_gram_job_manager_script_valid_state_change(
		    request, script_status)))
	{
	    request->unsent_status_change = GLOBUS_TRUE;
	    globus_gram_job_manager_request_set_status(request, script_status);
	    if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
	    {
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED;
		query->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED;
	    }
	}
	else if((query->signal == GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_SUSPEND ||
		query->signal == GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_RESUME) &&
	        globus_i_gram_job_manager_script_valid_state_change(
						 request,
						 script_status))
		
	{
	    globus_gram_job_manager_request_set_status(request, script_status);
	    request->unsent_status_change = GLOBUS_TRUE;
	}
    }
    else
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: unexpected response from script: %s:%s\n",
		variable,
		value ? value : "");
	query->failure_code = 
	    GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
    }

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_default_done() */
/**
 * Recursively print an RSL value.
 *
 * This function prints to the given file the passed rsl value (right
 * side of an RSL relation).  The format of the printout is a perl hash
 * of arrays.
 *
 * @param fp
 *        The file to write to.
 * @param globus_rsl_value_ptr
 *        The RSL value to print.
 *
 * @return 0 on success, 1 on error.
 */
static
int
globus_l_gram_job_manager_print_rsl_value(
    FILE *				fp,
    globus_rsl_value_t *		globus_rsl_value_ptr)
{
    globus_rsl_value_t *		tmp_rsl_value_ptr;
    globus_list_t *			tmp_rsl_list;
    char *				tmp;

    if (globus_rsl_value_ptr==NULL) return(0);

    switch (globus_rsl_value_ptr->type)
    {
        case GLOBUS_RSL_VALUE_LITERAL:
	    tmp = globus_rsl_value_literal_get_string(globus_rsl_value_ptr);

	    fputc('\'', fp);
	    while(*tmp)
	    {
		if(*tmp == '\'' || *tmp == '\\')
		{
		    fputc('\\', fp);
		    fputc(*tmp, fp);
		}
		else
		{
		    fputc(*tmp, fp);
		}
		tmp++;
	    }
	    fputc('\'', fp);

            break;

        case GLOBUS_RSL_VALUE_SEQUENCE:

            tmp_rsl_list = globus_rsl_value_sequence_get_value_list(
		    globus_rsl_value_ptr);

	    fprintf(fp, "[ ");

            while (! globus_list_empty(tmp_rsl_list))
            {
                tmp_rsl_value_ptr = (globus_rsl_value_t *) globus_list_first
                     (tmp_rsl_list);
                globus_l_gram_job_manager_print_rsl_value(fp,tmp_rsl_value_ptr);

                tmp_rsl_list = globus_list_rest(tmp_rsl_list);
		if(!globus_list_empty(tmp_rsl_list))
		{
		    fprintf(fp, ", ");
		}
            }
	    fprintf(fp, "] ");

            break;

        case GLOBUS_RSL_VALUE_VARIABLE:
        case GLOBUS_RSL_VALUE_CONCATENATION:
        default:
            fprintf(fp, "''");
	    return 1;
            break;
    }

    return 0;
}
/* globus_l_gram_job_manager_print_rsl_value() */

/**
 * Recursively print the RSL in perl syntax.
 *
 * This function prints to the given file the passed rsl tree.
 * The format of the printout is a perl hash of arrays.
 *
 * @param fp
 *        The file to write to.
 * @param ast_node
 *        The RSL tree to print.
 *
 * @return 0 on success, 1 on error.
 */
static
int
globus_l_gram_job_manager_print_rsl(
    FILE *				fp,
    globus_rsl_t *			ast_node)
{
    globus_list_t *			tmp_rsl_list;
    globus_rsl_t *			tmp_rsl_ptr;
    int					rc;

    if (globus_rsl_is_boolean(ast_node))
    {
        tmp_rsl_list = globus_rsl_boolean_get_operand_list(ast_node);


        while (! globus_list_empty(tmp_rsl_list))
        {
            tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                 (tmp_rsl_list);
            rc = globus_l_gram_job_manager_print_rsl(fp, tmp_rsl_ptr);

            tmp_rsl_list = globus_list_rest(tmp_rsl_list);

	    if(!globus_list_empty(tmp_rsl_list))
	    {
		fprintf(fp, ",\n");
	    }
	    if(rc != GLOBUS_SUCCESS)
	    {
		return rc;
	    }
        }
    }
    else
    {
	/* Skip these, as they will be over-ridden by the todo lists */
	if((strcmp(globus_rsl_relation_get_attribute(ast_node),
		    "filestagein") == 0) ||
	   (strcmp(globus_rsl_relation_get_attribute(ast_node),
		    "filestageinshared") == 0) ||
	   (strcmp(globus_rsl_relation_get_attribute(ast_node),
		    "filestageout") == 0))
	{
	    return 0;
	}
		  
	fprintf(fp,
		"    '%s' => ",
		globus_rsl_relation_get_attribute(ast_node));

        rc = globus_l_gram_job_manager_print_rsl_value(
		fp,
		globus_rsl_relation_get_value_sequence(ast_node));
	if(rc != GLOBUS_SUCCESS)
	{
	    return rc;
	}
    }
    return 0;
}
/* globus_l_gram_job_manager_print_rsl() */

static
int
globus_l_gram_job_manager_script_write_description(
    FILE *				fp,
    globus_gram_jobmanager_request_t *	request,
    ...)
{
    va_list				ap;
    char *				attribute;
    char				format;
    char *				string_value;
    int					int_value;
    char *				prepared;

    va_start(ap, request);

    fprintf(fp, "$description =\n{\n");

    globus_l_gram_job_manager_print_rsl(fp, request->rsl);

    /* Other non-rsl or rsl-override attributes */
    while(1)
    {
	attribute = va_arg(ap, char *);

	if(!attribute)
	{
	    break;
	}
	format = (char) va_arg(ap, int);

	switch(format)
	{
	  case 's':
	    string_value = va_arg(ap, char *);
	    if(string_value)
	    {
		prepared = globus_l_gram_job_manager_script_prepare_param(
			string_value);

		fprintf(fp, ",\n    '%s' => [ '%s' ]", attribute, prepared);
		free(prepared);
	    }
	    break;

	  case 'i':
	  case 'd':
	    int_value = va_arg(ap, int);
	    fprintf(fp, ",\n    '%s' => [ '%d' ]", attribute, int_value);
	    break;
	}
    }
    va_end(ap);

    if(request->manager->jobmanager_logfile)
    {
	fprintf(fp,
		",\n    'logfile' => [ '%s' ]",
		request->manager->jobmanager_logfile);
    }
    if(request->uniq_id)
    {
	fprintf(fp,
		",\n    'uniqid' => [ '%s' ]",
		request->uniq_id);
    }
    if(request->job_id)
    {
	fprintf(fp,
		",\n    'jobid' => [ '%s' ]",
		request->job_id);
    }
    if(request->cache_tag)
    {
	fprintf(fp,
		",\n    'cachetag' => [ '%s' ]",
		request->cache_tag);
    }
    if(request->config->condor_os)
    {
	fprintf(fp,
		",\n    'condoros' => [ '%s' ]",
		request->config->condor_os);
    }
    if(request->config->condor_arch)
    {
	fprintf(fp,
		",\n    'condorarch' => [ '%s' ]",
		request->config->condor_arch);
    }
    if (request->job_dir)
    {
	fprintf(fp,
		",\n    'jobdir' => [ '%s' ]",
		request->job_dir);
    }

    fprintf(fp, ",\n    'streamingdisabled' => [ %d ]",
	    request->config->streaming_disabled);
    fprintf(fp, ",\n    'streamingrequested' => [ %d ]",
	    request->streaming_requested );

    globus_l_gram_job_manager_print_staging_list(
	    request,
	    fp,
	    GLOBUS_GRAM_JOB_MANAGER_STAGE_IN);
    globus_l_gram_job_manager_print_staging_list(
	    request,
	    fp,
	    GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED);
    globus_l_gram_job_manager_print_staging_list(
	    request,
	    fp,
	    GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT);
    fprintf(fp, "\n};\n");

    return GLOBUS_SUCCESS;
}
/* globus_l_gram_job_manager_script_write_description() */

/**
 * Escape single quotes within a string
 *
 * @param param
 *        Original string to be escaped
 */
static
char *
globus_l_gram_job_manager_script_prepare_param(
    const char *			param)
{
    int					i;
    int					j;
    char *				new_param;

    if (param == NULL)
    {
	return NULL;
    }
    new_param = malloc(strlen(param)*2+1);

    for (i = 0, j = 0; param[i] != '\0'; i++)
    {
        if(param[i] == '\\' )
        {
           new_param[j++] = '\\';
           new_param[j++] = '\\';
        }
        else if (param[i] == '\'')
        {
           new_param[j++] = '\\';
           new_param[j++] = '\'';
        }
        else
        {
           new_param[j++] = param[i];
        }
    }
    new_param[j] = '\0';

    return new_param;
}
/* globus_l_gram_job_manager_script_prepare_param() */

/**
 * Validate that the job manager is properly configured.
 *
 * This function validates the job scripts needed to handle this job
 * request exist and are executable.
 *
 * @param request
 *        The job request we are submitting. This is used to check
 *        that the job manager type is supported by this installation
 *        of the job manager, and for logging.
 *
 * @retval GLOBUS_SUCCESS
 * The job manager is able to submit the job request to the appropriate
 * scripts.
 * @retval GLOBUS_FAILURE
 * The job manager is unable to submit the job request; the request
 * failure code will be updated with the reason why the job couldn't be
 * submitted.
 */
static
int
globus_l_gram_request_validate(
    globus_gram_jobmanager_request_t *	request)
{
    struct stat				statbuf;
    char				script_path[512];
    char *				location;
    int					rc = GLOBUS_SUCCESS;

    if (! request->config->jobmanager_type)
    {
	globus_gram_job_manager_request_log(request,
            "JMI: job manager type is not specified, cannot continue.\n");
        return GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_MANAGER_TYPE;
    }
    if(request->rsl == NULL)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
    }

    if(globus_location(&location) != GLOBUS_SUCCESS)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND;
    }
   /*
    * test that the scheduler script files exist and
    * that the user has permission to execute then.
    */
    globus_gram_job_manager_request_log(request,
	"JMI: testing job manager scripts for type %s exist and "
	"permissions are ok.\n", request->config->jobmanager_type);

   /*---------------- job manager script -----------------*/
   sprintf(script_path,
	   "%s/libexec/globus-job-manager-script.pl",
	   request->config->globus_location);

    if (stat(script_path, &statbuf) != 0)
    {
	globus_gram_job_manager_request_log(
		request,
		"JMI: ERROR: script %s was not found.\n",
		script_path);
	
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND;
	
	goto free_location_exit;
   }

   if (!(statbuf.st_mode & 0111))
   {
       globus_gram_job_manager_request_log(
	       request,
	       "JMI: ERROR: Not permitted to execute script %s.\n",
	       script_path);

       rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_PERMISSIONS;

       goto free_location_exit;
   }

   /*
    * Verify existence/executableness of scheduler specific script.
    */
    sprintf(script_path, "%s/lib/perl/Globus/GRAM/JobManager/%s.pm",
			location,
			request->config->jobmanager_type);

    if(stat(script_path, &statbuf) != 0)
    {
	globus_gram_job_manager_request_log(
		request,
		"JMI: ERROR: script %s was not found.\n",
		script_path);
	
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND;

	goto free_location_exit;
    }

    globus_gram_job_manager_request_log(
	    request,
	    "JMI: completed script validation: job manager type is %s.\n",
	    request->config->jobmanager_type);

free_location_exit:
    free(location);
    return rc;
}
/* globus_l_gram_request_validate() */

static
void
globus_l_gram_job_manager_print_staging_list(
    globus_gram_jobmanager_request_t *	request,
    FILE *				fp,
    globus_gram_job_manager_staging_type_t
    					type)
{
    globus_list_t *			tmp_list;
    char *				attribute;
    char *				from;
    char *				to;
    globus_gram_job_manager_staging_info_t *
					info;

    switch(type)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN:
	tmp_list = request->stage_in_todo;
	attribute = GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_PARAM;
	break;
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED:
	tmp_list = request->stage_in_shared_todo;
	attribute = GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_SHARED_PARAM;
	break;
      case GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT:
	tmp_list = request->stage_out_todo;
	attribute = GLOBUS_GRAM_PROTOCOL_FILE_STAGE_OUT_PARAM;
	break;
    }
    /* Always write the attribute to the script arg file, even if
     * it's empty---if we were restarted during staging, then we
     * may have files listed in the original RSL which have been staged
     * completely.
     */
    fprintf(fp, ",\n%s => [", attribute);
    while(!globus_list_empty(tmp_list))
    {
	info = globus_list_first(tmp_list);
	tmp_list = globus_list_rest(tmp_list);
	from = globus_l_gram_job_manager_script_prepare_param(
		info->evaled_from);
	to  = globus_l_gram_job_manager_script_prepare_param(
		info->evaled_to);

	fprintf(fp, " ['%s', '%s']%s",
		from,
		to,
		globus_list_empty(tmp_list) ? "\n" : ",\n");

	free(from);
	free(to);
    }
    fprintf(fp, " ]");
    return;
}
/* globus_l_gram_job_manager_print_staging_list() */

static
void
globus_l_gram_job_manager_script_staged_done(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_job_manager_staging_type_t
    					type,
    const char *			value)
{
    char *				from;
    char *				to;

    from = malloc(strlen(value)+1);
    to = malloc(strlen(value)+1);
    sscanf(value, "%s %s", from, to);

    globus_gram_job_manager_staging_remove(
	    request,
	    type,
	    from,
	    to);

    if(request->save_state &&
            request->jobmanager_state !=
                    GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT)
    {
	globus_gram_job_manager_state_file_write(
		request);
    }

    free(from);
    free(to);
}
/* globus_l_gram_job_manager_script_staged_done() */

globus_bool_t
globus_i_gram_job_manager_script_valid_state_change(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_protocol_job_state_t	new_state)
{
    switch(request->status)
    {
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING:
	  if(new_state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING)
	  {
	      return GLOBUS_TRUE;
	  }
	  return GLOBUS_FALSE;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE:
	  if(new_state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING &&
	     new_state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE)
	  {
	      return GLOBUS_TRUE;
	  }
	  return GLOBUS_FALSE;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED:
	  return GLOBUS_FALSE;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE:
	  return GLOBUS_FALSE;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED:
	  if(new_state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING &&
	     new_state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED)
	  {
	      return GLOBUS_TRUE;
	  }
	  return GLOBUS_FALSE;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED:
	  if(new_state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED)
	  {
	      return GLOBUS_TRUE;
	  }
	  return GLOBUS_FALSE;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN:
	  if(new_state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN)
	  {
	      return GLOBUS_TRUE;
	  }
	  return GLOBUS_FALSE;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_OUT:
	  if(new_state == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE ||
	     new_state == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
	  {
	      return GLOBUS_TRUE;
	  }
	  return GLOBUS_FALSE;
	default:
	  return GLOBUS_FALSE;
    }
}
/* globus_l_gram_job_manager_script_valid_state_change() */
