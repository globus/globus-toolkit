#include "globus_gram_job_manager.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

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
globus_l_gram_job_manager_scratch_done(
    void *				arg,
    globus_gram_jobmanager_request_t *	request,
    int					failure_code,
    int					starting_jobmanager_state,
    const char *			variable,
    const char *			value);

static
void
globus_l_gram_job_manager_stage_done(
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
char *
globus_l_gram_job_manager_script_prepare_param(
    char *				param);

/**
 * Begin execution of a job manager script
 */
static
int
globus_l_gram_job_manager_script_run(
    globus_gram_jobmanager_request_t *	request,
    const char *			script_cmd,
    globus_gram_job_manager_script_callback_t
    					callback,
    void *				callback_arg)
{
    globus_gram_job_manager_script_context_t *
					script_context;
    globus_result_t			result;

    script_context = globus_libc_malloc(
	    sizeof(globus_gram_job_manager_script_context_t));

    script_context->return_buf[0] = '\0';
    script_context->callback = callback;
    script_context->callback_arg = callback_arg;
    script_context->request = request;
    script_context->starting_jobmanager_state = request->jobmanager_state;

    globus_jobmanager_log(request->jobmanager_log_fp,
                          "JMI: cmd = %s\n", script_cmd);

    script_context->pipe = popen(script_cmd, "r");

    if(script_context->pipe == NULL)
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
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

    if(result != GLOBUS_SUCCESS)
    {
	goto register_read_failed;
    }
    return GLOBUS_SUCCESS;

register_read_failed:
posix_convert_failed:
    pclose(script_context->pipe);
popen_failed:

    globus_libc_free(script_context);

    request->failure_code =
	GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_JOBMANAGER_SCRIPT;

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
    char *				script_value;
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

	script_variable = script_context->return_buf;

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

	script_value = script_variable_end+1;

	script_context->callback(
		script_context->callback_arg,
		request,
		failure_code,
		script_context->starting_jobmanager_state,
		script_variable,
		script_value);

	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JMI: while return_buf = %s = %s\n",
		script_variable, script_value);

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
    
    script_context->callback(
	    script_context->callback_arg,
	    request,
	    failure_code,
	    script_context->starting_jobmanager_state,
	    NULL,
	    NULL);
    pclose(script_context->pipe);
}
/* globus_l_gram_job_manager_script_read() */

/**
 * Submit a job request to a local scheduler.
 *
 * This function submits the passed job request to the local scheduler
 * script. If the job request is a restart request, it doesn't actually
 * submit the job, but creates a new state file, and polls the job's
 * status.
 *
 * @param request
 *        The request containing the job description and related information.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or GLOBUS_FAILURE. This
 * function has side affects which may affect the job_id, status, and
 * failure_code fields of the request structure.
 */
int
globus_gram_job_manager_submit(
    globus_gram_jobmanager_request_t *  request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    FILE * script_arg_fp;
    char * stdout_filename = GLOBUS_NULL;
    char * stderr_filename = GLOBUS_NULL;
    int rc;

    if (!request)
        return(GLOBUS_FAILURE);

    if (globus_l_gram_request_validate(request) != GLOBUS_SUCCESS)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_gram_job_manager_submit()\n" );

    request->poll_frequency = 30;

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

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: local stdout filename = %s.\n", stdout_filename);
    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: local stderr filename = %s.\n", stderr_filename);

    if ((script_arg_fp = fopen(request->script_arg_file, "w")) == NULL)
    {
        globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              request->script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code =
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    fprintf(script_arg_fp, "\n$rsl = {\n");
    globus_l_gram_job_manager_print_rsl(
            script_arg_fp,
            request->rsl);

    if(request->jobmanager_logfile)
    {
        fprintf(script_arg_fp, ",\nlogfile => [ '%s' ]\n",
                request->jobmanager_logfile);
    }
    /* Override stdout/stderr rsl values with our local values. */
    fprintf(script_arg_fp, ",\n"
			   "    stdout => [ '%s' ],\n"
			   "    stderr => [ '%s' ]\n"
			   "};\n",
			   stdout_filename,
			   stderr_filename);

    sprintf(script_cmd,
	    "%s/globus-job-manager-script.pl -m %s -f %s -c submit\n",
	    request->jobmanager_libexecdir,
	    request->jobmanager_type,
	    request->script_arg_file);

    fclose(script_arg_fp);

    /*
     * used to test job manager functionality without actually submitting
     * job
     */
    if (request->dry_run)
    {
        globus_jobmanager_log(request->jobmanager_log_fp,
                "JMI: This is a dry run!!\n");
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE;
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_DRYRUN;
        return(GLOBUS_FAILURE);
    }

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		globus_l_gram_job_manager_default_done,
		NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning with error: %d\n", rc);

	request->failure_code = rc;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;

        return rc;
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
            "JMI: returning with success\n" );

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_submit() */

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
globus_gram_job_manager_poll(
    globus_gram_jobmanager_request_t *	request)
{
    char				script_cmd[
					    GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int					rc;

    if (!request)
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED);

    sprintf(script_cmd,
	    "%s/globus-job-manager-script.pl -m %s -f %s -c poll\n",
	    request->jobmanager_libexecdir,
	    request->jobmanager_type,
	    request->script_arg_file);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		globus_l_gram_job_manager_default_done,
		NULL);

    if(rc != GLOBUS_SUCCESS)
    {
        globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning with error: %d\n", rc);

	request->failure_code = rc;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
    }
    return rc;
}
/* globus_gram_job_manager_poll() */

/**
 * Cancel a GRAM job.
 *
 * This function invokes a scheduler-specific program which cancels the
 * job. Upon completion of the script, the job request's status is modified,
 * and the job status script is destroyed (meaning any subsequent calls
 * to globus_jobmanager_request_check() or globus_jobmanager_request_cancel()
 * will fail.
 *
 * @param request
 *        The job request containing information about the job to be cancelled.
 */
int
globus_gram_job_manager_cancel(
    globus_gram_jobmanager_request_t *	request)
{
#if 0
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int rc;

    if (!request)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in gram_job_manager_cancel()\n" );

    sprintf(script_cmd, "%s/globus-job-manager-script.pl -m %s -f %s -c rm\n",
                         request->jobmanager_libexecdir,
                         request->jobmanager_type,
                         request->script_arg_file);

    rc = globus_l_gram_script_run(script_cmd, request, NULL, NULL);

    if (remove(request->script_arg_file) != 0)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
                     "JM: Cannot remove argument file --> %s\n",
                     request->script_arg_file);
    }

    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;

    if (rc == GLOBUS_FAILURE)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: received error from script: %d\n", rc );
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning job state failed.\n" );
        return(GLOBUS_FAILURE);
    }

    return(GLOBUS_SUCCESS);
#endif
    return GLOBUS_FAILURE;
}
/* globus_gram_job_manager_cancel() */

/**
 * Send a signal to a job scheduler
 *
 * @param request
 *        The job request containing information about the job to
 *        signal. The signal and signal_arg data are used by
 *        this function.
 */
int
globus_gram_job_manager_signal(
    globus_gram_jobmanager_request_t *	request)
{
    FILE *				signal_arg_fp;
    char				script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int					rc;
    char *				tmp_signalfilename = NULL;
    char *				signal_arg;

    if (!request)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_gram_job_manager_signal()\n" );

    tmp_signalfilename = tempnam(NULL, "grami_signal");

    if ((signal_arg_fp = fopen(tmp_signalfilename, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram signal script argument file. %s\n",
              tmp_signalfilename );

        return(GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED);
    }

    /* Escape single quotes in the signal arg */
    signal_arg = globus_l_gram_job_manager_script_prepare_param(
	    request->signal_arg);

    if(signal_arg == GLOBUS_NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
		              "JMI: Failed to escape %s\n",
			      request->signal_arg);
	return GLOBUS_FAILURE;
    }

    /*
     * add the signal and signal_arg to the script arg file
     */
    fprintf(signal_arg_fp,
	    "$description = {\n"
	    "    signal => [ %d ],\n"
	    "    signalarg => [ '%s' ],\n"
	    "};\n",
	    request->signal,
	    signal_arg);

    globus_libc_free(signal_arg);

    fclose(signal_arg_fp);

    sprintf(script_cmd,
	    "%s/globus-job-manager-script.pl -m %s -f %s -c signal",
                         request->jobmanager_libexecdir,
                         request->jobmanager_type,
                         tmp_signalfilename);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		globus_l_gram_job_manager_default_done,
		tmp_signalfilename);

    if(rc != GLOBUS_SUCCESS)
    {
        globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning with error: %d\n", rc);

	return rc;
    }
    /* TODO: Handle cancel signal */
    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_signal() */

int 
globus_gram_job_manager_make_scratchdir(
    globus_gram_jobmanager_request_t *	request)
{
    char				script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int					rc;
    FILE *				script_arg_fp;
    char *				scratch_dir_base;

    if (!request)
        return(GLOBUS_FAILURE);

    if ((script_arg_fp = fopen(request->script_arg_file, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              request->script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    scratch_dir_base = globus_l_gram_job_manager_script_prepare_param(
	    request->scratch_dir_base);

    fprintf(script_arg_fp,
	    "$description = { scratchdirbase => [ '%s' ] };\n",
	    scratch_dir_base);

    globus_libc_free(scratch_dir_base);

    fclose(script_arg_fp);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_gram_job_manager_make_scratchdir()\n" );

    sprintf(script_cmd,
	    "%s/globus-job-manager-script.pl -m %s -f %s -c make_scratchdir\n",
	    request->jobmanager_libexecdir,
	    request->jobmanager_type,
	    request->script_arg_file);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		globus_l_gram_job_manager_scratch_done,
		request->script_arg_file);

    if (rc != GLOBUS_SUCCESS)
    {
        return rc;
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
            "JMI: returning with success\n" );

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_make_scratchdir() */

int 
globus_gram_job_manager_rm_scratchdir(
    globus_gram_jobmanager_request_t *	request)
{
    char				script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int					rc;
    FILE *				script_arg_fp;
    char *				scratch_dir;

    if (!request)
        return(GLOBUS_FAILURE);

    if (!request->scratchdir)
	return(GLOBUS_SUCCESS);

    if ((script_arg_fp = fopen(request->script_arg_file, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              request->script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    scratch_dir = globus_l_gram_job_manager_script_prepare_param(
	    request->scratchdir);

    fprintf(script_arg_fp,
	    "$description = { scratchdirectory => ['%s'] };\n",
	    scratch_dir);

    globus_libc_free(scratch_dir);

    fclose(script_arg_fp);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_gram_job_manager_rm_scratchdir()\n" );

    sprintf(script_cmd,
	    "%s/globus-job-manager-script.pl -m %s -f %s -c remove_scratchdir",
	    request->jobmanager_libexecdir,
	    request->jobmanager_type,
	    request->script_arg_file);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		globus_l_gram_job_manager_scratch_done,
		request->script_arg_file);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning with error: %d\n", rc);

	request->failure_code = rc;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;

        return rc;
    }

    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_rm_scratchdir() */

int 
globus_gram_job_manager_stage_in(
    globus_gram_jobmanager_request_t *	request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    FILE * script_arg_fp;
    int rc;

    if (!request)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_gram_job_manager_stage_in()\n" );

    if ((script_arg_fp = fopen(request->script_arg_file, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              request->script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    fprintf(script_arg_fp, "\n$rsl = {\n");
    globus_l_gram_job_manager_print_rsl(
	    script_arg_fp,
	    request->rsl);
    if(request->jobmanager_logfile)
    {
	fprintf(script_arg_fp, ",\nlogfile => [ '%s' ]\n",
		request->jobmanager_logfile); 
    }
    fprintf(script_arg_fp, "};\n");

    sprintf(script_cmd,
		"%s/globus-job-manager-script.pl -m %s -f %s -c stage_in\n",
		request->jobmanager_libexecdir,
		request->jobmanager_type,
		request->script_arg_file);
    fclose(script_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		globus_l_gram_job_manager_stage_done,
		request->script_arg_file);

    if (rc != GLOBUS_SUCCESS)
    {
	request->failure_code = rc;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;

	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning with error: %d\n", request->failure_code );

        return(GLOBUS_FAILURE);
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: returning with success\n" );
    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_stage_in() */

int 
globus_gram_job_manager_stage_out(
    globus_gram_jobmanager_request_t *	request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    FILE * script_arg_fp;
    int rc;

    if (!request)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_gram_job_manager_stage_out()\n" );

    if ((script_arg_fp = fopen(request->script_arg_file, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              request->script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    fprintf(script_arg_fp, "\n$rsl = {\n");
    globus_l_gram_job_manager_print_rsl(
	    script_arg_fp,
	    request->rsl);
    if(request->jobmanager_logfile)
    {
	fprintf(script_arg_fp, ",\nlogfile => [ '%s' ]\n",
		request->jobmanager_logfile); 
    }
    fprintf(script_arg_fp, "};\n");

    sprintf(script_cmd,
		"%s/globus-job-manager-script.pl -m %s -f %s -c stage_out\n",
		request->jobmanager_libexecdir,
		request->jobmanager_type,
		request->script_arg_file);
    fclose(script_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		globus_l_gram_job_manager_stage_done,
		request->script_arg_file);

    if (rc != GLOBUS_SUCCESS)
    {
	request->failure_code = rc;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;

	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning with error: %d\n", request->failure_code );

        return(GLOBUS_FAILURE);
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: returning with success\n" );
    return(GLOBUS_SUCCESS);
}
/* globus_gram_job_manager_stage_out() */

int 
globus_jobmanager_request_file_cleanup(
    globus_gram_jobmanager_request_t *	request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    FILE * script_arg_fp;
    int rc;

    if (!request)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_jobmanager_request_file_cleanup()\n" );

    if ((script_arg_fp = fopen(request->script_arg_file, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              request->script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    fprintf(script_arg_fp, "\n$rsl = {\n");
    globus_l_gram_job_manager_print_rsl(
	    script_arg_fp,
	    request->rsl);
    if(request->jobmanager_logfile)
    {
	fprintf(script_arg_fp, ",\nlogfile => [ '%s' ]\n",
		request->jobmanager_logfile); 
    }
    fprintf(script_arg_fp, "};\n");

    sprintf(script_cmd,
		"%s/globus-job-manager-script.pl -m %s -f %s -c file_cleanup\n",
		request->jobmanager_libexecdir,
		request->jobmanager_type,
		request->script_arg_file);
    fclose(script_arg_fp);

    rc = globus_l_gram_job_manager_script_run(
                request,
                script_cmd,
		globus_l_gram_job_manager_stage_done,
		request->script_arg_file);

    if (rc != GLOBUS_SUCCESS)
    {
	request->failure_code = rc;
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;

	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning with error: %d\n", request->failure_code );

        return(GLOBUS_FAILURE);
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: returning with success\n" );
    return(GLOBUS_SUCCESS);
}
/* globus_jobmanager_request_file_cleanup() */


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
	while(!globus_i_gram_job_manager_state_machine(request));
    }
    else if(strcmp(variable, "GRAM_SCRIPT_SUCCESS") == 0)
    {
	script_status = atoi(value);

	if(script_status < 0)
	{
	    request->failure_code = 
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else if(script_status > 0 && request->status != script_status)
	{
	    request->status = script_status;
	    request->unsent_status_change = GLOBUS_TRUE;
	}
    }
    else if(strcmp(variable, "GLOBUS_SCRIPT_ERROR") == 0)
    {
	script_status = atoi(value);

	if(script_status < 0)
	{
	    request->failure_code = 
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else if(request->jobmanager_state == starting_jobmanager_state)
	{
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code = script_status;
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    request->unsent_status_change = GLOBUS_TRUE;
	}
    }
    else if(strcmp(variable, "GRAM_SCRIPT_JOB_ID") == 0)
    {
	request->job_id = globus_libc_strdup(value);
    }
    else if(request->jobmanager_state == starting_jobmanager_state)
    {
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	request->failure_code = 
	    GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	request->unsent_status_change = GLOBUS_TRUE;
    }

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_default_done() */

static
void
globus_l_gram_job_manager_scratch_done(
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
	/*
	 * arg is the script args file
	 */
	globus_assert(arg);
	remove((char *) arg);

	while(!globus_i_gram_job_manager_state_machine(request));
    }
    else if(strcmp(variable, "GRAM_SCRIPT_SUCCESS") == 0)
    {
	script_status = atoi(value);

	if(script_status < 0)
	{
	    request->failure_code = 
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else if(script_status > 0 && request->status != script_status)
	{
	    request->status = script_status;
	    request->unsent_status_change = GLOBUS_TRUE;
	}
    }
    else if(strcmp(variable, "GLOBUS_SCRIPT_ERROR") == 0)
    {
	script_status = atoi(value);

	if(script_status < 0)
	{
	    request->failure_code = 
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else if(request->jobmanager_state == starting_jobmanager_state)
	{
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code = script_status;
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    request->unsent_status_change = GLOBUS_TRUE;
	}
    }
    else if(strcmp(variable, "GRAM_SCRIPT_SCRATCH_DIR") == 0)
    {
	request->scratchdir = globus_libc_strdup(value);
    }
    else if(request->jobmanager_state == starting_jobmanager_state)
    {
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	request->failure_code = 
	    GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	request->unsent_status_change = GLOBUS_TRUE;
    }

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_scratch_done() */

static
void
globus_l_gram_job_manager_stage_done(
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
	/*
	 * arg is the script args file
	 */
	globus_assert(arg);
	remove((char *) arg);

	while(!globus_i_gram_job_manager_state_machine(request));
    }
    else if(strcmp(variable, "GLOBUS_SCRIPT_SUCCESS") == 0)
    {
	script_status = atoi(value);

	if(script_status < 0)
	{
	    request->failure_code = 
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else if(script_status > 0 &&
		request->status != script_status)
	{
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code = script_status;
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    request->unsent_status_change = GLOBUS_TRUE;
	}
    }
    else if(strcmp(variable, "GLOBUS_SCRIPT_ERROR") == 0)
    {
	script_status = atoi(value);

	if(script_status < 0)
	{
	    request->failure_code = 
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	}
	else if(request->jobmanager_state == starting_jobmanager_state)
	{
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	    request->failure_code = script_status;
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    request->unsent_status_change = GLOBUS_TRUE;
	}
    }
    else if(request->jobmanager_state == starting_jobmanager_state)
    {
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
	request->failure_code = 
	    GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
	request->unsent_status_change = GLOBUS_TRUE;
    }

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_stage_done() */

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
		if(*tmp == '\'')
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

/**
 * Escape single quotes within a string
 *
 * @param param
 *        Original string to be escaped
 */
static
char *
globus_l_gram_job_manager_script_prepare_param(
    char *				param)
{
    int					i;
    int					j;
    char *				new_param;

    if (param == NULL)
    {
	return NULL;
    }
    new_param = globus_libc_malloc(strlen(param)*2+1);

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

    if (! request->jobmanager_type)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
            "JMI: job manager type is not specified, cannot continue.\n");
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_MANAGER_TYPE;
        return(GLOBUS_FAILURE);
    }
    if(globus_location(&location) != GLOBUS_SUCCESS)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND;
	return GLOBUS_FAILURE;
    }

   /*
    * test that the scheduler script files exist and
    * that the user has permission to execute then.
    */
    globus_jobmanager_log(request->jobmanager_log_fp,
	"JMI: testing job manager scripts for type %s exist and "
	"permissions are ok.\n", request->jobmanager_type);

   /*---------------- job manager script -----------------*/
   sprintf(script_path,
	   "%s/globus-job-manager-script.pl",
	   request->jobmanager_libexecdir);

    if (stat(script_path, &statbuf) != 0)
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JMI: ERROR: script %s was not found.\n",
		script_path);
	
	request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND;
	
	goto free_location_exit;
   }

   if (!(statbuf.st_mode & 0111))
   {
       globus_jobmanager_log(
	       request->jobmanager_log_fp,
	       "JMI: ERROR: Not permitted to execute script %s.\n",
	       script_path);

       request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_PERMISSIONS;

       goto free_location_exit;
   }

   /*
    * Verify existence/executableness of scheduler specific script.
    */
    sprintf(script_path, "%s/lib/perl/Globus/GRAM/JobManager/%s.pm",
			location,
			request->jobmanager_type);

    if(stat(script_path, &statbuf) != 0)
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JMI: ERROR: script %s was not found.\n",
		script_path);
	
	request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND;

	goto free_location_exit;
    }

    globus_jobmanager_log(
	    request->jobmanager_log_fp,
	    "JMI: completed script validation: job manager type is %s.\n",
	    request->jobmanager_type);

free_location_exit:
    globus_libc_free(location);
    return(GLOBUS_SUCCESS);
}
/* globus_l_gram_request_validate() */
