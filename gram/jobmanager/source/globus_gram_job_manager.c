/******************************************************************************
globus_gram_job_manager.c 

Description:
    Globus Job Management API

CVS Information:
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common.h"
#include "globus_gram_protocol.h"
#include "globus_gram_job_manager.h"
#include "globus_rsl.h"

#include <stdio.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

/*
 * Module specific prototypes
 */
static
char *
globus_l_gram_param_prepare(
    char *				param);

static
int
globus_l_gram_script_run(
    char *				cmd,
    globus_gram_jobmanager_request_t *	request,
    char *				return_var,
    char **				return_val);

static
int
globus_l_gram_request_validate(
    globus_gram_jobmanager_request_t *	request);

static
int
globus_l_gram_job_manager_print_rsl(
    FILE *				fp,
    globus_rsl_t *			ast_node);

/*
 * Define module specific variables
 */
static char * graml_script_arg_file = NULL;

/**
 * Allocate and initialize a request.
 *
 * This function allocates a new request structure and clears all of the
 * values in the structure. It also creates a script argument file which
 * will be used when the job request is submitted.
 *
 * @param request
 *        A pointer to a globus_gram_jobmanager_request_t pointer. This
 *        will be modified to point to a freshly allocated request structure.
 *
 * @return GLOBUS_SUCCESS on successfully initialization, or GLOBUS_FAILURE.
 */
int 
globus_jobmanager_request_init(globus_gram_jobmanager_request_t ** request)
{
    globus_gram_jobmanager_request_t * r;

    /*** creating request structure ***/
    *request = (globus_gram_jobmanager_request_t * ) globus_libc_calloc
                   (1, sizeof(globus_gram_jobmanager_request_t));

    r = *request;

    r->failure_code = 0;
    r->user_pointer = NULL;
    r->job_id = NULL;
    r->poll_frequency = 0;
    r->jobmanager_type = NULL;
    r->jobmanager_libexecdir = NULL;
    r->jobmanager_logfile = NULL;
    r->jobmanager_log_fp = NULL;
    r->local_stdout = NULL;
    r->local_stderr = NULL;
    r->condor_os = NULL;
    r->condor_arch = NULL;
    r->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED;
    r->two_phase_commit = GLOBUS_FALSE;
    r->save_state = GLOBUS_FALSE;
    r->jm_restart = NULL;
    r->scratchdir = GLOBUS_NULL;
    r->scratch_dir_base = GLOBUS_NULL;
    r->in_handler = GLOBUS_FALSE;
    globus_i_gram_job_manager_output_init(r);
    globus_mutex_init(&r->mutex, GLOBUS_NULL);
    r->validation_records = NULL;
    globus_cond_init(&r->cond, GLOBUS_NULL);

    if ( (graml_script_arg_file = tempnam(NULL, "grami")) == NULL )
    {
        r->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        r->failure_code =
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    return(GLOBUS_SUCCESS);

} /* globus_jobmanager_request_init() */

/**
 * Deallocate memory related to a request.
 *
 * This function frees the data within the request, and then frees the request.
 * The caller must not access the request after this function has returned.
 *
 * @param request
 *        Job request to destroy.
 *
 * @return GLOBUS_SUCCESS
 */
int 
globus_jobmanager_request_destroy(globus_gram_jobmanager_request_t * request)
{
    if (!request)
        return(GLOBUS_FAILURE);

    if (request->job_id)
        globus_libc_free(request->job_id);
    if (request->jobmanager_type)
        globus_libc_free(request->jobmanager_type);
    if (request->jobmanager_libexecdir)
        globus_libc_free(request->jobmanager_libexecdir);
    if (request->jobmanager_logfile)
        globus_libc_free(request->jobmanager_logfile);
    if (request->local_stdout)
        globus_libc_free(request->local_stdout);
    if (request->local_stderr)
        globus_libc_free(request->local_stderr);

    globus_libc_free(request);

    return(GLOBUS_SUCCESS);

} /* globus_jobmanager_request_destroy() */

/**
 * Write data to the job manager log file
 *
 * This function writes data to the passed file, using a printf format
 * string. Data is prefixed with a timestamp when written.
 *
 * @param log_fp
 *        Log file to write to.
 * @param format
 *        Printf-style format string to be written.
 * @param ...
 *        Parameters substituted into the format string, if needed.
 *
 * @return This function returns the value returned by vfprintf.
 */
int
globus_jobmanager_log( FILE *log_fp, const char *format, ... )
{
    struct tm *curr_tm;
    time_t curr_time;
    va_list ap;
    int rc;

    if ( log_fp == GLOBUS_NULL ) {
	return -1;
    }

    time( &curr_time );
    curr_tm = localtime( &curr_time );

    globus_libc_lock();

    fprintf( log_fp, "%d/%d %02d:%02d:%02d ",
	     curr_tm->tm_mon + 1, curr_tm->tm_mday,
	     curr_tm->tm_hour, curr_tm->tm_min,
	     curr_tm->tm_sec );

    va_start(ap, format);

    rc = vfprintf( log_fp, format, ap );

    globus_libc_unlock();

    return rc;
}
/* globus_jobmanager_log() */


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
globus_jobmanager_request(
    globus_gram_jobmanager_request_t *	request)
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
          "JMI: in globus_jobmanager_request()\n" );

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

    if ((script_arg_fp = fopen(graml_script_arg_file, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              graml_script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    fprintf(script_arg_fp, "\n$rsl = {\n");
    globus_l_gram_job_manager_print_rsl(
	    script_arg_fp,
	    request->rsl);

    /* Override stdout/stderr rsl values with our local values. */
    if ( request->jm_restart == GLOBUS_NULL )
    {
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
		graml_script_arg_file);
    }
    else
    {
	fprintf(script_arg_fp, ",\n"
		               "    jobid  => [ '%s' ],\n"
			       "    stdout => [ '%s' ],\n"
			       "    stderr => [ '%s' ]\n"
			       "};\n",
			       request->job_id,
			       stdout_filename,
			       stderr_filename);

	sprintf(script_cmd,
		"%s/globus-job-manager-script.pl -m %s -f %s -c poll\n",
		request->jobmanager_libexecdir,
		request->jobmanager_type,
		graml_script_arg_file);
    }
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

    rc = globus_l_gram_script_run(
		script_cmd,
		request,
		(request->job_id == NULL) ? "GRAM_SCRIPT_JOB_ID" : NULL,
		(request->job_id == NULL) ? &request->job_id : NULL);

    if (rc != GLOBUS_SUCCESS)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning with error: %d\n", request->failure_code );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        return(GLOBUS_FAILURE);
    }

    if ( (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE)  &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING) &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)  &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)    &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED) )
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: grami_gram_job_request(): submit script returned"
              " unknown value: %d\n", request->status );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOBSTATE;
        return(GLOBUS_FAILURE);
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: returning with success\n" );
    return(GLOBUS_SUCCESS);
}
/* globus_jobmanager_request() */


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
globus_jobmanager_request_cancel(
    globus_gram_jobmanager_request_t *	request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int rc;

    if (!request)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_jobmanager_request_cancel()\n" );

    sprintf(script_cmd, "%s/globus-job-manager-script.pl -m %s -f %s -c rm\n",
                         request->jobmanager_libexecdir,
                         request->jobmanager_type,
                         graml_script_arg_file);

    rc = globus_l_gram_script_run(script_cmd, request, NULL, NULL);

    if (remove(graml_script_arg_file) != 0)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
                     "JM: Cannot remove argument file --> %s\n",
                     graml_script_arg_file);
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

}
/* globus_jobmanager_request_cancel() */


/**
 * Send a signal to a job scheduler
 *
 * @param request
 *        The job request containing information about the job to
 *        signal. The signal and signal_arg data are used by
 *        this function.
 */
int
globus_jobmanager_request_signal(
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
          "JMI: in globus_jobmanager_request_signal()\n" );

    tmp_signalfilename = tempnam(NULL, "grami_signal");

    if ((signal_arg_fp = fopen(tmp_signalfilename, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram signal script argument file. %s\n",
              tmp_signalfilename );
        return(GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED);
    }

    /* Escape single quotes in the signal arg */
    signal_arg = globus_l_gram_param_prepare(request->signal_arg);
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

    rc = globus_l_gram_script_run(script_cmd, request, NULL, NULL);

    if (request->signal == GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_CANCEL)
    {
        if (remove(graml_script_arg_file) != 0)
        {
	    globus_jobmanager_log(request->jobmanager_log_fp,
                         "JM: Cannot remove argument file --> %s\n",
                         graml_script_arg_file);
        }
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
    }

    if (rc == GLOBUS_FAILURE)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: received error from script: %d\n", request->failure_code );
        return(GLOBUS_GRAM_PROTOCOL_ERROR_SIGNALING_JOB);
    }

    return(GLOBUS_SUCCESS);

}
/* globus_jobmanager_request_signal() */


/**
 * Check the status of a job request.
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
globus_jobmanager_request_check(
    globus_gram_jobmanager_request_t *	request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int old_status;

    if (!request)
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED);

    sprintf(script_cmd,
	    "%s/globus-job-manager-script.pl -m %s -f %s -c poll\n",
	    request->jobmanager_libexecdir,
	    request->jobmanager_type,
	    graml_script_arg_file);

    old_status = request->status;

    if (globus_l_gram_script_run(script_cmd, request, NULL, NULL) != GLOBUS_SUCCESS)
    {
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED);
    }

    if ( (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE)  &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING) &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)  &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)    &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED) )
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JMI: globus_jobmanager_request_check(): "
		    "poll script returned unknown value: %d\n",
		request->status);

        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOBSTATE;

        return(GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED);
    }

    if (request->status == old_status)
    {
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_UNCHANGED);
    }
    else if ((request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED) ||
             (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE) )
    {
	if (remove(graml_script_arg_file) != 0)
	{
	    globus_jobmanager_log(request->jobmanager_log_fp,
		     "JM: Cannot remove argument file --> %s\n",
		     graml_script_arg_file);
	}
    }

    return(GLOBUS_GRAM_JOBMANAGER_STATUS_CHANGED);
}
/* globus_jobmanager_request_check() */

/**
 * Escape single quotes within a string
 *
 * @param param
 *        Original string to be escaped
 */
static
char *
globus_l_gram_param_prepare(
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
/* globus_l_gram_param_prepare() */

/**
 * Run a scheduler script and parse it's output.
 *
 * @param cmd
 *        The command line of the script to execute.
 * @param request
 *        The job request which the command is being executed to
 *        handle.
 * @param return_var
 *        A script return variable to be parsed out of the script's
 *        standard output. The script should return <return_var>:value,
 *        for example, GRAM_SCRIPT_SCRATCH_DIR:/path/to/created/scratch/dir
 * @param return_val
 *        A pointer to be set to a copy of the value of the return_var, if
 *        it is found in the script's output.
 */
static
int
globus_l_gram_script_run(
    char *				cmd,
    globus_gram_jobmanager_request_t *	request,
    char *				return_var,
    char **				return_val)
{
    FILE *				fp;
    char *				return_buf;
    int					script_status;
    globus_size_t			varlen;
    int					rc = GLOBUS_SUCCESS;

    globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: cmd = %s\n", cmd );

    if ((fp = popen(cmd, "r")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
		"JMI: Cannot popen shell file\n");
        request->failure_code =
	    GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_JOBMANAGER_SCRIPT;
        return(GLOBUS_FAILURE);
    }

    return_buf = globus_libc_malloc(GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE);
    return_buf[0] = '\0';

    while (fgets(return_buf, GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE, fp) != NULL)
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JMI: while return_buf = %s\n",
		return_buf);

	if(return_var != NULL && return_val != NULL)
	{
	    varlen = strlen(return_var);

	    if (strncmp(return_buf, return_var, varlen) == 0)
	    {
		return_buf[strlen(return_buf)-1] = '\0';
		*return_val =
		    globus_libc_malloc(
			    strlen(&return_buf[varlen + 1]) + 1);
		strcpy(*return_val, &return_buf[varlen+1]);

		globus_jobmanager_log(
			request->jobmanager_log_fp,
			"JMI: %s = %s\n", return_var, *return_val);
	    }
	}
    }

    pclose(fp);

    return_buf[strlen(return_buf)-1] = '\0';
    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: return_buf = %s\n", return_buf );

    if (strncmp(return_buf, "GRAM_SCRIPT_SUCCESS:", 20) == 0)
    {
        if ((script_status = atoi(&return_buf[20])) < 0)
        {
            /* unable to determine script status */
            request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;

	    rc = GLOBUS_FAILURE;
	    goto free_return_buf_exit;
        }
	globus_jobmanager_log(request->jobmanager_log_fp,
		"JMI: ret value = %d\n",
                       script_status );

        request->status = script_status;
    }
    else if (strncmp(return_buf, "GRAM_SCRIPT_ERROR:", 18) == 0)
    {
	rc = GLOBUS_FAILURE;

        if ((script_status = atoi(&return_buf[18])) < 0)
        {
            request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
        }
        else
        {
            request->failure_code = script_status;
        }

	globus_jobmanager_log(request->jobmanager_log_fp,
		"JMI: ret value = %d\n",
		request->failure_code );

        goto free_return_buf_exit;
    }
    else
    {
        request->failure_code =
	    GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_REPLY;
        rc = GLOBUS_FAILURE;
	goto free_return_buf_exit;
    }

free_return_buf_exit:
    globus_libc_free(return_buf);

    return rc;
}
/* globus_l_gram_script_run() */


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

    if (!(statbuf.st_mode & 0111))
    {
	globus_jobmanager_log(
		request->jobmanager_log_fp,
		"JMI: ERROR: Not permitted to execute script %s.\n",
		script_path);
	
	request->failure_code =
	    GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_PERMISSIONS;
	
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

int 
globus_jobmanager_request_scratchdir(
	globus_gram_jobmanager_request_t * request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int rc;
    FILE * script_arg_fp;
    char * scratch_dir_base;

    if (!request)
        return(GLOBUS_FAILURE);

    if ((script_arg_fp = fopen(graml_script_arg_file, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              graml_script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    scratch_dir_base = globus_l_gram_param_prepare(request->scratch_dir_base);

    fprintf(script_arg_fp,
	    "$description = { scratchdirbase => [ '%s' ] };\n",
	    scratch_dir_base);

    globus_libc_free(scratch_dir_base);

    fclose(script_arg_fp);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_jobmanager_request_scratchdir()\n" );

    sprintf(script_cmd,
	    "%s/globus-job-manager-script.pl -m %s -f %s -c make_scratchdir\n",
	    request->jobmanager_libexecdir,
	    request->jobmanager_type,
	    graml_script_arg_file);

    rc = globus_l_gram_script_run(
	    script_cmd,
	    request,
	    "GRAM_SCRIPT_SCRATCH_DIR",
	    &request->scratchdir);

    if (remove(graml_script_arg_file) != 0)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
                     "JM: Cannot remove argument file --> %s\n",
                     graml_script_arg_file);
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
} /* globus_jobmanager_request_scratchdir() */

int 
globus_jobmanager_request_rm_scratchdir(
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

    if ((script_arg_fp = fopen(graml_script_arg_file, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              graml_script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    scratch_dir = globus_l_gram_param_prepare(request->scratchdir);

    fprintf(script_arg_fp,
	    "$description = { scratchdirectory => ['%s'] };\n",
	    scratch_dir);

    globus_libc_free(scratch_dir);

    fclose(script_arg_fp);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_jobmanager_request_rm_scratchdir()\n" );

    sprintf(script_cmd,
	    "%s/globus-job-manager-script.pl -m %s -f %s -c remove_scratchdir",
	    request->jobmanager_libexecdir,
	    request->jobmanager_type,
	    graml_script_arg_file);

    rc = globus_l_gram_script_run(
	    script_cmd,
	    request,
	    NULL,
	    NULL);

    if (remove(graml_script_arg_file) != 0)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
                     "JM: Cannot remove argument file --> %s\n",
                     graml_script_arg_file);
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
}
/* globus_jobmanager_request_rm_scratchdir() */


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
