#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gram_job_manager_request.c Globus Job Management Request
 *
 * CVS Information:
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#endif

/*
 * Include header files
 */
#include "globus_common.h"
#include "globus_gram_protocol.h"
#include "globus_gram_job_manager.h"

#include <string.h>

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
globus_gram_job_manager_request_init(
    globus_gram_jobmanager_request_t **	request)
{
    globus_gram_jobmanager_request_t * r;

    /*** creating request structure ***/
    *request = (globus_gram_jobmanager_request_t * ) globus_libc_calloc
                   (1, sizeof(globus_gram_jobmanager_request_t));

    r = *request;

    r->failure_code = 0;
    r->job_id = NULL;
    r->poll_frequency = 30;
    r->jobmanager_type = NULL;
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
    r->validation_records = NULL;
    globus_fifo_init(&r->pending_queries);
    globus_gram_job_manager_output_init(r);
    globus_mutex_init(&r->mutex, GLOBUS_NULL);
    globus_cond_init(&r->cond, GLOBUS_NULL);

    return(GLOBUS_SUCCESS);

}
/* globus_gram_job_manager_request_init() */

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
globus_gram_job_manager_request_destroy(
    globus_gram_jobmanager_request_t *	request)
{
    if (!request)
        return(GLOBUS_FAILURE);

    globus_mutex_destroy(&request->mutex);
    globus_cond_destroy(&request->cond);

    if (request->job_id)
        globus_libc_free(request->job_id);
    if (request->jobmanager_type)
        globus_libc_free(request->jobmanager_type);
    if (request->jobmanager_logfile)
        globus_libc_free(request->jobmanager_logfile);
    if (request->local_stdout)
        globus_libc_free(request->local_stdout);
    if (request->local_stderr)
        globus_libc_free(request->local_stderr);

    globus_libc_free(request);

    return(GLOBUS_SUCCESS);

}
/* globus_gram_job_manager_request_destroy() */

extern
void
globus_gram_job_manager_request_open_logfile(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_job_manager_logfile_flag_t
    					logfile_flag)
{
    if (logfile_flag == GLOBUS_GRAM_JOB_MANAGER_DONT_SAVE)
    {
        /* don't write a log file */
        request->jobmanager_logfile = globus_libc_strdup("/dev/null");
    }
    else
    {
        /*
         * Open the gram logfile just for testing!
         */
	request->jobmanager_logfile =
	    globus_libc_malloc(strlen("%s/gram_job_mgr_%lu.log") +
		                      strlen(request->home) +
				      16);

        sprintf(request->jobmanager_logfile, "%s/gram_job_mgr_%lu.log",
                request->home,
                (unsigned long) getpid());

        request->jobmanager_log_fp = fopen(request->jobmanager_logfile, "a");
	
	if(request->jobmanager_log_fp == NULL)
        {
            sprintf(request->jobmanager_logfile,
		    "/tmp/gram_job_mgr_%lu.log",
                    (unsigned long) getpid());

            request->jobmanager_log_fp =
		fopen(request->jobmanager_logfile, "a");

	    if(request->jobmanager_log_fp == NULL)
            {
                fprintf(stderr, "JM: Cannot open gram logfile.\n");
                sprintf(request->jobmanager_logfile, "/dev/null");
            }
        }
    }

    if (!request->jobmanager_log_fp)
    {
	request->jobmanager_log_fp = fopen(request->jobmanager_logfile, "w");
    }

    if(request->jobmanager_log_fp)
    {
	setbuf(request->jobmanager_log_fp, NULL);
    }
}
/* globus_gram_job_manager_request_open_logfile() */

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
globus_gram_job_manager_request_log(
    globus_gram_jobmanager_request_t *	request,
    const char *			format,
    ... )
{
    struct tm *curr_tm;
    time_t curr_time;
    va_list ap;
    int rc;

    if ( request->jobmanager_log_fp == GLOBUS_NULL ) {
	return -1;
    }

    time( &curr_time );
    curr_tm = localtime( &curr_time );

    globus_libc_lock();

    fprintf( request->jobmanager_log_fp,
	     "%d/%d %02d:%02d:%02d ",
	     curr_tm->tm_mon + 1, curr_tm->tm_mday,
	     curr_tm->tm_hour, curr_tm->tm_min,
	     curr_tm->tm_sec );

    va_start(ap, format);

    rc = vfprintf( request->jobmanager_log_fp,
	           format,
		   ap);

    globus_libc_unlock();

    return rc;
}
/* globus_gram_job_manager_request_log() */
