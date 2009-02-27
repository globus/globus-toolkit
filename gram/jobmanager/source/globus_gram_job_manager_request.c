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
#include <syslog.h>

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
	r->status_update_time = 0;
    r->url_base = GLOBUS_NULL;
    r->job_contact = GLOBUS_NULL;
    r->job_contact_path = GLOBUS_NULL;
    r->old_job_contact = GLOBUS_NULL;
    r->two_phase_commit = GLOBUS_FALSE;
    r->save_state = GLOBUS_FALSE;
    r->jm_restart = NULL;
    r->scratchdir = GLOBUS_NULL;
    r->scratch_dir_base = GLOBUS_NULL;
    r->in_handler = GLOBUS_FALSE;
    r->validation_records = NULL;
    r->relocated_proxy = GLOBUS_FALSE;
    r->proxy_timeout = 60;
    r->cache_tag = GLOBUS_NULL;
    r->job_state_file_dir = GLOBUS_NULL;
    r->job_state_file = GLOBUS_NULL;
    r->job_state_lock_file = GLOBUS_NULL;
    r->job_state_lock_fd = -1;
    r->stdout_position_hack = GLOBUS_NULL;
    r->stderr_position_hack = GLOBUS_NULL;
    globus_fifo_init(&r->pending_queries);
    globus_gram_job_manager_output_init(r);
    globus_mutex_init(&r->mutex, GLOBUS_NULL);
    globus_cond_init(&r->cond, GLOBUS_NULL);
    r->extra_envvars = GLOBUS_NULL;
    r->response_context = GSS_C_NO_CONTEXT;
    r->streaming_disabled = GLOBUS_FALSE;
    r->streaming_requested = GLOBUS_FALSE;
    r->disable_duct = GLOBUS_FALSE;

    r->seg_module = NULL;
    r->seg_started = GLOBUS_FALSE;
    r->seg_last_timestamp = 0;
    globus_fifo_init(&r->seg_event_queue);
    
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
    OM_uint32                           minor_status;
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
    if (request->cache_tag)
	globus_libc_free(request->cache_tag);
    if (request->url_base)
	globus_libc_free(request->url_base);
    if (request->job_contact)
	globus_libc_free(request->job_contact);
    if (request->job_contact_path)
	globus_libc_free(request->job_contact_path);
    if (request->old_job_contact)
	globus_libc_free(request->old_job_contact);
    if (request->job_state_file_dir)
	globus_libc_free(request->job_state_file_dir);
    if (request->job_state_file)
	globus_libc_free(request->job_state_file);
    if (request->job_state_lock_file)
	globus_libc_free(request->job_state_lock_file);
    if (request->extra_envvars)
        globus_libc_free(request->extra_envvars);
    if (request->response_context == GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&minor_status,
                               &request->response_context,
                               NULL);

    globus_libc_free(request);

    return(GLOBUS_SUCCESS);

}
/* globus_gram_job_manager_request_destroy() */

/**
 * Copy memory related to a request.
 *
 * This function creates a duplicate of a job request with copies of all data
 * from the the initial request. 
 *
 * @param copy
 *        New copy of the job request.
 * @param original
 *        Original job request.
 *
 * @return GLOBUS_SUCCESS
 */
int 
globus_gram_job_manager_request_copy(
    globus_gram_jobmanager_request_t ** copy,
    globus_gram_jobmanager_request_t *  original)
{
    int rc;
    globus_gram_jobmanager_request_t *  cp;

    rc = globus_gram_job_manager_request_init(copy);

    if (rc != GLOBUS_SUCCESS)
    {
        goto out;
    }
    cp = *copy;

    if (original->job_id)
        cp->job_id = globus_libc_strdup(original->job_id);
    if (original->jobmanager_type)
        cp->jobmanager_type = globus_libc_strdup(original->jobmanager_type);
    if (original->jobmanager_logfile)
        cp->jobmanager_logfile =
            globus_libc_strdup(original->jobmanager_logfile);
    if (original->local_stdout)
        cp->local_stdout = globus_libc_strdup(original->local_stdout);
    if (original->local_stderr)
        cp->local_stderr = globus_libc_strdup(original->local_stderr);
    if (original->cache_tag)
	cp->cache_tag = globus_libc_strdup(original->cache_tag);
    if (original->url_base)
	cp->url_base = globus_libc_strdup(original->url_base);
    if (original->job_contact)
	cp->job_contact = globus_libc_strdup(original->job_contact);
    if (original->job_contact_path)
	cp->job_contact_path = globus_libc_strdup(original->job_contact_path);
    if (original->old_job_contact)
	cp->old_job_contact = globus_libc_strdup(original->old_job_contact);
    if (original->job_state_file_dir)
	cp->job_state_file_dir =
                globus_libc_strdup(original->job_state_file_dir);
    if (original->job_state_file)
	cp->job_state_file = globus_libc_strdup(original->job_state_file);
    if (original->job_state_lock_file)
	cp->job_state_lock_file =
                globus_libc_strdup(original->job_state_lock_file);
    if (original->extra_envvars)
        cp->extra_envvars = globus_libc_strdup(original->extra_envvars);
    if (original->rsl_spec)
        cp->rsl_spec = globus_libc_strdup(original->rsl_spec);
    globus_symboltable_init(&cp->symbol_table,
                            globus_hashtable_string_hash,
                            globus_hashtable_string_keyeq);
    globus_symboltable_create_scope(&cp->symbol_table);


    cp->parent_jm = original;
    cp->jobmanager_log_fp = original->jobmanager_log_fp;
out:
    return rc;
}
/* globus_gram_job_manager_request_copy() */

/**
 * Change the status associated with a job request
 *
 * Changes the status associated with a job request.
 * There is now additional tracking data associated with the
 * status that must be updated when the status is.  This function
 * handles managing it.  It is NOT recommended that you directly
 * change the status.
 *
 * @param request
 *        Job request to change status of.
 * @param status
 *        Status to set the job request to.
 *
 * @return GLOBUS_SUCCESS assuming valid input.
 *         If the request is null, returns GLOBUS_FAILURE.
 */
int
globus_gram_job_manager_request_set_status(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_protocol_job_state_t	status)
{
    return globus_gram_job_manager_request_set_status_time(request, status,
		time(0));
}
/* globus_gram_job_manager_request_set_status() */


/**
 * Change the status associated with a job request
 *
 * Changes the status associated with a job request.
 * There is now additional tracking data associated with the
 * status that must be updated when the status is.  This function
 * handles managing it.  It is NOT recommended that you directly
 * change the status.
 *
 * @param request
 *        Job request to change status of.
 * @param status
 *        Status to set the job request to.
 * @param valid_time
 *        The status is known good as of this time (seconds since epoch)
 *
 * @return GLOBUS_SUCCESS assuming valid input.
 *         If the request is null, returns GLOBUS_FAILURE.
 */
int
globus_gram_job_manager_request_set_status_time(
    globus_gram_jobmanager_request_t *	request,
    globus_gram_protocol_job_state_t	status,
    time_t valid_time)
{
    if( ! request )
        return GLOBUS_FAILURE;
    request->status = status;
    request->status_update_time = valid_time;
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_request_set_status() */

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

        if (!request->jobmanager_log_fp)
        {
            request->jobmanager_log_fp = fopen(request->jobmanager_logfile, "a");
        }
	
	if(request->jobmanager_log_fp == NULL)
        {
	    if(request->jobmanager_log_fp == NULL)
            {
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
        int fd;

	setbuf(request->jobmanager_log_fp, NULL);

        fd = fileno(request->jobmanager_log_fp);

        while(fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        {
            if(errno != EINTR)
            {
                break;
            }
        }
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

    if (!request)
    {
        return -1;
    }

    if ( request->jobmanager_log_fp == GLOBUS_NULL ) {
	return -1;
    }

    time( &curr_time );
    curr_tm = localtime( &curr_time );

    globus_libc_lock();

    fprintf( request->jobmanager_log_fp,
	     "%d/%d %02d:%02d:%02d %p ",
	     curr_tm->tm_mon + 1, curr_tm->tm_mday,
	     curr_tm->tm_hour, curr_tm->tm_min,
	     curr_tm->tm_sec,
             request);

    va_start(ap, format);

    rc = vfprintf( request->jobmanager_log_fp,
	           format,
		   ap);

    globus_libc_unlock();

    return rc;
}
/* globus_gram_job_manager_request_log() */

/**
 * Write data to the job manager accounting file.
 * Also use syslog() to allow for easy central collection.
 *
 * This function writes data to the passed file descriptor, if any,
 * using a printf format string.
 * Data is prefixed with a timestamp when written.
 *
 * @param format
 *        Printf-style format string to be written.
 * @param ...
 *        Parameters substituted into the format string, if needed.
 *
 * @return This function returns the value returned by write().
 */
int
globus_gram_job_manager_request_acct(
    globus_gram_jobmanager_request_t *	request,
    const char *			format,
    ... )
{
    static const char *jm_syslog_id  = "gridinfo";
    static int         jm_syslog_fac = LOG_DAEMON;
    static int         jm_syslog_lvl = LOG_NOTICE;
    static int         jm_syslog_init;
    struct tm *curr_tm;
    time_t curr_time;
    va_list ap;
    int rc = -1;
    int fd;
    const char * gk_acct_fd_var = "GATEKEEPER_ACCT_FD";
    const char * gk_acct_fd;
    int n;
    int t;
    char buf[1024 * 128];

    time( &curr_time );
    curr_tm = localtime( &curr_time );

    n = t = sprintf( buf, "JMA %04d/%02d/%02d %02d:%02d:%02d ",
		     curr_tm->tm_year + 1900,
		     curr_tm->tm_mon + 1, curr_tm->tm_mday,
		     curr_tm->tm_hour, curr_tm->tm_min,
		     curr_tm->tm_sec );

    va_start( ap, format );

    /*
     * FIXME: we should use vsnprintf() here...
     */

    n += vsprintf( buf + t, format, ap );

    if (!jm_syslog_init) {
	const char *s;

	if ((s = globus_libc_getenv( "JOBMANAGER_SYSLOG_ID"  )) != 0) {
	    jm_syslog_id = *s ? s : 0;
	}

	if ((s = globus_libc_getenv( "JOBMANAGER_SYSLOG_FAC" )) != 0) {
	    if (sscanf( s, "%u", &jm_syslog_fac ) != 1) {
		jm_syslog_id = 0;
	    }
	}

	if ((s = globus_libc_getenv( "JOBMANAGER_SYSLOG_LVL" )) != 0) {
	    if (sscanf( s, "%u", &jm_syslog_lvl ) != 1) {
		jm_syslog_id = 0;
	    }
	}

	if (jm_syslog_id) {
	    openlog( jm_syslog_id, LOG_PID, jm_syslog_fac );
	}

	jm_syslog_init = 1;
    }

    if (jm_syslog_id)
    {
	char *p, *q = buf;

	while ((p = q) < buf + n) {
	    char c;

	    while ((c = *q) != 0 && c != '\n') {
		q++;
	    }

	    *q = 0;

	    syslog( jm_syslog_lvl, "%s", p );

	    *q++ = c;
	}
    }

    if (!(gk_acct_fd = globus_libc_getenv( gk_acct_fd_var )))
    {
	return -1;
    }

    if (sscanf( gk_acct_fd, "%d", &fd ) != 1)
    {
	globus_gram_job_manager_request_log( request,
	    "ERROR: %s has bad value: '%s'\n", gk_acct_fd_var, gk_acct_fd );
	return -1;
    }

    if (fcntl( fd, F_SETFD, FD_CLOEXEC ) < 0)
    {
	globus_gram_job_manager_request_log( request,
	    "ERROR: cannot set FD_CLOEXEC on %s '%s': %s\n",
	    gk_acct_fd_var, gk_acct_fd, strerror( errno ) );
    }

    if ((rc = write( fd, buf, n )) != n)
    {
	globus_gram_job_manager_request_log( request,
	    "ERROR: only wrote %d bytes to %s '%s': %s\n%s\n",
	    rc, gk_acct_fd_var, gk_acct_fd, strerror( errno ), buf + t );

	rc = -1;
    }

    return rc;
}
/* globus_gram_job_manager_request_acct() */
