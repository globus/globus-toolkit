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

#include "globus_common.h"
#include "globus_gram_client.h"

typedef struct
{
	int				state;
	int				errorcode;
	globus_mutex_t			mutex;
	globus_cond_t			cond;
}
monitor_t;

int cb_count=0;

static
void
gram_state_callback(
    void *				arg,
    char *				job_contact,
    int					state,
    int					errorcode);

static
void
nonblocking_callback(
    void *                              user_callback_arg,
    globus_gram_protocol_error_t        operation_failure_code,
    const char *                        job_contact,
    globus_gram_protocol_job_state_t    job_state,
    globus_gram_protocol_error_t        job_failure_code);



int main(int argc, char *argv[])
{
    char *				callback_contact;
    char *				job_contact;
    monitor_t				monitor;
    int					rc = 0;
    globus_abstime_t			timeout;
    globus_abstime_t			start_time;
    globus_abstime_t			stop_time;
    globus_reltime_t			delta;
    int					calls=0;

    if(argc != 2)
    {
	fprintf(stderr, "Usage: %s resource-manager-contact\n", argv[0]);
	exit(1);
    }
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc)
    {
	goto end;
    }
    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    if(rc)
    {
	goto disable_modules;
    }

    globus_mutex_init(&monitor.mutex ,GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.state = GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING;

    rc = globus_gram_client_callback_allow(gram_state_callback,
	                                   &monitor,
					   &callback_contact);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error creating callback contact %s.\n",
		globus_gram_client_error_string(rc));

	goto error_exit;
    }

    globus_mutex_lock(&monitor.mutex);
    cb_count++;
    rc = globus_gram_client_job_request(
	    argv[1],
	    "&(executable=/bin/sleep)(arguments=60)",
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL,
	    callback_contact,
	    &job_contact);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error submitting job request %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_callback_contact;
    }

    GlobusTimeAbstimeGetCurrent(start_time);

    while(monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED &&
	  monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
    {
	rc = globus_gram_client_register_job_status(
		job_contact,
		GLOBUS_GRAM_CLIENT_NO_ATTR,
		nonblocking_callback,
		&monitor);
	cb_count++;
	calls++;

	if(rc != GLOBUS_SUCCESS)
	{
	    fprintf(stderr, "job status check failed because %s.\n",
		    globus_gram_client_error_string(rc));
	}
	if(rc != GLOBUS_SUCCESS &&
           rc != GLOBUS_GRAM_PROTOCOL_ERROR_CONNECTION_FAILED)
	{
	    goto destroy_callback_contact;
	}

	GlobusTimeAbstimeSet(timeout, 0, 100);

	while(cb_count > 2)
	{
	    globus_cond_timedwait(&monitor.cond, &monitor.mutex, &timeout);
	}
    }

    rc = monitor.errorcode;
destroy_callback_contact:
    if(calls)
    {
	GlobusTimeAbstimeGetCurrent(stop_time);

	GlobusTimeAbstimeDiff(delta, start_time, stop_time);

	fprintf(stderr,
		"Made %d calls to status in %ld.%06ld seconds\n",
		calls,
		(long) delta.tv_sec,
		(long) delta.tv_usec);
    }
    globus_mutex_unlock(&monitor.mutex);
    globus_gram_client_callback_disallow(callback_contact);
    globus_libc_free(callback_contact);
    globus_libc_free(job_contact);
error_exit:
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
disable_modules:
    globus_module_deactivate_all();
end:
    return rc;
}
/* main() */

static
void
gram_state_callback(
    void *				arg,
    char *				job_contact,
    int					state,
    int					errorcode)
{
    nonblocking_callback(arg, 0, job_contact, state, errorcode);
}
/* gram_state_callback() */

static
void
nonblocking_callback(
    void *                              user_callback_arg,
    globus_gram_protocol_error_t        operation_failure_code,
    const char *                        job_contact,
    globus_gram_protocol_job_state_t    job_state,
    globus_gram_protocol_error_t        job_failure_code)
{
    monitor_t *				monitor;

    monitor = user_callback_arg;

    globus_mutex_lock(&monitor->mutex);
    monitor->state = job_state;
    monitor->errorcode =
	operation_failure_code ? operation_failure_code : job_failure_code;
    cb_count--;
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}
