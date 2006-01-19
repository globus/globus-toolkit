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

char * resource_manager_contact = 0;

typedef struct
{
	int				state;
	int				errorcode;
	globus_mutex_t			mutex;
	globus_cond_t			cond;
	int				done_count;
}
monitor_t;

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
    void *				arg,
    globus_gram_protocol_error_t	operation_failure_code,
    const char *			job_contact,
    globus_gram_protocol_job_state_t	job_state,
    globus_gram_protocol_error_t	job_failure_code);

/* submit a job without a callback contact, register a callback
 * contact, wait for job to terminate
 */
int
test1()
{
    char *				callback_contact;
    char *				job_contact;
    int					rc;
    monitor_t				monitor;

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);

    if(rc)
    {
	goto disable_module;
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
    rc = globus_gram_client_job_request(
	    resource_manager_contact,
	    "&(executable=/bin/sleep)(arguments=90)",
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL,
	    GLOBUS_NULL,
	    &job_contact);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Failed submitting job request because %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_callback_contact;
    }
    
    rc = globus_gram_client_register_job_callback_registration(
	    job_contact,
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED|
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE,
	    callback_contact,
	    GLOBUS_GRAM_CLIENT_NO_ATTR,
	    nonblocking_callback,
	    GLOBUS_NULL);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error registering callback contact because %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_callback_contact;
    }

    while(monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED &&
	  monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }

    rc = monitor.errorcode;

destroy_callback_contact:
    globus_gram_client_callback_disallow(callback_contact);
    globus_libc_free(callback_contact);
    globus_libc_free(job_contact);
    globus_mutex_unlock(&monitor.mutex);
error_exit:
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
disable_module:
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);

    return rc;
}

/* submit a job with a callback contact, register another callback
 * contact (2x), wait for job to terminate
 */
int
test2()
{
    char *				callback_contact[3];
    char *				job_contact;
    int					rc;
    monitor_t				monitor;

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);

    if(rc)
    {
	goto disable_module;
    }

    globus_mutex_init(&monitor.mutex ,GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.state = GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING;
    monitor.done_count = 0;

    rc = globus_gram_client_callback_allow(gram_state_callback,
	                                   &monitor,
					   &callback_contact[0]);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error creating callback contact %s.\n",
		globus_gram_client_error_string(rc));

	goto error_exit;
    }
    rc = globus_gram_client_callback_allow(gram_state_callback,
	                                   &monitor,
					   &callback_contact[1]);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error creating callback contact %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_callback_contact0;
    }
    rc = globus_gram_client_callback_allow(gram_state_callback,
	                                   &monitor,
					   &callback_contact[2]);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error creating callback contact %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_callback_contact1;
    }

    globus_mutex_lock(&monitor.mutex);
    rc = globus_gram_client_job_request(
	    resource_manager_contact,
	    "&(executable=/bin/sleep)(arguments=90)",
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL,
	    callback_contact[0],
	    &job_contact);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Failed submitting job request because %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_callback_contact1;
    }
    
    rc = globus_gram_client_register_job_callback_registration(
	    job_contact,
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED|
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE,
	    callback_contact[1],
	    GLOBUS_GRAM_CLIENT_NO_ATTR,
	    nonblocking_callback,
	    GLOBUS_NULL);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error registering callback contact because %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_callback_contact2;
    }
    rc = globus_gram_client_register_job_callback_registration(
	    job_contact,
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED|
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE,
	    callback_contact[2],
	    GLOBUS_GRAM_CLIENT_NO_ATTR,
	    nonblocking_callback,
	    GLOBUS_NULL);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error registering callback contact because %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_callback_contact2;
    }

    while(monitor.done_count < 3)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }

    rc = monitor.errorcode;

destroy_callback_contact2:
    globus_gram_client_callback_disallow(callback_contact[2]);
    globus_libc_free(callback_contact[2]);
destroy_callback_contact1:
    globus_gram_client_callback_disallow(callback_contact[1]);
    globus_libc_free(callback_contact[1]);
destroy_callback_contact0:
    globus_gram_client_callback_disallow(callback_contact[0]);
    globus_libc_free(callback_contact[0]);
    globus_libc_free(job_contact);
    globus_mutex_unlock(&monitor.mutex);
error_exit:
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
disable_module:
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);

    return rc;
}

/* submit a job with a callback contact, unregister another bogus callback
 * contact, wait for job to terminate
 */
int
test3()
{
    char *				callback_contact;
    char *				job_contact;
    char *				bad_callback_contact;
    int					rc;
    monitor_t				monitor;

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);

    if(rc)
    {
	goto disable_module;
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
    rc = globus_gram_client_callback_allow(gram_state_callback,
	                                   &monitor,
					   &bad_callback_contact);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Error creating callback contact %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_callback_contact;
    }

    globus_mutex_lock(&monitor.mutex);
    rc = globus_gram_client_job_request(
	    resource_manager_contact,
	    "&(executable=/bin/sleep)(arguments=90)",
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL,
	    callback_contact,
	    &job_contact);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr,
		"Failed submitting job request because %s.\n",
		globus_gram_client_error_string(rc));

	goto destroy_bad_callback_contact;
    }
    
    rc = globus_gram_client_register_job_callback_unregistration(
	    job_contact,
	    bad_callback_contact,
	    GLOBUS_GRAM_CLIENT_NO_ATTR,
	    nonblocking_callback,
	    GLOBUS_NULL);

    while(monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED &&
	  monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }

    if(rc != GLOBUS_GRAM_PROTOCOL_ERROR_CLIENT_CONTACT_NOT_FOUND)
    {
	rc |= monitor.errorcode;
    }
    else
    {
	rc = 0;
    }

destroy_bad_callback_contact:
    globus_gram_client_callback_disallow(bad_callback_contact);
    globus_libc_free(bad_callback_contact);
destroy_callback_contact:
    globus_gram_client_callback_disallow(callback_contact);
    globus_libc_free(callback_contact);
    globus_libc_free(job_contact);
    globus_mutex_unlock(&monitor.mutex);
error_exit:
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
disable_module:
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);

    return rc;
}

int
main(int argc, char *argv[])
{
    int					rc = 0;
    int					test_num = 0;
    int					not_ok = 0;

    if(argc < 2)
    {
	fprintf(stderr, "Usage: %s resource-manager-contact [test number]\n",
		argv[0]);
	exit(1);
    }
    resource_manager_contact = argv[1];

    if(argc > 2)
    {
	test_num = atoi(argv[2]);
    }
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc)
    {
	not_ok |= rc;
	goto end;
    }

    if(test_num == 0 || test_num == 1)
    {
	rc = test1();
	printf("%sok\n", rc ? "not " : "");
	not_ok |= rc;
    }

    if(test_num == 0 || test_num == 2)
    {
	rc = test2();
	printf("%sok\n", rc ? "not " : "");
	not_ok |= rc;
    }

    if(test_num == 0 || test_num == 3)
    {
	rc = test3();
	printf("%sok\n", rc ? "not " : "");
	not_ok |= rc;
    }


    globus_module_deactivate_all();
end:
    return not_ok;
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
    void *				arg,
    globus_gram_protocol_error_t	operation_failure_code,
    const char *			job_contact,
    globus_gram_protocol_job_state_t	job_state,
    globus_gram_protocol_error_t	job_failure_code)
{
    monitor_t *				monitor;

    monitor = arg;
    if(!monitor) return;

    globus_mutex_lock(&monitor->mutex);
    monitor->state = job_state;
    monitor->errorcode = operation_failure_code ? operation_failure_code : job_failure_code;
    if(job_state == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE ||
       job_state == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
	monitor->done_count++;
    }
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}
/* nonblocking_callback() */
