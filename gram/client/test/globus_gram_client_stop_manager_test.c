/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_gram_client.h"

#include <string.h>

typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_gram_protocol_job_state_t	state;
    int					failure_code;
}
test_monitor_t;

static
void
gram_callback(
    void *				user_callback_arg,
    char *				job_contact,
    int					state,
    int					error_code)
{
    test_monitor_t *			monitor;

    monitor = user_callback_arg;

    globus_mutex_lock(&monitor->mutex);
    monitor->state = state;
    monitor->failure_code = error_code;
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}

int main(int argc, char *argv[])
{
    int					rc;
    char *				contact;
    char *				job_contact;
    const char *			rsl_format="&(restart=%s)";
    char *				rsl;
    test_monitor_t			monitor;
    int                                 test_num=1;

    if(argc != 2 && argc != 3)
    {
	fprintf(stderr, "usage: %s gatekeeper-contact [test-number]\n"
                "where test-number is 1 or 2\n", argv[0]);
    }

    if(argc == 3)
    {
        test_num = atoi(argv[2]);
    }
    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    rc |= globus_module_activate(GLOBUS_COMMON_MODULE);

    if(rc != GLOBUS_SUCCESS)
    {
	goto error_exit;
    }

    globus_mutex_init(&monitor.mutex, NULL);
    globus_cond_init(&monitor.cond, NULL);
    monitor.state = GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED;

    globus_mutex_lock(&monitor.mutex);

    rc = globus_gram_client_callback_allow(gram_callback, &monitor, &contact);

    if(rc != GLOBUS_SUCCESS)
    {
	goto deactivate_exit;
    }
    printf("submitting job request\n");
    rc = globus_gram_client_job_request(
	    argv[1],
            (test_num == 1)
                ? ("&(executable=/bin/no-such-executable)"
                    "(two_phase=30)(save_state=yes)")
                : ("&(executable=/bin/sleep)(arguments=60)"
                   " (two_phase=30)(save_state=yes)"),
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL,
	    contact,
	    &job_contact);

    if(rc != GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT)
    {
	goto disallow_exit;
    }

    printf("sending commit signal\n");
    rc = globus_gram_client_job_signal(
	    job_contact,
	    GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_REQUEST,
	    NULL,
	    NULL,
	    NULL);

    if(rc != GLOBUS_SUCCESS)
    {
	goto disallow_exit;
    }

    printf("waiting for job\n");
    while(monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE &&
	  monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    printf("stopping the job manager\n");
    rc = globus_gram_client_job_signal(
	    job_contact,
	    GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STOP_MANAGER,
	    NULL,
	    NULL,
	    NULL);

    if(rc != GLOBUS_SUCCESS)
    {
	goto disallow_exit;
    }

    if(test_num == 1 && monitor.failure_code
            != GLOBUS_GRAM_PROTOCOL_ERROR_EXECUTABLE_NOT_FOUND)
    {
        goto disallow_exit;
    }
    else if(test_num == 2 && monitor.failure_code
            != GLOBUS_SUCCESS)
    {
        goto disallow_exit;
    }

    rsl = globus_libc_malloc(strlen(rsl_format) + strlen(job_contact) + 1);

    sprintf(rsl, rsl_format, job_contact);
    globus_libc_free(job_contact);
    monitor.state = GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED;

    printf("restarting the job manager\n");
    rc = globus_gram_client_job_request(
	    argv[1],
	    rsl,
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL,
	    contact,
	    &job_contact);

    if(rc != GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT)
    {
	goto disallow_exit;
    }

    printf("commiting the restart\n");
    rc = globus_gram_client_job_signal(
	    job_contact,
	    GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_REQUEST,
	    NULL,
	    NULL,
	    NULL);

    if(rc != GLOBUS_SUCCESS)
    {
	goto disallow_exit;
    }
    printf("waiting for the job\n");
    while(monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE &&
	  monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    if(test_num == 1 && monitor.failure_code
            == GLOBUS_GRAM_PROTOCOL_ERROR_EXECUTABLE_NOT_FOUND)
    {
        printf("signalling commit end\n");
        rc = globus_gram_client_job_signal(
                job_contact,
                GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_END,
                NULL,
                NULL,
                NULL);
    }
    else if(test_num == 2 && monitor.failure_code == GLOBUS_SUCCESS)
    {
        printf("signalling commit end\n");
        rc = globus_gram_client_job_signal(
                job_contact,
                GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_END,
                NULL,
                NULL,
                NULL);
    }
    else
    {
        rc = -1;
    }

    globus_libc_free(job_contact);

disallow_exit:
    globus_gram_client_callback_disallow(contact);
deactivate_exit:
    globus_mutex_unlock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    globus_module_deactivate_all();
error_exit:
    return rc;
}
