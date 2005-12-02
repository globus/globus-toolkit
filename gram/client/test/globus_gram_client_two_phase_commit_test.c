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

#include "globus_common.h"
#include "globus_gram_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char * format = "&(executable=/bin/true)(save_state=%s)(two_phase=%d)";

typedef struct
{
    char * callback_contact;
    char * job_contact;
    globus_mutex_t mutex;
    globus_cond_t cond;
    enum { no_commit, no_commit_end, commit} mode;
    int job_status;
    int failure_code;
    int timeout;
}
monitor_t;

static 
void
globus_l_state_callback(void * callback_arg, char * job_contact, int state,
        int errorcode);

static
globus_bool_t
globus_l_get_mode(monitor_t * monitor, char * arg)
{
    globus_bool_t ret = GLOBUS_TRUE;

    if (! strcmp(arg, "no-commit"))
    {
        monitor->mode = no_commit;
    }
    else if (! strcmp(arg, "no-commit-end"))
    {
        monitor->mode = no_commit_end;
    }
    else if (! strcmp(arg, "commit"))
    {
        monitor->mode = commit;
    }
    else
    {
        ret = GLOBUS_FALSE;
    }
    return ret;
}

int main(int argc, char *argv[])
{
    int rc;
    monitor_t monitor;
    char * rsl;

    if (argc < 5 || (!globus_l_get_mode(&monitor, argv[2]))
            || (strcmp(argv[3], "yes") && strcmp(argv[3], "no"))
            || ((monitor.timeout = atoi(argv[4])) < 0))
    {
        globus_libc_fprintf(stderr,
                "Usage: %s RM-CONTACT MODE SAVE_STATE TIMEOUT\n"
                "    RM-CONTACT: resource manager contact\n"
                "    MODE: no-commit|no-commit-end|commit\n"
                "    SAVE_STATE: yes|no\n"
                "    TIMEOUT: two-phase timeout in seconds\n",
                argv[0]);
        goto error_exit;
    }

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(stderr,
                "failure activating GLOBUS_GRAM_CLIENT_MODULE: %s\n",
                globus_gram_client_error_string(rc));
        goto error_exit;
    }

    rsl = globus_libc_malloc(strlen(format)
            + 1 + strlen(argv[3]) + strlen(argv[4]));

    if (rsl == NULL)
    {
        globus_libc_fprintf(stderr, "failure allocating rsl string\n");
        goto deactivate_exit;
    }

    rc = sprintf(rsl, format, argv[3], monitor.timeout);
    if (rc < 0)
    {
        globus_libc_fprintf(stderr, "failure formatting rsl string\n");
        goto free_rsl_exit;
    }
    globus_mutex_init(&monitor.mutex, NULL);
    globus_cond_init(&monitor.cond, NULL);
    monitor.job_contact = NULL;
    monitor.callback_contact = NULL;

    rc = globus_gram_client_callback_allow(
            globus_l_state_callback,
            &monitor,
            &monitor.callback_contact);

    if (rc != GLOBUS_SUCCESS || monitor.callback_contact == NULL)
    {
        globus_libc_fprintf(stderr,
                "failure allowing callbacks\n");
        rc = -1;
        goto destroy_monitor_exit;
    }

    globus_mutex_lock(&monitor.mutex);
    rc = globus_gram_client_job_request(
            argv[1],
            rsl,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL,
            monitor.callback_contact,
            &monitor.job_contact);
    if (monitor.job_contact != NULL)
    {
        globus_libc_printf("%s\n", monitor.job_contact);
    }

    if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT)
    {
        if (rc == GLOBUS_SUCCESS)
        {
            globus_libc_fprintf(stderr,
                    "job manager did not return "
                    "GLOBUS_GRAM_PROTOCOL_ERROR_COMMIT_TIMED_OUT\n");
            rc = -1;
        }
        else
        {
            globus_libc_fprintf(stderr,
                    "failure submitting job request [%d]: %s\n",
                    rc,
                    globus_gram_client_error_string(rc));
        }

        goto disallow_exit;
    }
    rc = 0;

    if (monitor.mode == no_commit)
    {
        goto disallow_exit;
    }

    rc = globus_gram_client_job_signal(
            monitor.job_contact,
            GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_REQUEST,
            NULL,
            &monitor.job_status,
            &monitor.failure_code);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(stderr,
                "failure sending commit signal: %s\n",
                globus_gram_client_error_string(rc));
        goto disallow_exit;
    }

    while (monitor.job_status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE &&
           monitor.job_status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);
    }

    if (monitor.mode == no_commit_end)
    {
        rc = 0;
        goto disallow_exit;
    }

    rc = globus_gram_client_job_signal(
            monitor.job_contact,
            GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_END,
            NULL,
            &monitor.job_status,
            &monitor.failure_code);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(stderr,
                "failure sending commit end signal: %s\n",
                globus_gram_client_error_string(rc));
        goto disallow_exit;
    }

disallow_exit:
    if (monitor.job_contact != NULL)
    {
        globus_gram_client_job_contact_free(monitor.job_contact);
    }
    globus_mutex_unlock(&monitor.mutex);
    globus_gram_client_callback_disallow(monitor.callback_contact);
destroy_monitor_exit:
    if (monitor.callback_contact != NULL)
    {
        globus_libc_free(monitor.callback_contact);
    }
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
free_rsl_exit:
    globus_libc_free(rsl);
deactivate_exit:
    globus_module_deactivate_all();
error_exit:
    return rc;
}

static 
void
globus_l_state_callback(
    void * callback_arg,
    char * job_contact,
    int state,
    int errorcode)
{
    monitor_t * monitor = callback_arg;

    globus_mutex_lock(&monitor->mutex);
    if (! strcmp(monitor->job_contact, job_contact))
    {
        monitor->job_status = state;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}
