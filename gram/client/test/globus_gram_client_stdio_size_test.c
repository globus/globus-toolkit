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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STDOUT_SIZE "18" /*strlen("hello\nhello again\n")*/

const char * rsl = "&(executable=/bin/sh)"
        "(arguments=-c '/bin/echo hello; /bin/sleep 30; /bin/echo hello again')"
        "(stdout=/dev/../dev/null)"
        "(save_state=yes)(two_phase=60)";

typedef struct
{
    char * callback_contact;
    char * job_contact;
    globus_mutex_t mutex;
    globus_cond_t cond;
    int job_status;
    int failure_code;
    int stdout_size;
}
monitor_t;

static 
void
globus_l_state_callback(void * callback_arg, char * job_contact, int state,
        int errorcode);

int main(int argc, char *argv[])
{
    int rc;
    monitor_t monitor;

    if (argc < 2)
    {
        globus_libc_fprintf(stderr,
                "Usage: %s RM-CONTACT\n"
                "    RM-CONTACT: resource manager contact\n",
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

    if (monitor.job_status  != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE &&
           monitor.job_status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
        rc = globus_gram_client_job_signal(
                monitor.job_contact,
                GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_SIZE,
                STDOUT_SIZE,
                NULL,
                NULL);

        if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_STILL_STREAMING)
        {
            globus_libc_fprintf(stderr,
                    "job manager returned %d (%s) when I expected it to still "
                    "be streaming output\n",
                    rc, globus_gram_client_error_string(rc));
            goto disallow_exit;
        }
    }
    while (monitor.job_status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE &&
           monitor.job_status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);
    }

    rc = globus_gram_client_job_signal(
            monitor.job_contact,
            GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_SIZE,
            STDOUT_SIZE,
            NULL,
            NULL);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(stderr,
                "job manager returned %d (%s) when I expected it to still "
                "be streaming output\n",
                rc, globus_gram_client_error_string(rc));
        goto disallow_exit;
    }

    rc = globus_gram_client_job_signal(
            monitor.job_contact,
            GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_SIZE,
            "0",
            NULL,
            NULL);

    if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_STDIO_SIZE)
    {
        globus_libc_fprintf(stderr,
                "job manager returned %d (%s) when I expected it to give me "
                "an incorrect size error\n",
                rc, globus_gram_client_error_string(rc));
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
