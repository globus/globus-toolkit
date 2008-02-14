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
#include "globus_scheduler_event_generator.h"
#include "globus_scheduler_event_generator_app.h"
#include "globus_scheduler_event_generator_stdout.h"

#include <stdio.h>
#include <unistd.h>

static globus_mutex_t shutdown_mutex;
static globus_cond_t shutdown_cond;
static globus_bool_t shutdown_called = GLOBUS_FALSE;

/**
 * @mainpage Globus Scheduler Event Generator
 *
 * The Scheduler Event Generator (SEG) is a program which uses
 * scheduler-specific monitoring modules to generate job state
 * change events. At the SEG level, the state change events correspond to 
 * changes in any jobs which are managed by the scheduler, even if they do
 * not correspond to jobs initiated by the Managed Job Service. These state
 * change events are propagated to the Job State Monitor.
 *
 * Depending on scheduler-specific requirements, the SEG may need to run with 
 * priviledges to enable it to obtain scheduler event
 * notifications. As such, one SEG runs per scheduler resource. For example,
 * on a host which provides access to both PBS and fork jobs, two SEGs, running
 * at (potentially) different privilege levels will be running.
 *
 * When executed, the SEG is able to start issuing events from some
 * time in the past. The SEG will, in general, not require any persistent
 * state between invocations. One SEG instance exists for any particular
 * scheduled resource instance (one for all homogeneous PBS queues, one for
 * all fork jobs, etc).
 *
 * The SEG is implemented in an executable called the
 * globus-scheduler-event-generator, located in the Globus Toolkit's libexec
 * directory. It is invoked with the following command line:
 * 
 * @code
 *     globus-scheduler-event-generator -s SCHEDULER NAME [-t TIMESTAMP]
 * @endcode
 *     
 * It produces events in the format described in the
 * @ref seg_protocol "SEG Protocol" section of this document on the standard
 * output of the process.
 * 
 * When begun, it loads the scheduler module for the scheduler named on the
 * command line and then defers to it for most functionality. When it detects
 * an error writing to stdout or reading stdin, it terminates. The scheduler
 * specific code uses the SEG API to emit events to the JSM.
 *
 * Scheduler implementations use the @ref seg_api "SEG API" to send messages
 * to the JSM.
 */
static
void
globus_l_fault_handler(
    void *                              user_arg,
    globus_result_t                     fault);


static
void
usage(char * cmd)
{
    printf("Usage: %s [-t timestamp] -s scheduler\n", cmd);
}

int
main(int argc, char *argv[])
{
    int rc;
    char * module = NULL;
    time_t timestamp = 0;
    globus_result_t result;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    if (rc != 0)
    {
        goto error;
    }

    rc = globus_module_activate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);

    if (rc != 0)
    {
        goto deactivate_error;
    }

    rc = globus_module_activate(GLOBUS_SCHEDULER_EVENT_GENERATOR_STDOUT_MODULE);

    while ((rc = getopt(argc, argv, "s:t:")) != EOF)
    {
        switch (rc)
        {
        case 's':
            module = optarg;
            break;

        case 't':
            rc = sscanf(optarg, "%lu", (unsigned long*) &timestamp);
            if (rc < 1)
            {
                fprintf(stderr, "Invalid timestamp [%s]\n", optarg);
                goto deactivate_error;

            }
            break;

        default:
            fprintf(stderr, "Invalid option: %c\n", (char) rc);
            usage(argv[0]);

            goto deactivate_error;
        }
    }

    result = globus_scheduler_event_generator_set_fault_handler(
            globus_l_fault_handler,
            NULL);

    if (result != GLOBUS_SUCCESS)
    {
        goto deactivate_error;
    }

    result = globus_scheduler_event_generator_set_event_handler(
            globus_scheduler_event_generator_stdout_handler,
            NULL);
    if (result != GLOBUS_SUCCESS)
    {
        goto deactivate_error;
    }

    if (timestamp != 0)
    {
        result = globus_scheduler_event_generator_set_timestamp(timestamp);

        if (result != GLOBUS_SUCCESS)
        {
            goto deactivate_error;
        }
    }

    if (module == NULL)
    {
        fprintf(stderr, "Error: no scheduler specified\n");

        usage(argv[0]);

        goto deactivate_error;
    }
    else
    {
        result = globus_scheduler_event_generator_load_module(
                module);

        if (result != GLOBUS_SUCCESS)
        {
            goto deactivate_error;
        }
    }

    globus_mutex_lock(&shutdown_mutex);

    while (! shutdown_called)
    {
        globus_cond_wait(&shutdown_cond, &shutdown_mutex);
    }

    globus_mutex_unlock(&shutdown_mutex);

    globus_module_deactivate_all();

    return 0;

deactivate_error:
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "%s\n",
                globus_object_printable_to_string(
                        globus_error_peek(result)));
    }
    globus_module_deactivate_all();
error:
    return 1;
}
/* main() */

static
void
globus_l_fault_handler(
    void *                              user_arg,
    globus_result_t                     fault)
{
    globus_object_t *                   err = NULL;

    if (fault != GLOBUS_SUCCESS)
    {
        err = globus_error_peek(fault);
    }

    if (! globus_error_match(err, GLOBUS_XIO_MODULE, GLOBUS_XIO_ERROR_CANCELED))
    {
        fprintf(stderr, "Fault: %s\n",
                globus_object_printable_to_string(globus_error_peek(fault)));
    }

    globus_mutex_lock(&shutdown_mutex);
    shutdown_called = GLOBUS_TRUE;
    globus_cond_signal(&shutdown_cond);
    globus_mutex_unlock(&shutdown_mutex);
}
/* globus_l_fault_handler() */
