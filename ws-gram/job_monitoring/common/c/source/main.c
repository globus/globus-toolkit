#include "globus_common.h"
#include "globus_scheduler_event_generator.h"

#include <stdio.h>
#include <unistd.h>

static globus_mutex_t shutdown_mutex;
static globus_cond_t shutdown_cond;
static globus_bool_t shutdown_called = GLOBUS_FALSE;

static
void
globus_l_fault_handler(
    void *                              user_arg,
    globus_result_t                     fault);

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

    if (timestamp != 0)
    {
        result = globus_scheduler_event_generator_set_timestamp(timestamp);

        if (result != GLOBUS_SUCCESS)
        {
            fprintf(stderr,
                    "Error setting timestamp: %s\n",
                    globus_object_printable_to_string(
                            globus_error_peek(result)));
            goto deactivate_error;
        }
    }

    if (module == NULL)
    {
        fprintf(stderr, "Missing module name [-s parameter]\n");
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
    globus_mutex_lock(&shutdown_mutex);
    fprintf(stderr, "SEG Fault: %s\n",
            globus_object_printable_to_string(globus_error_peek(fault)));
    shutdown_called = GLOBUS_TRUE;
    globus_cond_signal(&shutdown_cond);
    globus_mutex_unlock(&shutdown_mutex);
}
/* globus_l_fault_handler() */
