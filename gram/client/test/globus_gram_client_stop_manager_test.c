#include "globus_gram_client.h"

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

    if(argc != 2)
    {
	fprintf(stderr, "usage: %s gatekeeper-contact\n", argv[0]);
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
    rc = globus_gram_client_job_request(
	    argv[1],
	    "&(executable=/bin/no-such-executable)(two_phase=30)(save_state=yes)",
	    GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL,
	    contact,
	    &job_contact);

    if(rc != GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT)
    {
	goto disallow_exit;
    }

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

    while(monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE &&
	  monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
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

    rsl = globus_libc_malloc(strlen(rsl_format) + strlen(job_contact) + 1);

    sprintf(rsl, rsl_format, job_contact);
    globus_libc_free(job_contact);
    monitor.state = GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED;

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

    while(monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE &&
	  monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    rc = globus_gram_client_job_signal(
	    job_contact,
	    GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_END,
	    NULL,
	    NULL,
	    NULL);

    if(rc != GLOBUS_SUCCESS)
    {
	goto disallow_exit;
    }
    if(monitor.failure_code == 5)
    {
	rc = 0;
    }
    else
    {
	rc = -1;
    }

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
