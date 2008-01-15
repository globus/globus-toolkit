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

typedef struct
{
	int				state;
	int				errorcode;
	globus_mutex_t			mutex;
	globus_cond_t			cond;
}
monitor_t;

static
void
gram_state_callback(
    void *				arg,
    char *				job_contact,
    int					state,
    int					errorcode);

int main(int argc, char *argv[])
{
    char *				callback_contact;
    char *				job_contact;
    monitor_t				monitor;
    int					rc = 0;
    gss_cred_id_t                       cred;
    OM_uint32                           maj_stat, min_stat;

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

    maj_stat = globus_gss_assist_acquire_cred(
            &min_stat,
            GSS_C_BOTH,
            &cred);

    if (GSS_ERROR(maj_stat))
    {
        char * status;
        globus_gss_assist_display_status_str(
            &status,
            "acquire_cred",
            maj_stat,
            min_stat,
            0);
        fprintf(stderr, "%s\n", status);
        free(status);

        rc = 1;

        goto error_exit;
    }
    rc = globus_gram_client_set_credentials(cred);
    if (rc != 0)
    {
        fprintf(stderr, "Error setting credentials\n");

        goto error_exit;
    }

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
	    argv[1],
	    "&(executable=/bin/sleep)(arguments=90)",
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

    while(monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED &&
	  monitor.state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }

    rc = monitor.errorcode;
destroy_callback_contact:
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
    monitor_t *				monitor;

    monitor = arg;

    globus_mutex_lock(&monitor->mutex);
    monitor->state = state;
    monitor->errorcode = errorcode;
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}
/* gram_state_callback() */
