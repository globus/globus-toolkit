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
 * @file globus_job_manager.c Resource Allocation Job Manager
 *
 * CVS Information:
 * 
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */

#include "globus_common.h"
#include "gssapi.h"
#include "globus_gss_assist.h"
#include "globus_gsi_system_config.h"
#include "globus_common.h"
#include "globus_callout.h"
#include "globus_gram_job_manager.h"
#include "globus_gram_protocol.h"
#include "globus_rsl.h"
#include "globus_gass_cache.h"
#include "globus_io.h"
#include "globus_gass_transfer.h"
#include "globus_ftp_client.h"
#include "globus_gram_jobmanager_callout_error.h"

static
int
globus_l_gram_job_manager_activate(void);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

int
main(
    int 				argc,
    char **				argv)
{
    int					rc;
    globus_gram_job_manager_config_t    config;
    globus_gram_job_manager_t           manager;
    globus_gram_jobmanager_request_t *  request;
    char *                              sleeptime_str;
    long                                sleeptime;
    globus_bool_t                       debugging_without_client = GLOBUS_FALSE;
    globus_reltime_t			delay;
    char *                              rsl;
    char *                              contact = NULL;
    int                                 job_state_mask = 0;
    gss_ctx_id_t                        context = GSS_C_NO_CONTEXT;

    if ((sleeptime_str = globus_libc_getenv("GLOBUS_JOB_MANAGER_SLEEP")))
    {
	sleeptime = atoi(sleeptime_str);
	sleep(sleeptime);
    }
    /*
     * Stdin and stdout point at socket to client
     * Make sure no buffering.
     * stderr may also, depending on the option in the grid-services
     */
    setbuf(stdout,NULL);

    /* Activate a common before parsing command-line so that
     * things work. Note that we can't activate everything yet because we might
     * set the GLOBUS_TCP_PORT_RANGE after parsing command-line args and we
     * need that set before activating XIO.
     */
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error activating GLOBUS_COMMON_MODULE\n");
        exit(1);
    }

    /* Parse command line options to get jobmanager configuration */
    rc = globus_gram_job_manager_config_init(&config, argc, argv, &rsl);
    if (rc != GLOBUS_SUCCESS)
    {
        exit(1);
    }
    if (rsl)
    {
        debugging_without_client = GLOBUS_TRUE;
    }
    /* Set environment variables from configuration */
    if(config.globus_location != NULL)
    {
        globus_libc_setenv("GLOBUS_LOCATION",
                           config.globus_location,
                           GLOBUS_TRUE);
    }
    if(config.tcp_port_range != NULL)
    {
        globus_libc_setenv("GLOBUS_TCP_PORT_RANGE",
                           config.tcp_port_range,
                           GLOBUS_TRUE);
    }

    /* Activate all of the modules we will be using */
    rc = globus_l_gram_job_manager_activate();
    if(rc != GLOBUS_SUCCESS)
    {
        exit(1);
    }

    /* Set up LRM-specific state based on our configuration. This will create
     * the job contact listener, start the SEG if needed, and open the log
     * file if needed.
     */
    rc = globus_gram_job_manager_init(&manager, &config);
    if(rc != GLOBUS_SUCCESS)
    {
        exit(1);
    }

    /*
     * Attempt to import security context and read HTTP input to get RSL value
     * and contact.
     */
    if (rsl == NULL)
    {
        rc = globus_gram_job_manager_import_sec_context(
            &manager,
            &context);
        if (rc != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "Error importing security context\n");
            exit(1);
        }

        rc = globus_gram_job_manager_read_request(
                &manager,
                &rsl,
                &contact,
                &job_state_mask);
        if (rc != GLOBUS_SUCCESS)
        {
            /* TODO: Send response */
            fprintf(stderr, "Error reading request\n");
            exit(1);
        }
    }

    if (globus_gram_job_manager_request_init(&request, &manager, rsl, context)
            != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
            "ERROR: globus_jobmanager_request_init() failed.\n");
        exit(1);
    }

    if (contact != NULL)
    {
        rc = globus_gram_job_manager_contact_add(
                request,
                contact,
                job_state_mask);
        /* TODO: send failure */
        assert(rc == GLOBUS_SUCCESS);
    }

    globus_mutex_lock(&request->mutex);

    GlobusTimeReltimeSet(delay, 0, 0);

    globus_callback_register_oneshot(
	    NULL,
	    &delay,
	    globus_gram_job_manager_state_machine_callback,
	    request);

    while(request->jobmanager_state != GLOBUS_GRAM_JOB_MANAGER_STATE_DONE &&
	  request->jobmanager_state != GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE && 
	  request->jobmanager_state != GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE)
    {
	globus_cond_wait(&request->cond, &request->mutex);
    }

    /* Write auditing file if job is DONE or FAILED */
    if (request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_DONE ||
	request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE)
    {
        if (globus_gram_job_manager_auditing_file_write(request) != GLOBUS_SUCCESS)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: Error writing audit record\n");
        }
    }

    /*
     * If we ran without a client, display final state and error if applicable
     */
    if(debugging_without_client)
    {
	fprintf(stderr,
		"Final Job Status: %d%s%s%s\n",
		request->status,
		(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
		? " (failed because " : "",
		(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
		    ? globus_gram_protocol_error_string(request->failure_code)
		    : "",
		(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
		    ? ")" : "");
    }
    else if((!request->relocated_proxy) &&
	    globus_gram_job_manager_gsi_used(request) &&
	    request->jobmanager_state != GLOBUS_GRAM_JOB_MANAGER_STATE_DONE &&
            (!debugging_without_client) &&
	    globus_libc_getenv("X509_USER_PROXY"))
    {
	remove(globus_libc_getenv("X509_USER_PROXY"));
    }
    globus_mutex_unlock(&request->mutex);
    rc = globus_module_deactivate_all();
    if (rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "deactivation failed with rc=%d\n",
		rc);
	exit(1);
    }

    {
	const char * gk_jm_id_var = "GATEKEEPER_JM_ID";
	const char * gk_jm_id = globus_libc_getenv(gk_jm_id_var);

	globus_gram_job_manager_request_acct(
		request,
		"%s %s JM exiting\n",
		gk_jm_id_var, gk_jm_id ? gk_jm_id : "none");
    }

    globus_gram_job_manager_request_log(
	    request,
	    "JM: exiting globus_gram_job_manager.\n");

    switch(request->config->logfile_flag)
    {
      case GLOBUS_GRAM_JOB_MANAGER_SAVE_ALWAYS:
	  break;
      case GLOBUS_GRAM_JOB_MANAGER_SAVE_ON_ERROR:
	if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE
	   && !request->dry_run)
	{
	    break;
	}
	/* FALLSTHROUGH */
      case GLOBUS_GRAM_JOB_MANAGER_DONT_SAVE:
	if (strcmp(manager.jobmanager_logfile, "/dev/null") != 0)
	{
	    /*
	     * Check to see if the jm log file exists.  If so, then
	     * delete it.
	     */
	    if (access(manager.jobmanager_logfile, F_OK) == 0)
	    {
		if (remove(manager.jobmanager_logfile) != 0)
		{
		    fprintf(stderr,
			    "failed to remove job manager log file = %s\n",
			    manager.jobmanager_logfile);
		}
	    }
	}
    }

    return(0);
}
/* main() */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Activate all globus modules used by the job manager
 *
 * Attempts to activate all of the modules used by the job manager. In the
 * case of an error, a diagnostic message is printed to stderr.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval all other
 *     A module failed to activate
 */
static
int
globus_l_gram_job_manager_activate(void)
{
    int rc;
    globus_module_descriptor_t *        modules[] =
    {
        GLOBUS_COMMON_MODULE,
        GLOBUS_CALLOUT_MODULE,
        GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR_MODULE,
        GLOBUS_GSI_GSS_ASSIST_MODULE,
        GLOBUS_GSI_SYSCONFIG_MODULE,
        GLOBUS_IO_MODULE,
        GLOBUS_GRAM_PROTOCOL_MODULE,
        GLOBUS_GASS_CACHE_MODULE,
        GLOBUS_GASS_TRANSFER_MODULE,
        GLOBUS_FTP_CLIENT_MODULE,
        NULL
    };
    globus_module_descriptor_t *        failed_module = NULL;

    rc = globus_module_activate_array(modules, &failed_module);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error (%d) activating %s\n", 
                rc, failed_module->module_name);
    }

    return rc;
}
/* globus_l_gram_job_manager_activate() */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
