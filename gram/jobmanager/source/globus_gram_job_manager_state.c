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
 * @file globus_gram_job_manager_state.c Job Manager State Machine
 *
 * CVS Information:
 * 
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#include "globus_gram_job_manager.h"
#include "globus_rsl_assist.h"
#include "globus_callout.h"
#include "globus_callout_constants.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_system_config_constants.h"
#include "globus_gram_jobmanager_callout_error.h"

#include <string.h>

#endif

/* Module Specific Prototypes */
static
int
globus_l_gram_job_manager_read_request(
    globus_gram_jobmanager_request_t *	request);

static
int
globus_l_gram_job_manager_set_unique_id(
    globus_gram_jobmanager_request_t *	request);

static
char *
globus_l_gram_job_manager_getenv(
    const char *			var,
    const char *			default_value);

static
globus_bool_t
globus_l_gram_job_manager_set_restart_state(
    globus_gram_jobmanager_request_t *	request);

static
int
globus_l_gram_job_manager_reply(
    globus_gram_jobmanager_request_t *	request);

static
void
globus_l_gram_job_manager_state_log_rsl(
    globus_gram_jobmanager_request_t *	request,
    const char *			label);

static
void
globus_l_gram_job_manager_cancel_queries(
    globus_gram_jobmanager_request_t *	request);

static
int
globus_l_gram_job_manager_validate_username(
    globus_gram_jobmanager_request_t *	request);

#ifdef BUILD_DEBUG

#   define GLOBUS_GRAM_JOB_MANAGER_INVALID_STATE(request) \
        globus_gram_job_manager_request_log(request, \
	                  "Invalid Job Manager State %s\n", \
			  globus_l_gram_job_manager_state_string(\
			      request->jobmanager_state));\
        globus_assert(0);

#   define GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, when) \
        globus_gram_job_manager_request_log(request, \
	                  "Job Manager State Machine (%s): %s\n", \
			  when, \
			  globus_l_gram_job_manager_state_string(\
			      request->jobmanager_state));
static
const char *
globus_l_gram_job_manager_state_string(
    globus_gram_jobmanager_state_t	state);
#else

#   define GLOBUS_GRAM_JOB_MANAGER_INVALID_STATE(request)
#   define GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, when)

#endif

/*
 * Callback to enter the state machine from a timeout. Used to
 * handle two-phase commit timeouts, and delays between calls to the
 * poll script.
 */
void
globus_gram_job_manager_state_machine_callback(
    void *				user_arg)
{
    globus_gram_jobmanager_request_t *	request;
    globus_bool_t			event_registered;

    request = user_arg;

    globus_mutex_lock(&request->mutex);

    /*
     * If nobody tried to cancel this callback, then we need to unregister
     * it to free memory in the callback code.
     */
    if(request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
    {
	globus_callback_unregister(request->poll_timer, NULL, NULL, NULL);
	request->poll_timer = GLOBUS_HANDLE_TABLE_NO_HANDLE;
    }
    
    do
    {
	event_registered = globus_gram_job_manager_state_machine(request);
    }
    while(!event_registered);
    globus_mutex_unlock(&request->mutex);
}
/* globus_gram_job_manager_state_machine_callback() */


/*
 * Job Manager state machine.
 */
globus_bool_t
globus_gram_job_manager_state_machine(
    globus_gram_jobmanager_request_t *	request)
{
    globus_bool_t			event_registered = GLOBUS_FALSE;
    globus_reltime_t			delay_time;
    int					rc = 0;
    int					save_status;
    int					save_jobmanager_state;
    char *				tmp_str;
    globus_result_t			result;
    globus_rsl_t *			original_rsl;
    globus_rsl_t *			restart_rsl;
    globus_gram_job_manager_query_t *	query;
    globus_bool_t			first_poll = GLOBUS_FALSE;
    globus_callout_handle_t             authz_handle;
    char *                              filename;
    globus_object_t *                   error;
    globus_gram_jobmanager_state_t      next_state;

    GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, "entering");

    switch(request->jobmanager_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
	/*
	 * Read some environment variables we are interested in, and
	 * create our log file
	 */
	request->home =
	    globus_l_gram_job_manager_getenv("HOME", NULL);

	if(request->home == NULL)
	{
	    fprintf(stderr, "ERROR: unable to get HOME from the environment\n");
	    request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED;
	    globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	    request->jobmanager_state =
	        GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
	    break;
	}
	globus_gram_job_manager_request_open_logfile(request,
		                                     request->logfile_flag);

	request->logname =
	    globus_l_gram_job_manager_getenv("LOGNAME", "noname");

	request->globus_id = 
	    globus_l_gram_job_manager_getenv("GLOBUS_ID", "unknown globusid");

	if(!request->globus_location)
	{
	    result = globus_location(&request->globus_location);
	    if(result != GLOBUS_SUCCESS)
	    {
		globus_gram_job_manager_request_log(
			request,
			"JM: globus_location failed\n");

		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED;
	        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
		break;
	    }
	    globus_gram_job_manager_request_log(
		    request,
		    "JM: GLOBUS_LOCATION = %s\n",
		    request->globus_location);
	}

	/*
	 * Make sure all of the required parameters where passed in on
	 * the command line or conf file.
	 */
	if(!request->jobmanager_type)
	{
	    globus_gram_job_manager_request_log( request,
              "JM: Jobmanager service misconfigured. "
              "jobmanager Type not defined.\n");

	    request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED;
	    globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	    request->jobmanager_state =
	        GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
	    break;
	}
	if(!request->rdn)
	{
	    globus_gram_job_manager_request_log( request,
            "JM: -rdn parameter required\n");

	    request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED;
	    globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	    request->jobmanager_state =
	        GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
	    break;
	}
	if(strcasecmp(request->jobmanager_type, "condor") == 0)
	{
	    if(request->condor_arch == NULL)
	    {
		globus_gram_job_manager_request_log( request,
		    "JMI: Condor_arch must be specified when "
		    "jobmanager type is condor\n");

		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_ARCH;
	        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
		break;
	    }
	    if(request->condor_os == NULL)
	    {
	       globus_gram_job_manager_request_log( request,
		    "JMI: Condor_os must be specified when "
		    "jobmanager type is condor\n");
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_ARCH;
	        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
	    }
	}
	rc = globus_gram_job_manager_validation_init(request);
	if(rc != GLOBUS_SUCCESS)
	{
           globus_gram_job_manager_request_log( request,
                "JMI: error initializing rsl validation.\n");
	    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}
	if(!request->rsl_spec)
	{
	    rc = globus_gram_job_manager_import_sec_context(request);
	    if(rc != GLOBUS_SUCCESS)
	    {
		request->failure_code = rc;
	        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
		break;
	    }
	}

	rc = globus_l_gram_job_manager_read_request(
		request);

	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code = rc;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}

	rc = globus_gram_protocol_allow_attach(
		&request->url_base,
		globus_gram_job_manager_query_callback,
		request);

	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code = rc;
	    request->jobmanager_state =
	        GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}

	globus_gram_job_manager_request_log(
		request,
		"Pre-parsed RSL string: %s\n",
		request->rsl_spec);

	request->rsl = globus_rsl_parse(request->rsl_spec);

	if(!request->rsl)
	{
	    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}

	globus_l_gram_job_manager_state_log_rsl(request, "Job Request RSL");

	/* Build symbol table for RSL evaluation */
	globus_symboltable_insert(&request->symbol_table,
                                (void *) "HOME",
                                (void *) request->home);

        if (request->logname)
	{
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "LOGNAME",
                                (void *) request->logname);
	}

        if (request->globus_id)
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_ID",
                                (void *) request->globus_id);
        if (request->rdn)
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_GRAM_RDN",
                                (void *) request->rdn);
        if (request->condor_os)
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_CONDOR_OS",
                                (void *) request->condor_os);
        if (request->condor_arch)
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_CONDOR_ARCH",
                                (void *) request->condor_arch);
        if (request->globus_location)
	{
            globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_LOCATION",
                                (void *) request->globus_location);
	}

	rc = globus_rsl_assist_attributes_canonicalize(request->rsl);
	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}

	globus_l_gram_job_manager_state_log_rsl(
		request,
		"Job Request RSL (canonical)");

	rc = globus_gram_job_manager_rsl_add_substitutions_to_symbol_table(
		request);
	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code = rc;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}
	
	if(globus_gram_job_manager_rsl_need_restart(request))
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "Job Request is a Job Restart\n");

	    /* Need to do this before unique id is set */
	    rc = globus_gram_job_manager_rsl_eval_one_attribute(
		    request,
		    GLOBUS_GRAM_PROTOCOL_RESTART_PARAM,
		    &request->jm_restart);

	    if(rc != GLOBUS_SUCCESS)
	    {
		request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    else if(request->jm_restart == NULL)
	    {
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_RSL_RESTART;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    globus_gram_job_manager_request_log(
		    request,
		    "Will try to restart job %s\n",
		    request->jm_restart);
	}

	/* This sets request->job_contact and request->uniq_id */
	rc = globus_l_gram_job_manager_set_unique_id(request);

	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code = rc;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}
        globus_symboltable_insert(&request->symbol_table,
                                (void *) "GLOBUS_GRAM_JOB_CONTACT",
                                (void *) request->job_contact);

        rc = globus_gram_job_manager_output_make_job_dir(request);

        if (rc != GLOBUS_SUCCESS)
        {
            request->failure_code = rc;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
        }

	if(request->scratch_dir_base)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "JM default scratch dir: %s\n",
		    request->scratch_dir_base);

	    rc = globus_gram_job_manager_rsl_eval_string(
		    request,
		    request->scratch_dir_base,
		    &tmp_str);

	    if(rc != GLOBUS_SUCCESS)
	    {
		request->failure_code = rc;
		request->jobmanager_state = 
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    globus_libc_free(request->scratch_dir_base);
	    request->scratch_dir_base = tmp_str;
	    globus_gram_job_manager_request_log(
		    request,
		    "JM default scratch dir (post-eval): %s\n",
		    request->scratch_dir_base);
	}
	else
	{
	    request->scratch_dir_base = globus_libc_strdup(request->home);
	}

	rc = globus_gram_job_manager_rsl_eval_one_attribute(
		request,
		GLOBUS_GRAM_PROTOCOL_GASS_CACHE_PARAM,
		&tmp_str);

	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code = rc;
	    request->jobmanager_state = 
	        GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}

	/* cache location in rsl, but not a literal after eval */
	if(tmp_str == GLOBUS_NULL &&
		!globus_list_empty(
		    globus_rsl_param_get_values(
			request->rsl,
			GLOBUS_GRAM_PROTOCOL_GASS_CACHE_PARAM)))
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "Poorly-formed RSL gass_cache attribute\n");

	    request->failure_code = 
		    GLOBUS_GRAM_PROTOCOL_ERROR_RSL_CACHE;
	    request->jobmanager_state = 
	        GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}
        if(tmp_str != NULL)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "Overriding system gass_cache location %s "
		    " with RSL-supplied %s\n",
		    request->cache_location
		        ? request->cache_location : "NULL",
		    tmp_str);
	    
	    if(request->cache_location != NULL)
	    {
		globus_libc_free(request->cache_location);
	    }
	    request->cache_location = tmp_str;
        }
	if(request->cache_location != NULL)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "gass_cache location: %s\n",
		    request->cache_location);

	    rc = globus_gram_job_manager_rsl_eval_string(
		    request,
		    request->cache_location,
		    &tmp_str);

	    if(rc != GLOBUS_SUCCESS)
	    {
		request->failure_code = rc;
		request->jobmanager_state = 
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    globus_libc_free(request->cache_location);
	    request->cache_location = tmp_str;
	    tmp_str = NULL;
	    globus_gram_job_manager_request_log(
		    request,
		    "gass_cache location (post-eval): %s\n",
		    request->cache_location);
	}

	rc = globus_gass_cache_open(request->cache_location,
		                    &request->cache_handle);
	if(rc != GLOBUS_SUCCESS)
	{
	    if(request->cache_location)
	    {
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_CACHE;
	    }
	    else
	    {
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE;
	    }
	    request->jobmanager_state = 
	        GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}
	if(request->cache_location)
	{
	    globus_libc_setenv(
		"GLOBUS_GASS_CACHE_DEFAULT",
		request->cache_location,
		GLOBUS_TRUE);
	}

	globus_gram_job_manager_reporting_file_set(request);
        globus_gram_job_manager_history_file_set(request);

	globus_libc_setenv("GLOBUS_GRAM_JOB_CONTACT",
		           request->job_contact,
			   1);

        rc = globus_gram_job_manager_output_get_cache_name(
            request,
            "stdout",
            &tmp_str);
        if (rc != GLOBUS_SUCCESS)
        {
            request->failure_code = rc;
	    request->jobmanager_state = 
	        GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;

            break;
        }
	globus_symboltable_insert(
		&request->symbol_table,
		"GLOBUS_CACHED_STDOUT",
                tmp_str);

        rc = globus_gram_job_manager_output_get_cache_name(
		    request,
		    "stderr",
                    &tmp_str);
        if (rc != GLOBUS_SUCCESS)
        {
            request->failure_code = rc;
	    request->jobmanager_state = 
	        GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;

            break;
        }
	globus_symboltable_insert(
		&request->symbol_table,
		"GLOBUS_CACHED_STDERR",
                tmp_str);

	if(request->jm_restart)
	{
	    globus_l_gram_job_manager_state_log_rsl(
		    request,
		    "Restart RSL");

	    rc = globus_rsl_eval(request->rsl, &request->symbol_table);
	    if(rc != GLOBUS_SUCCESS)
	    {
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    globus_l_gram_job_manager_state_log_rsl(
		    request,
		    "Restart RSL (post-eval)");

	    rc = globus_gram_job_manager_validate_rsl(
		    request,
		    GLOBUS_GRAM_VALIDATE_JOB_MANAGER_RESTART);
	    if(rc != GLOBUS_SUCCESS)
	    {
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->failure_code = rc;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    globus_l_gram_job_manager_state_log_rsl(
		    request,
		    "Restart RSL (post-validate)");
	    /*
	     * Eval after validating, as validation may insert
	     * RSL substitions when processing default values of
	     * RSL attributes
	     */
	    rc = globus_rsl_eval(request->rsl, &request->symbol_table);
	    if(rc != GLOBUS_SUCCESS)
	    {
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    globus_l_gram_job_manager_state_log_rsl(
		    request,
		    "Restart RSL (post-validate-eval)");

	    /* Free the restart RSL spec. Make room for the job
	     * request RSL which we'll read from the state file
	     */
	    globus_libc_free(request->rsl_spec);
	    request->rsl_spec = NULL;

	    /* Remove the restart parameter from the RSL spec. */
	    globus_gram_job_manager_rsl_remove_attribute(
		    request,
		    GLOBUS_GRAM_PROTOCOL_RESTART_PARAM);

	    /* is this still necessary? */
	    globus_gram_job_manager_reporting_file_set(request);
	    /* globus_gram_job_manager_history_file_set(request); */
	    globus_gram_job_manager_state_file_set(request);

	    /* Attempt to read the job state file */
	    rc = globus_gram_job_manager_state_file_read(request);
	    if(rc != GLOBUS_SUCCESS)
	    {
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->failure_code = rc;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }

	    rc = globus_rsl_assist_attributes_canonicalize(request->rsl);
	    if(rc != GLOBUS_SUCCESS)
	    {
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }

	    globus_gram_job_manager_request_log(
		request,
		"Pre-parsed Original RSL string: %s\n",
		request->rsl_spec);

	    original_rsl = globus_rsl_parse(request->rsl_spec);
	    if(!original_rsl)
	    {
		request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    tmp_str = globus_rsl_unparse(original_rsl);

	    if(tmp_str)
	    {
		globus_gram_job_manager_request_log(
			request,
			"<<<<<original Job RSL\n%s\n"
			">>>>>original Job RSL\n",
			tmp_str);
		globus_libc_free(tmp_str);
		tmp_str = NULL;
	    }
	    restart_rsl = request->rsl;

	    request->rsl = original_rsl;
	    rc = globus_rsl_assist_attributes_canonicalize(request->rsl);
	    if(rc != GLOBUS_SUCCESS)
	    {
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    globus_l_gram_job_manager_state_log_rsl(
		    request,
		    "Original Job RSL (canonical)");

	    /* Remove the two-phase commit from the original RSL; if the
	     * new client wants it, they can put it in their RSL
	     */
	    globus_gram_job_manager_rsl_remove_attribute(
			request,
			GLOBUS_GRAM_PROTOCOL_TWO_PHASE_COMMIT_PARAM);

            /*
             * Remove stdout_position and stderr_position before merging.
             * They aren't valid for job submission RSLs, but are for
             * restart RSLs. They will be reinserted after validation.
             */
            request->stdout_position_hack =
                globus_gram_job_manager_rsl_extract_relation(
                    restart_rsl,
                    GLOBUS_GRAM_PROTOCOL_STDOUT_POSITION_PARAM);

            request->stderr_position_hack = 
                globus_gram_job_manager_rsl_extract_relation(
                    restart_rsl,
                    GLOBUS_GRAM_PROTOCOL_STDERR_POSITION_PARAM);

	    request->rsl = globus_gram_job_manager_rsl_merge(
			original_rsl,
			restart_rsl);

	    if(request->rsl == NULL)
	    {
		request->failure_code = rc;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    globus_l_gram_job_manager_state_log_rsl(
		    request,
		    "Merged Job RSL");
	}

        /* call authz callout here */

        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_SYSTEM_FAILURE;

            
        result = GLOBUS_GSI_SYSCONFIG_GET_AUTHZ_CONF_FILENAME(&filename);
        
        if(result != GLOBUS_SUCCESS)
        {
            error = globus_error_get(result);
            
            if(globus_error_match(
                   error,
                   GLOBUS_GSI_SYSCONFIG_MODULE,
                   GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_AUTHZ_FILENAME)
               == GLOBUS_TRUE)
            {
                globus_object_free(error);
            }
            else
            {
                globus_object_free(error);
                request->failure_code = rc;
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
                break;
            }
        }
        else
        {
            
            result = globus_callout_handle_init(&authz_handle);
            
            if(result != GLOBUS_SUCCESS)
            {
                free(filename);
                request->failure_code = rc;
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
                break;                
            }
            
            result = globus_callout_read_config(authz_handle, filename);

            free(filename);
            
            if(result != GLOBUS_SUCCESS)
            {
                globus_callout_handle_destroy(authz_handle);
                request->failure_code = rc;
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
                break;                
            }
            
            result = globus_callout_call_type(authz_handle,
                                              GLOBUS_GRAM_AUTHZ_CALLOUT_TYPE,
                                              request->response_context,
                                              request->response_context,
                                              request->uniq_id,
                                              request->rsl,
                                              "start");
            globus_callout_handle_destroy(authz_handle);
            
            if(result != GLOBUS_SUCCESS)
            {
                error = globus_error_get(result);
                
                if(globus_error_match(
                       error,
                       GLOBUS_CALLOUT_MODULE,
                       GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED)
                   == GLOBUS_TRUE)
                {
                    globus_object_free(error);
                }
                else
                { 
                    if(globus_error_match(
                           error,
                           GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR_MODULE,
                           GLOBUS_GRAM_JOBMANAGER_CALLOUT_AUTHZ_DENIED)
                       == GLOBUS_TRUE)
                    {
                        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED;
                    }
                    else if(globus_error_match(
                                error,
                                GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR_MODULE,
                                GLOBUS_GRAM_JOBMANAGER_CALLOUT_AUTHZ_DENIED_INVALID_JOB)
                            == GLOBUS_TRUE)
                    {
                        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED_JOB_ID;
                    }
                    else if(globus_error_match(
                                error,
                                GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR_MODULE,
                                GLOBUS_GRAM_JOBMANAGER_CALLOUT_AUTHZ_DENIED_BAD_EXECUTABLE)
                            == GLOBUS_TRUE)
                    {
                        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED_EXECUTABLE;
                    }

                    /* rc already contains default error */

                    globus_object_free(error);
                    request->failure_code = rc;
                    request->jobmanager_state =
                        GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
                    break;
                }
            }
        }

	/* GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_MAKE_SCRATCHDIR used to be here */
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_MAKE_SCRATCHDIR;

	/* Add job manager-generated environment strings. This
	 * must be done after a RESTART rsl is validated
	 */
	if(request->cache_location)
	{
	    globus_gram_job_manager_rsl_env_add(
		request->rsl,
		"GLOBUS_GASS_CACHE_DEFAULT",
		request->cache_location);
	}
	if(request->logname)
	{
	    globus_gram_job_manager_rsl_env_add(
		request->rsl,
		"LOGNAME",
		request->logname);
	}
	globus_gram_job_manager_rsl_env_add(
	    request->rsl,
	    "HOME",
	    request->home);

        if (request->extra_envvars)
        {
            char *  p = request->extra_envvars;
            while (p && *p)
            {
                char * val = GLOBUS_NULL;
                char * q   = strchr(p,',');
                if (q) *q = '\0';
                if (*p && (val = globus_libc_getenv(p)))
                {
                    globus_gram_job_manager_request_log(
                        request,
                        "Appending extra env.var %s=%s\n",
                        p,
                        val);
                    globus_gram_job_manager_rsl_env_add(
                        request->rsl,
                        p,
                        val);
                }
                p = (q) ? q+1 : GLOBUS_NULL;
            }
        }

        rc = globus_l_gram_job_manager_validate_username(
                request);
        if (rc != 0)
        {
            request->failure_code = rc;
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
            break;
        }

	globus_gram_job_manager_reporting_file_start_cleaner(request);

	if(globus_gram_job_manager_rsl_need_scratchdir(request) &&
		!request->scratchdir)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "Evaluating scratch directory RSL\n");
	    rc = globus_gram_job_manager_rsl_eval_one_attribute(
		    request,
		    GLOBUS_GRAM_PROTOCOL_SCRATCHDIR_PARAM,
		    &tmp_str);
	    if(rc != GLOBUS_SUCCESS)
	    {
		globus_gram_job_manager_request_log(
			request,
			"Evaluation of scratch directory RSL failed\n");
		request->failure_code = rc;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    else if(tmp_str == GLOBUS_NULL)
	    {
		globus_gram_job_manager_request_log(
			request,
			"Evaluation of scratch directory RSL didn't "
			"yield string\n");
		/* scratch_dir did not evaluate to a string */
		request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SCRATCH;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		break;
	    }
	    globus_gram_job_manager_request_log(
		    request,
		    "Scratch Directory RSL -> %s\n",
		    tmp_str);

	    rc = globus_gram_job_manager_script_make_scratchdir(
		    request,
		    tmp_str);

	    globus_libc_free(tmp_str);

	    if(rc != GLOBUS_SUCCESS)
	    {
		request->failure_code = rc;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    }
	    else
	    {
		event_registered = GLOBUS_TRUE;
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_MAKE_SCRATCHDIR:
	if(request->scratchdir)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "Adding scratch dir to symbol table and env: %s\n",
		    request->scratchdir);

	    globus_symboltable_insert(
		&request->symbol_table,
		"SCRATCH_DIRECTORY",
		request->scratchdir);
	    globus_gram_job_manager_rsl_env_add(
		request->rsl,
		"SCRATCH_DIRECTORY",
		request->scratchdir);
	}
	else if(globus_gram_job_manager_rsl_need_scratchdir(request))
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "Failed to create scratch dir\n");
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	    if(request->failure_code == GLOBUS_SUCCESS)
	    {
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRATCH;
	    }
	    break;
	}

	globus_l_gram_job_manager_state_log_rsl(
		request,
		"Job RSL");

	rc = globus_rsl_eval(request->rsl, &request->symbol_table);
	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}
	globus_l_gram_job_manager_state_log_rsl(
		request,
		"Job RSL (post-eval)");

	rc = globus_gram_job_manager_validate_rsl(
		request,
		GLOBUS_GRAM_VALIDATE_JOB_SUBMIT);
	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code = rc;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}
	globus_l_gram_job_manager_state_log_rsl(
		request,
		"Job RSL (post-validation)");

        /*
         * Insert stdout_position and stderr_position back to rsl if they were
         * present in restart RSL
         */
        if(request->stdout_position_hack != NULL)
        {
            globus_gram_job_manager_rsl_add_relation(
                request->rsl,
                request->stdout_position_hack);
            request->stdout_position_hack = NULL;
        }
        if(request->stderr_position_hack != NULL)
        {
            globus_gram_job_manager_rsl_add_relation(
                request->rsl,
                request->stderr_position_hack);
            request->stderr_position_hack = NULL;
        }

	rc = globus_rsl_eval(request->rsl, &request->symbol_table);
	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}
	globus_l_gram_job_manager_state_log_rsl(
		request,
		"Job RSL (post-validation-eval)");

	if(!request->jm_restart)
	{
	    request->cache_tag = globus_libc_strdup(request->job_contact);
	}

	rc = globus_gram_job_manager_rsl_request_fill(request);
	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code = rc;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    break;
	}
	
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_REMOTE_IO_FILE_CREATE;

	if(request->remote_io_url)
	{
	    rc = globus_gram_job_manager_script_remote_io_file_create(request);

	    if(rc == GLOBUS_SUCCESS)
	    {
		event_registered = GLOBUS_TRUE;
	    }
	    else
	    {
		request->failure_code = rc;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_REMOTE_IO_FILE_CREATE:
	if(request->remote_io_url != NULL &&
	   request->remote_io_url_file == NULL)
	{
	    request->jobmanager_state = 
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	    if(request->failure_code == GLOBUS_SUCCESS)
	    {
		request->failure_code = 
		    GLOBUS_GRAM_PROTOCOL_ERROR_RSL_REMOTE_IO_URL;
	    }
	    break;
	}
	/*
	 * Append some values from the configuration file to the
	 * job's environment
	 */
	if(request->x509_cert_dir != NULL)
	{
	    globus_gram_job_manager_rsl_env_add(
		request->rsl,
		"X509_CERT_DIR",
		request->x509_cert_dir);
	}

	if(request->job_contact)
	{
	    globus_gram_job_manager_rsl_env_add(
		request->rsl,
		"GLOBUS_GRAM_JOB_CONTACT",
		request->job_contact);
	}

	if(request->globus_location)
	{
	    globus_gram_job_manager_rsl_env_add(
		request->rsl,
		"GLOBUS_LOCATION",
		request->globus_location);
	}

	if(request->tcp_port_range)
	{
	    globus_gram_job_manager_rsl_env_add(
		request->rsl,
		"GLOBUS_TCP_PORT_RANGE",
		request->tcp_port_range);
	}
	if(request->remote_io_url_file)
	{
	    globus_gram_job_manager_rsl_env_add(
		request->rsl,
		"GLOBUS_REMOTE_IO_URL",
		request->remote_io_url_file);
	}

	/* Determine local cache file names */
	request->local_stdout =
	    globus_gram_job_manager_output_local_name(
	        request,
		GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM);
	request->local_stderr =
	    globus_gram_job_manager_output_local_name(
		request,
		GLOBUS_GRAM_PROTOCOL_STDERR_PARAM);

	if (request->local_stdout == GLOBUS_NULL)
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_STDOUT_FILENAME_FAILED;
	}
	else if (request->local_stderr == GLOBUS_NULL)
	{
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_STDERR_FILENAME_FAILED;
	}
	else
	{
	    /* Open output destinations */
	    rc = globus_gram_job_manager_output_open(request);
	}
	if(rc == GLOBUS_SUCCESS)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT;
	    event_registered = GLOBUS_TRUE;
	}
	else
	{
	    request->jobmanager_state = 
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	    request->failure_code = rc;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT:
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_RELOCATE;

	tmp_str = globus_libc_getenv("X509_USER_PROXY");

	/* Try to relocate proxy if we aren't using kerberos or we
	 * weren't started with -rsl option
	 */
        if((!request->kerberos) &&
	    globus_gram_job_manager_gsi_used(request) &&
	    (request->response_context != GSS_C_NO_CONTEXT))
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "JM: GSSAPI type is GSI.. relocating proxy\n");

            rc = globus_gram_job_manager_gsi_relocate_proxy(
                    request,
                    globus_libc_strdup(tmp_str));
 
            if(rc != GLOBUS_SUCCESS)
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
                request->failure_code = rc;
                break;
            }
 
            request->relocated_proxy = GLOBUS_TRUE;

	    rc = globus_gram_job_manager_script_proxy_relocate(request);

	    if(rc == GLOBUS_SUCCESS)
	    {
		event_registered = GLOBUS_TRUE;
	    }
	    else
	    {
		request->jobmanager_state = 
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		request->failure_code = rc;
	    }
	}
	else if(request->response_context == GSS_C_NO_CONTEXT)
	{
	    /* pretend we relocated the proxy, so that it won't be
	     * deleted in the -rsl startup case
	     */
	    request->relocated_proxy = GLOBUS_TRUE;
	}
	break;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_RELOCATE:
	if((!request->kerberos) && globus_gram_job_manager_gsi_used(request))
	{
	    if((!request->x509_user_proxy) &&
		    request->response_context != GSS_C_NO_CONTEXT)
	    {
		/* failed to relocated proxy for job */
		request->jobmanager_state = 
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		if(request->failure_code == GLOBUS_SUCCESS)
		{
		    request->failure_code =
			GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_REPLY;
		}
		break;
	    }

	    request->relocated_proxy = GLOBUS_TRUE;

	    if(request->x509_user_proxy)
	    {
		/*
		 * The proxy timeout callback is registered to happen
		 * shortly (5 minutes) before the job manager's proxy will
		 * expire. We do this to save state and exit the job manager
		 * so another can be restarted in it's place.
		 */
		globus_gram_job_manager_request_log(request,
				      "JM: Relocated Proxy to %s\n",
				      request->x509_user_proxy);
		globus_libc_setenv("X509_USER_PROXY",
				   request->x509_user_proxy,
				   GLOBUS_TRUE);

		globus_gram_job_manager_rsl_env_add(
		    request->rsl,
		    "X509_USER_PROXY",
		    request->x509_user_proxy);
		rc = globus_gram_job_manager_gsi_register_proxy_timeout(
			request);
		if (rc != GLOBUS_SUCCESS)
		{
		    request->jobmanager_state = 
			GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
		    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
		    globus_gram_job_manager_request_log( request,
				   "JM: error setting proxy timeout--"
                                   "proxy too short-lived\n");
		    break;
		}
	    }
	}

	if(request->save_state && !request->jm_restart)
	{
	    if (rc == GLOBUS_SUCCESS && request->save_state == GLOBUS_TRUE)
	    {
		if ( request->job_state_file == NULL )
		{
		    globus_gram_job_manager_state_file_set(request);
		}

		rc = globus_gram_job_manager_state_file_write(request);

		if (rc != GLOBUS_SUCCESS)
		{
		    request->jobmanager_state = 
			GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
                    globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		    request->failure_code =
			GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_STATE_FILE;
		    globus_gram_job_manager_request_log( request,
				   "JM: error writing the state file\n");
		    break;
		}
	    }
	}

	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE;

	/*
	 * To do a two-phase commit, we need to send an error
	 * message (WAITING_FOR_COMMIT) in the initial reply; otherwise,
	 * we just return the current status code.
         * 
	 * When doing a dry run, we don't send the reply until we would
	 * submit the job (no state callbacks with a dry-run.)
	 */
	if(!request->dry_run)
	{
	    rc = globus_l_gram_job_manager_reply(request);

	    if(request->two_phase_commit != 0 && rc == GLOBUS_SUCCESS)
	    {
		GlobusTimeReltimeSet(delay_time,
		                     request->two_phase_commit,
				     0);

		globus_callback_register_oneshot(
			&request->poll_timer,
			&delay_time,
			globus_gram_job_manager_state_machine_callback,
			request);

		event_registered = GLOBUS_TRUE;
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
	if(request->two_phase_commit != 0 && request->commit_extend != 0)
	{
	    GlobusTimeReltimeSet(delay_time,
				 request->commit_extend,
				 0);

	    globus_callback_register_oneshot(
			&request->poll_timer,
			&delay_time,
			globus_gram_job_manager_state_machine_callback,
			request);

	    request->commit_extend = 0;

	    event_registered = GLOBUS_TRUE;
	}
	else if(request->two_phase_commit == 0)
	{
	    /* Nothing to do here if we are not doing the two-phase
	     * commit protocol
	     */
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED;
	}
	else if(request->jm_restart)
	{
            /*
             * commit didn't happen, but this was a restart of a job manager
             * so we'll just stop and leave the job manager state.
             */
	    request->poll_timer = GLOBUS_HANDLE_TABLE_NO_HANDLE;
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
	}
	else
	{
	    request->poll_timer = GLOBUS_HANDLE_TABLE_NO_HANDLE;
            /* Send failed message later */
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_COMMIT_TIMED_OUT;
            request->unsent_status_change = GLOBUS_TRUE;
            /* Don't do two-phase commit after sending FAILED state change */
            request->two_phase_commit = 0;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
	if(request->jm_restart)
	{
	    if(globus_l_gram_job_manager_set_restart_state(request))
	    {
		break;
	    }
	}
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN;

	if(globus_gram_job_manager_rsl_need_stage_in(request))
	{
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN);

	    if(!request->dry_run)
	    {
		globus_gram_job_manager_contact_state_callback(request);
	    }

	    rc = globus_gram_job_manager_script_stage_in(request);

	    if(rc != GLOBUS_SUCCESS)
	    {
		request->failure_code = rc;
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    }
	    else
	    {
		event_registered = GLOBUS_TRUE;
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN:
	if((!globus_list_empty(request->stage_in_todo)) ||
           (!globus_list_empty(request->stage_in_shared_todo)))
	{
	    /* Didn't successfully stage in everything. */
	    request->jobmanager_state = 
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    if(request->failure_code == GLOBUS_SUCCESS)
	    {
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_IN_FAILED;
	    }
	    break;
	}
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT;

	if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED && 
	   request->dry_run)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;

	    globus_l_gram_job_manager_reply(request);
	    break;
	}
	else if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
	{
	    request->jobmanager_state = 
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    break;
	}

        request->seg_last_timestamp = time(NULL);

	rc = globus_gram_job_manager_script_submit(request);

	if(rc != GLOBUS_SUCCESS)
	{
	    request->failure_code = rc;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);

	    if(!request->dry_run)
	    {
		request->jobmanager_state = 
			GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
		request->unsent_status_change = GLOBUS_TRUE;
	    }
	}
	else
	{
	    event_registered = GLOBUS_TRUE;
	}

	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
	if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED && 
	   request->dry_run)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;

	    globus_l_gram_job_manager_reply(request);
	    break;
	}
	else if(request->job_id == NULL)
	{
	    /* submission failed to generate a job id */
	    if(request->failure_code == GLOBUS_SUCCESS)
	    {
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_SUBMIT_UNKNOWN;
	    }
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
            request->unsent_status_change = GLOBUS_TRUE;
	}
        request->queued_time = time(NULL);
	globus_gram_job_manager_reporting_file_create(request);
        globus_gram_job_manager_history_file_create(request);
	request->job_history_status = request->status;

	if(request->save_state)
	{
	    globus_gram_job_manager_state_file_write(request);
	}
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
	first_poll = GLOBUS_TRUE;
	
	/* FALLSTHROUGH so we can act on a job state change returned from
	 * the submit script.
	 */
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
        if (! globus_fifo_empty(&request->seg_event_queue))
        {
            /* A SEG event occurred recently. Let's update our job state
             */
            globus_gram_job_manager_seg_handle_event(request);

        }
	if(request->unsent_status_change && request->save_state)
	{
	    globus_gram_job_manager_state_file_write(request);
	    globus_gram_job_manager_reporting_file_create(request);
	}

	/* The request->job_history_status is used to save the last job status
	 * that is stored in history file. If it is different with
	 * request->status, we have to write history file.
	 */ 
        if(request->unsent_status_change &&
		(request->job_history_status != request->status))
        {
	    globus_gram_job_manager_history_file_create(request);
            request->job_history_status = request->status;
	}

	if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	}
	else if(request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
	{
	    /* Job finished! start finalizing */
	    if(globus_gram_job_manager_rsl_need_stage_out(request))
	    {
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_OUT);
		globus_gram_job_manager_contact_state_callback(request);
	    }
	    request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT;
	    break;
	}
	else
	{
	    /* Send job state callbacks if necessary */
	    if(request->unsent_status_change)
	    {
		globus_gram_job_manager_contact_state_callback(request);
		request->unsent_status_change = GLOBUS_FALSE;
	    }

	    if(!globus_fifo_empty(&request->pending_queries))
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1;
		break;
	    }
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;

            if (request->seg_module != NULL && !request->seg_started)
            {
                /* We want to use the SEG, so we'll start that up. We won't
                 * have to reregister the callback after each event in this
                 * case.
                 */
                rc = globus_gram_job_manager_init_seg(request);

                if (rc != GLOBUS_SUCCESS)
                {
                    /* Error starting the SEG. Fallback to non-SEG mode */
                    request->seg_module = NULL;
                }
                else
                {
                    /* SEG was now started. When an event arrives, it will
                     * be enqueued and then state will change to POLL1
                     */
                    event_registered = GLOBUS_TRUE;
                }
            }
            else if(! first_poll)
	    {
		/* Register next poll of job state */
                if (request->seg_module == NULL)
                {
                    GlobusTimeReltimeSet(
                            delay_time,
                            request->poll_frequency, 0);

                    globus_callback_register_oneshot(
                            &request->poll_timer,
                            &delay_time,
                            globus_gram_job_manager_state_machine_callback,
                            request);
                    event_registered = GLOBUS_TRUE;
                }
                else
                {
                    /* SEG has been started. If there is an event pending,
                     * we should jump to POLL1 state and not set
                     * event_registered, so that we can process it.
                     *
                     * Otherwise, we'll set event_registered and the next
                     * query or SEG event will move the state machine.
                     */
                    if (! globus_fifo_empty(&request->seg_event_queue))
                    {

                        request->jobmanager_state =
                            GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
                    }
                    else
                    {
                        event_registered = GLOBUS_TRUE;
                    }
                }

	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
	/* timer expired since last poll. start polling again. */

        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;

        if (request->seg_module == NULL)
        {
            rc = globus_gram_job_manager_script_poll(request);
        }
        else if (!globus_fifo_empty(&request->seg_event_queue))
        {
            /* We don't want to set event_registered in this case, because
             * we want to immediately process the event in the queue.
             */
            break;
        }

        if(rc != GLOBUS_SUCCESS)
        {
            globus_gram_job_manager_request_log(
                request,
                "Error polling job... resources temporarily depleted?\n");
        }
        else
        {
            event_registered = GLOBUS_TRUE;
        }
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1:
        if (request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1)
        {
            next_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2;
        }
        else
        {
            next_state = GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2;
        }

	/*
	 * timer cancelled since last poll, because we may have some
	 * queries to process
	 */
	query = globus_fifo_peek(&request->pending_queries);

	if(query->type == GLOBUS_GRAM_JOB_MANAGER_SIGNAL &&
	   query->signal == GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_UPDATE)
	{
	    globus_gram_job_manager_request_log(
		request,
		"Parsing query RSL: %s\n",
		query->signal_arg);

	    query->rsl = globus_rsl_parse(query->signal_arg);
	    if(!query->rsl)
	    {
		query->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
	        request->jobmanager_state = next_state;
		break;
	    }
	    rc = globus_rsl_assist_attributes_canonicalize(query->rsl);
	    if(rc != GLOBUS_SUCCESS)
	    {
		query->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
	        request->jobmanager_state = next_state;
		break;
	    }
	    original_rsl = request->rsl;
	    request->rsl = query->rsl;
	    rc = globus_gram_job_manager_validate_rsl(
		    request,
		    GLOBUS_GRAM_VALIDATE_STDIO_UPDATE);
	    if(rc != GLOBUS_SUCCESS)
	    {
		query->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
	        request->jobmanager_state = next_state;
		request->rsl = original_rsl;
		break;
	    }
	    rc = globus_rsl_eval(request->rsl, &request->symbol_table);
	    if(rc != GLOBUS_SUCCESS)
	    {
		query->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
	        request->jobmanager_state = next_state;
		request->rsl = original_rsl;
		break;
	    }

	    request->rsl = globus_gram_job_manager_rsl_merge(
		original_rsl,
		query->rsl);

	    if(request->rsl == GLOBUS_NULL)
	    {
		request->rsl = original_rsl;
		query->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
	        request->jobmanager_state = next_state;
		break;
	    }

            if (next_state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2)
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_CLOSE;

                rc = globus_gram_job_manager_output_close(request);
                if(rc == GLOBUS_SUCCESS)
                {
                    event_registered = GLOBUS_TRUE;
                }
            }
            else
            {
                /* When STDIO_UPDATE occurs before commit, we don't need
                 * to open/close any files
                 */
	        request->jobmanager_state = next_state;
            }
	    break;
	}
	else if(query->type == GLOBUS_GRAM_JOB_MANAGER_SIGNAL)
	{
	    rc = globus_gram_job_manager_script_signal(
		    request,
		    query);
	}
	else if(query->type == GLOBUS_GRAM_JOB_MANAGER_CANCEL)
	{
	    rc = globus_gram_job_manager_script_cancel(
		    request,
		    query);
	}
	else if(query->type == GLOBUS_GRAM_JOB_MANAGER_PROXY_REFRESH)
	{
            if (request->jobmanager_state ==
                    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1)
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH;
            }
            else
            {
                request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH;
            }
	    rc = globus_gram_protocol_accept_delegation(
		    query->handle,
		    GSS_C_NO_OID_SET,
		    GSS_C_NO_BUFFER_SET,
		    GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG |
		        GSS_C_GLOBUS_SSL_COMPATIBLE,
		    0,
		    globus_gram_job_manager_query_delegation_callback,
		    request);

	    if(rc == GLOBUS_SUCCESS)
	    {
		event_registered = GLOBUS_TRUE;
	    }
	    break;
	}
	if(rc == GLOBUS_SUCCESS)
	{
	    request->jobmanager_state = next_state;

	    event_registered = GLOBUS_TRUE;
	}
	else
	{
	    globus_fifo_dequeue(&request->pending_queries);
	    query->failure_code = rc;

	    globus_gram_job_manager_query_reply(request, query);

	    if(globus_fifo_empty(&request->pending_queries))
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2:
	query = globus_fifo_dequeue(&request->pending_queries);

	/* Frees the query */
	globus_gram_job_manager_query_reply(
		request,
		query);

	if(globus_fifo_empty(&request->pending_queries))
	{
            GlobusTimeReltimeSet(delay_time,
                                 request->two_phase_commit,
                                 0);

            globus_callback_register_oneshot(
                    &request->poll_timer,
                    &delay_time,
                    globus_gram_job_manager_state_machine_callback,
                    request);

            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE;

            event_registered = GLOBUS_TRUE;
	}
        else
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1;
        }
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
	query = globus_fifo_dequeue(&request->pending_queries);

	/* Frees the query */
	globus_gram_job_manager_query_reply(
		request,
		query);

	if(globus_fifo_empty(&request->pending_queries) &&
	   (request->unsent_status_change ||
            !globus_fifo_empty(&request->seg_event_queue)))
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
	}
	else if(globus_fifo_empty(&request->pending_queries))
	{
	    request->jobmanager_state = 
		GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2;
	}
	else
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1;
	}
	break;
    
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH:
	query = globus_fifo_peek(&request->pending_queries);

	globus_assert(query->type == GLOBUS_GRAM_JOB_MANAGER_PROXY_REFRESH);

        if (request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH)
        {
            request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2;
        }
        else if (request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH)
        {
            request->jobmanager_state =
                    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2;
        }

	if(query->delegated_credential != GSS_C_NO_CREDENTIAL)
	{
	    /*
	     * We got a new credential... update our listener and
	     * store it on disk
	     */
	    rc = globus_gram_job_manager_gsi_update_credential(
		    request,
		    query->delegated_credential);
	    if(rc != GLOBUS_SUCCESS)
	    {
		break;
	    }

	    rc = globus_gram_job_manager_gsi_update_proxy_timeout(
		    request,
		    query->delegated_credential);

	    if(rc != GLOBUS_SUCCESS)
	    {
		break;
	    }

	    /* Update the proxy on the job execution hosts, if applicable.
	     * Perhaps signal the job that a new proxy is available.
	     */
	    rc = globus_gram_job_manager_script_proxy_update(
		    request,
		    query);
	    if(rc == GLOBUS_SUCCESS)
	    {
		query->failure_code = rc;

		event_registered = GLOBUS_TRUE;
	    }
	}
	else
	{
	    query->failure_code =
		GLOBUS_GRAM_PROTOCOL_ERROR_DELEGATION_FAILED;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_CLOSE:
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN;
	rc = globus_gram_job_manager_rsl_request_fill(request);
	if(rc != GLOBUS_SUCCESS)
	{
	    query->failure_code = rc;
	    break;
	}
	rc = globus_gram_job_manager_output_open(request);
	if(rc == GLOBUS_SUCCESS)
	{
	    event_registered = GLOBUS_TRUE;
	}
	else
	{
	    query->failure_code = rc;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN:
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2;
	if(request->remote_io_url)
	{
	    query->failure_code =
                globus_gram_job_manager_script_remote_io_file_create(request);

            if (query->failure_code == GLOBUS_SUCCESS)
            {
		event_registered = GLOBUS_TRUE;
	    }
        }
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED:
	if(request->unsent_status_change && request->save_state)
	{
	    globus_gram_job_manager_state_file_write(request);
	}
	if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT;
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CLOSE_OUTPUT;
	}
	else
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT;
	}
	save_status = request->status;
	save_jobmanager_state = request->jobmanager_state;

        /* Reply to any outstanding queries */
	while (!globus_fifo_empty(&request->pending_queries))
	{
            query = globus_fifo_dequeue(&request->pending_queries);

	    query->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
            /* Frees the query */
            globus_gram_job_manager_query_reply(
                    request,
                    query);
	}

	rc = globus_gram_job_manager_output_close(request);

	if(rc == GLOBUS_SUCCESS)
	{
	    event_registered = GLOBUS_TRUE;
	}
	else
	{
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	    request->failure_code = rc;

	    if(request->jobmanager_state ==
		    GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT)
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT;
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE:
	if(request->two_phase_commit != 0 && request->commit_extend != 0)
	{
	    GlobusTimeReltimeSet(delay_time,
				 request->commit_extend,
				 0);

	    globus_callback_register_oneshot(
			&request->poll_timer,
			&delay_time,
			globus_gram_job_manager_state_machine_callback,
			request);

	    request->commit_extend = 0;

	    event_registered = GLOBUS_TRUE;
	}
	else if(request->two_phase_commit == 0)
	{
	    /* Nothing to do here if we are not doing the two-phase
	     * commit protocol
	     */
            if(request->jobmanager_state ==
		    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END)
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED;
	    }
	    else
	    {
		request->jobmanager_state =
		  GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;
	    }
	}
	else if(request->save_state)
	{
	    request->jobmanager_state = 
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE;
            globus_l_gram_job_manager_cancel_queries(request);
	    globus_cond_signal(&request->cond);
	    globus_gram_job_manager_reporting_file_stop_cleaner(request);
            globus_gram_job_manager_reporting_file_remove(request);
	    event_registered = GLOBUS_TRUE;
	}
	else
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_PRE_FILE_CLEAN_UP:
	if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP;
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_PRE_FILE_CLEAN_UP)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_FILE_CLEAN_UP;
	}
	else
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP;
	}
	if(globus_gram_job_manager_rsl_need_file_cleanup(request))
	{
	    rc = globus_gram_job_manager_script_file_cleanup(request);

	    if(rc == GLOBUS_SUCCESS)
	    {
		event_registered = GLOBUS_TRUE;
	    }
	    else
	    {
		request->failure_code = rc;
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);

		if(request->jobmanager_state !=
			GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_FILE_CLEAN_UP)
		{
		    request->jobmanager_state =
			GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP;
		}
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_FILE_CLEAN_UP:
	if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP)
	{
	    if(request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP;
	    }
	    else
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_SCRATCH_CLEAN_UP;
	    }
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_FILE_CLEAN_UP)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_SCRATCH_CLEAN_UP;
	}
	else
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP;
	}

	if(globus_gram_job_manager_rsl_need_scratchdir(request) &&
	   request->scratchdir)
	{
	    rc = globus_gram_job_manager_script_rm_scratchdir(request);

	    if(rc == GLOBUS_SUCCESS)
	    {
		event_registered = GLOBUS_TRUE;
	    }
	    else
	    {
                globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
		request->failure_code = rc;

		if(request->jobmanager_state !=
		    GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_SCRATCH_CLEAN_UP)
		{
		    request->jobmanager_state = 
			GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP;
		}
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_SCRATCH_CLEAN_UP:
	if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP;
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_SCRATCH_CLEAN_UP)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CACHE_CLEAN_UP;
	}
	else
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP;
	}
	rc = globus_gram_job_manager_script_cache_cleanup(request);

	if(rc == GLOBUS_SUCCESS)
	{
	    event_registered = GLOBUS_TRUE;
	}
	else if(rc != GLOBUS_SUCCESS && request->failure_code == 0)
	{
            request->failure_code = rc;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);

	    if(request->jobmanager_state == 
		    GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP)
	    {
		request->jobmanager_state =
		    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP;
	    }
	}
	break;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CACHE_CLEAN_UP:
	if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_DONE;
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CACHE_CLEAN_UP)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_RESPONSE;
	}
	else
	{
	    request->jobmanager_state = 
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
	}
	
	if(request->save_state)
	{
	    if(request->job_state_file)
	    {
		remove(request->job_state_file);
	    }
	    if(request->job_state_lock_file)
	    {
		remove(request->job_state_lock_file);
	    }
	}
	if(request->jobmanager_state != 
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_RESPONSE)
	{
            globus_l_gram_job_manager_cancel_queries(request);
	    globus_cond_signal(&request->cond);
	    globus_gram_job_manager_reporting_file_stop_cleaner(request);
            globus_gram_job_manager_reporting_file_remove(request);
	    event_registered = GLOBUS_TRUE;
	}

	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP:
	/* This state is reached when the job manager decides to stop
	 * between the time the job request reply is sent and the 
	 * job manager has noticed stop or failed
	 */
	request->jobmanager_state =
	    GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;

	if(request->job_history_status != request->status)
	{
            globus_gram_job_manager_history_file_create(request);
	    request->job_history_status = request->status;
	}

	rc = globus_gram_job_manager_output_close(request);
	if(rc == GLOBUS_SUCCESS)
	{
	    event_registered = GLOBUS_TRUE;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT:
	/*
	 * Send the job manager stopped or proxy expired failure callback.
	 * This callback is delayed until after the close output is completed,
	 * so that clients won't exit before the output is sent.
	 */
        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);

	globus_gram_job_manager_contact_state_callback(request);

	request->jobmanager_state = 
	    GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE;

        globus_l_gram_job_manager_cancel_queries(request);
	globus_cond_signal(&request->cond);
	globus_gram_job_manager_reporting_file_stop_cleaner(request);
        globus_gram_job_manager_reporting_file_remove(request);
	event_registered = GLOBUS_TRUE;
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE:
	if(request->save_state)
	{
	    if(request->job_state_file)
	    {
		remove(request->job_state_file);
	    }
	    if(request->job_state_lock_file)
	    {
		remove(request->job_state_lock_file);
	    }
	}
        globus_l_gram_job_manager_cancel_queries(request);
	globus_cond_signal(&request->cond);
	globus_gram_job_manager_reporting_file_stop_cleaner(request);
        globus_gram_job_manager_reporting_file_remove(request);
	event_registered = GLOBUS_TRUE;
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE:
        globus_l_gram_job_manager_cancel_queries(request);
	globus_cond_signal(&request->cond);
	event_registered = GLOBUS_TRUE;
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_RESPONSE:
	request->two_phase_commit = 0;
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE;
	globus_l_gram_job_manager_reply(request);
	globus_cond_signal(&request->cond);
	globus_gram_job_manager_reporting_file_stop_cleaner(request);
        globus_gram_job_manager_reporting_file_remove(request);
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:

        if (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED && request->failure_code == GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_OUT_FAILED)
        {
            request->jobmanager_state =
            GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT;
            break;
        }

        request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT;
	if(globus_gram_job_manager_rsl_need_stage_out(request))
	{
	    rc = globus_gram_job_manager_script_stage_out(request);
	    
	    if(rc != GLOBUS_SUCCESS)
	    {
		request->failure_code = rc;
		request->jobmanager_state =
			GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    }
	    else
	    {
		event_registered = GLOBUS_TRUE;
	    }
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
	if(!globus_list_empty(request->stage_out_todo))
	{
	    request->jobmanager_state
                    = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT;
	    if(request->failure_code == GLOBUS_SUCCESS)
	    {
		request->failure_code =
		    GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_OUT_FAILED;
	    }
	}
      /* FALLSTHROUGH */
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CLOSE_OUTPUT:
	if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE);
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT)
	{
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CLOSE_OUTPUT)
	{
	    request->jobmanager_state = 
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_PRE_FILE_CLEAN_UP;
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	    break;
	}

	/*
	 * To do a two-phase commit, we need to send an error
	 * message (WAITING_FOR_COMMIT) in the initial reply; otherwise,
	 * we just return the current status code.
         */
	if(request->unsent_status_change)
	{
            if(request->job_history_status != request->status)
            {
            	globus_gram_job_manager_history_file_create(request);
            	request->job_history_status = request->status;
            }

            globus_gram_job_manager_contact_state_callback(request);
	    request->unsent_status_change = GLOBUS_FALSE;
	}

	if(request->two_phase_commit != 0)
	{
	    GlobusTimeReltimeSet(delay_time, request->two_phase_commit, 0);

	    globus_callback_register_oneshot(
		    &request->poll_timer,
		    &delay_time,
		    globus_gram_job_manager_state_machine_callback,
		    request);

	    event_registered = GLOBUS_TRUE;
	}
	break;
    }

    return event_registered;
}
/* globus_gram_job_manager_state_machine() */

static
int
globus_l_gram_job_manager_reply(
    globus_gram_jobmanager_request_t *	request)
{
    int					failure_code;
    int					rc;
    char *				sent_contact;
    globus_byte_t *                     reply = NULL;
    globus_size_t                       replysize;
    globus_byte_t *                     sendbuf;
    globus_size_t                       sendsize;
    OM_uint32				major_status;
    OM_uint32				minor_status;
    int					token_status;


    failure_code = request->failure_code;

    if(request->two_phase_commit != 0)
    {
	failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT;
	sent_contact = request->job_contact;
    }
    else if(failure_code == 0)
    {
	sent_contact = request->job_contact;
    }
    else if (failure_code == GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE)
    {
	sent_contact = request->old_job_contact;
    }
    else
    {
	sent_contact = NULL;
    }

    /* Response to initial job request. */
    rc = globus_gram_protocol_pack_job_request_reply(
	    failure_code,
	    sent_contact,
	    &reply,
	    &replysize);

    if(rc == GLOBUS_SUCCESS)
    {
	rc = globus_gram_protocol_frame_reply(
		200,
		reply,
		replysize,
		&sendbuf,
		&sendsize);
    }
    else
    {
	rc = globus_gram_protocol_frame_reply(
		400,
		NULL,
		0,
		&sendbuf,
		&sendsize);
    }
    if(reply)
    {
	globus_libc_free(reply);
    }
    globus_gram_job_manager_request_log( request,
		   "JM: before sending to client: rc=%d (%s)\n",
		   rc, globus_gram_protocol_error_string(rc));
    if(rc == GLOBUS_SUCCESS)
    {
	if(request->response_context != GSS_C_NO_CONTEXT)
	{
	    major_status = globus_gss_assist_wrap_send(
		    &minor_status,
		    request->response_context,
		    sendbuf,
		    sendsize,
		    &token_status,
		    globus_gss_assist_token_send_fd,
		    stdout,
		    request->jobmanager_log_fp);
	}
	else
	{
	    printf("Job Manager Response: %s\n", sendbuf);
	    major_status = 0;
	}
	/*
	 * close the connection (both stdin and stdout are connected to the
	 * socket
	 */
	close(0);
	close(1);

	/*
	 * Reopen stdin and stdout to /dev/null---the job submit code
	 * expects to be able to close them
	 */
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);

	globus_libc_free(sendbuf);

	if(major_status != GSS_S_COMPLETE)
	{
            globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	    request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
	}
    }
    else
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: couldn't send job contact to client: rc=%d (%s)\n",
		rc,
		globus_gram_protocol_error_string(rc));
        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
    }

    if(rc != GLOBUS_SUCCESS)
    {
	request->failure_code = rc;
    }

    GLOBUS_GRAM_JOB_MANAGER_DEBUG_STATE(request, "exiting");
    return rc;
}
/* globus_l_gram_job_manager_reply() */


static
int
globus_l_gram_job_manager_read_request(
    globus_gram_jobmanager_request_t *	request)
{
    int					rc;
    char *				args_fd_str;
    int					args_fd;
    globus_size_t			jrbuf_size;
    char				buffer[
	                                    GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int					job_state_mask;
    char *				client_contact_str;

    if(request->rsl_spec)
    {
	return GLOBUS_SUCCESS;
    }

    args_fd_str = globus_libc_getenv("GRID_SECURITY_HTTP_BODY_FD");

    if ((!args_fd_str) || ((args_fd = atoi(args_fd_str)) == 0))
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    jrbuf_size = (globus_size_t) lseek(args_fd, 0, SEEK_END);
    (void) lseek(args_fd, 0, SEEK_SET);
    if (jrbuf_size > GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE)
    {
	globus_gram_job_manager_request_log( request,
	    "JM: RSL file too big\n");
	return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    if (read(args_fd, buffer, jrbuf_size) != jrbuf_size)
    {
	globus_gram_job_manager_request_log(
		request,
		"JM: Error reading the RSL file\n");
	return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    close(args_fd);

    rc = globus_gram_protocol_unpack_job_request(
	    buffer,
	    jrbuf_size,
	    &job_state_mask,
	    &client_contact_str,
	    &request->rsl_spec);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_gram_job_manager_request_log(request,
		              "JM: request unpack failed because %s\n",
			      globus_gram_protocol_error_string(rc));
	return rc;
    }
    if(client_contact_str != NULL)
    {
	rc = globus_gram_job_manager_contact_add(
		request,
		client_contact_str,
		job_state_mask);
    }
    return rc;
}
/* globus_l_gram_job_manager_read_request() */

static
int
globus_l_gram_job_manager_set_unique_id(
    globus_gram_jobmanager_request_t *	request)
{
    unsigned long			my_pid;
    unsigned long			my_time;
    int					rc;

    if(request->jm_restart)
    {
	sscanf( request->jm_restart,
		"https://%*[^:]:%*d/%lu/%lu/",
		&my_pid,
		&my_time);
    }
    else
    {
	my_pid = (unsigned long) getpid();
	my_time = (unsigned long) time(NULL);
    }

    request->uniq_id = globus_libc_malloc(GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE);
    rc = sprintf(request->uniq_id, "%lu.%lu", my_pid, my_time);
    /* If this assertion isn't true, then we've corrupted memory anyway */
    globus_assert(rc < GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE);

    request->job_contact =
	globus_libc_malloc(GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE);

    rc = sprintf(request->job_contact,
	         "%s%lu/%lu/",
		 request->url_base,
		 my_pid,
		 my_time);

    /* If this assertion isn't true, then we've corrupted memory anyway */
    globus_assert(rc < GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE);

    request->job_contact_path =
	globus_libc_malloc(strlen(request->job_contact)+1);

    rc = sprintf(request->job_contact_path,
	         "/%lu/%lu/",
	         my_pid,
	         my_time);

    /* If this assertion isn't true, then we've corrupted memory anyway */
    globus_assert(rc < GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE);

    return GLOBUS_SUCCESS;
}
/* globus_l_gram_job_manager_set_unique_id() */

static
char *
globus_l_gram_job_manager_getenv(
    const char *			var,
    const char *			default_value)
{
    char *				tmp_str;

    tmp_str = globus_libc_getenv(var);

    if(tmp_str)
    {
	return globus_libc_strdup(tmp_str);
    }
    else if(default_value)
    {
	return globus_libc_strdup(default_value);
    }
    else
    {
	return NULL;
    }
}
/* globus_l_gram_job_manager_getenv() */

/**
 * Do the state transition for handling a job manager restart.
 *
 * @param request
 *        The request to changes states.
 *
 * @return
 *       Returns GLOBUS_TRUE if if the job manager's state was
 *       changed as a result of this call; GLOBUS_FALSE otherwise.
 *
 * @note This case statement MUST cover all cases where the
 *        state file can be written (where
 *        globus_gram_job_manager_state_file_write()
 *        is called).
 */
static
globus_bool_t
globus_l_gram_job_manager_set_restart_state(
    globus_gram_jobmanager_request_t *	request)
{
    globus_bool_t			changed = GLOBUS_FALSE;

    switch(request->restart_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT:
	break;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
	changed = GLOBUS_TRUE;
	break;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE);
	request->unsent_status_change = GLOBUS_TRUE;
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
	changed = GLOBUS_TRUE;
	break;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
        globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
	request->unsent_status_change = GLOBUS_TRUE;
	request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1;
	changed = GLOBUS_TRUE;
	break;
      default:
	break;
    }
    request->restart_state = GLOBUS_GRAM_JOB_MANAGER_STATE_START;

    return changed;
}
/* globus_l_gram_job_manager_set_restart_state() */

static
void
globus_l_gram_job_manager_state_log_rsl(
    globus_gram_jobmanager_request_t *	request,
    const char *			label)
{
    char *				tmp_str;

    tmp_str = globus_rsl_unparse(request->rsl);

    if(tmp_str)
    {
	globus_gram_job_manager_request_log(
		request,
		"\n<<<<<%s\n%s\n"
		">>>>>%s\n",
		label,
		tmp_str,
		label);

	globus_libc_free(tmp_str);
    }
}
/* globus_l_gram_job_manager_state_log_rsl() */

#ifdef BUILD_DEBUG
static
const
char *
globus_l_gram_job_manager_state_string(
    globus_gram_jobmanager_state_t	state)
{
#   define STRING_CASE(x) case x: return #x;

    switch(state)
    {
	STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_START)
	STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_MAKE_SCRATCHDIR)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_REMOTE_IO_FILE_CREATE)
	STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_RELOCATE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_DONE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CLOSE_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_PRE_FILE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_FILE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_SCRATCH_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CACHE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_RESPONSE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STOP)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_CLOSE)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2)
        STRING_CASE(GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH)
	/* Don't put a default case here. */
    }
    return "UNKNOWN";
}
/* globus_l_gram_job_manager_state_string() */
#endif /* BUILD_DEBUG */

static
void
globus_l_gram_job_manager_cancel_queries(
    globus_gram_jobmanager_request_t *	request)
{
    globus_gram_job_manager_query_t *	query;

    while(!globus_fifo_empty(&request->pending_queries))
    {
        query = globus_fifo_dequeue(&request->pending_queries);
        query->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;

        /* Frees the query */
        globus_gram_job_manager_query_reply(
                request,
                query);

    }
}
/* globus_l_gram_job_manager_cancel_queries() */

/**
 * Validate that the job manager is running as the username specified in the
 * RSL if it is present.
 *
 * @param request
 *     Request which contains information about the job. We'll only look at
 *     the RSL in the request to check for presence of the username attribute.
 *
 * @retval GLOBUS_SUCCESS
 *     Either the username RSL attribute was not present, or it was present
 *     and its value matched the account this process is running as.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Some system call failed when we tried to look up the user id.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_USER_NAME
 *     This process is not running as the desired user.
 */
static
int
globus_l_gram_job_manager_validate_username(
    globus_gram_jobmanager_request_t *	request)
{
    char *                              tmp_str = NULL;
    char *                              buffer = NULL;
    struct passwd                       pwd;
    struct passwd *                     pwd_result = NULL;
    int                                 rc = GLOBUS_SUCCESS;

    /* Validate username RSL attribute if present */
    rc = globus_gram_job_manager_rsl_eval_one_attribute(
            request,
            GLOBUS_GRAM_PROTOCOL_USER_NAME,
            &tmp_str);

    if (rc != 0)
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: eval of %s failed\n",
                GLOBUS_GRAM_PROTOCOL_USER_NAME);

        return rc;
    }

    if (tmp_str != NULL)
    {
        buffer = malloc(1024);

        if (buffer == NULL)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: allocating buffer for getpwnam_r failed\n");
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto free_tmp_str_exit;
        }

        rc = globus_libc_getpwnam_r(
                tmp_str,
                &pwd,
                buffer,
                sizeof(1024),
                &pwd_result);

        if (rc != 0 || pwd_result == NULL)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: getpwnam_r failed\n");

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto free_buffer_exit;
        }

        if (pwd.pw_uid != getuid())
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: job manager is NOT running as %s (uid=%lu)"
                    "---running as uid=%lu\n",
                    tmp_str,
                    (unsigned long )pwd.pw_uid,
                    (unsigned long) getuid());

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_USER_NAME;

            goto free_buffer_exit;
        }
    }

free_buffer_exit:
    if (buffer != NULL)
    {
        free(buffer);
    }

free_tmp_str_exit:
    if (tmp_str != NULL)
    {
        free(tmp_str);
    }

    return rc;
}
/* globus_l_gram_job_manager_validate_username() */
