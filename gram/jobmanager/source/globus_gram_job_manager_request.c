/*
 * Copyright 1999-2009 University of Chicago
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
 * @file globus_gram_job_manager_request.c Globus Job Management Request
 *
 * CVS Information:
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */

/*
 * Include header files
 */
#include "globus_common.h"
#include "globus_gram_protocol.h"
#include "globus_gram_job_manager.h"
#include "globus_rsl_assist.h"

#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <ftw.h>

enum
{
    GRAM_JOB_MANAGER_COMMIT_TIMEOUT=60
};


static
int
globus_l_gram_symbol_table_populate(
    globus_gram_jobmanager_request_t *  request);

static
int
globus_l_gram_symboltable_add(
    globus_symboltable_t *              symbol_table,
    const char *                        symbol,
    const char *                        value);

static
void
globus_l_gram_log_rsl(
    globus_gram_jobmanager_request_t *  request,
    const char *                        label);

static
int
globus_l_gram_generate_id(
    globus_gram_jobmanager_request_t *  request,
    char **                             jm_restart,
    uint64_t *                          uniq1p,
    uint64_t *                          uniq2p);

static
int
globus_l_gram_init_cache(
    globus_gram_jobmanager_request_t *  request,
    char **                             cache_locationp,
    globus_gass_cache_t  *              cache_handlep);

static
int
globus_l_gram_restart(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_t **                     stdout_position_hack,
    globus_rsl_t **                     stderr_position_hack);

static
int
globus_l_gram_populate_environment(
    globus_gram_jobmanager_request_t *  request);

static
int
globus_l_gram_add_environment(
    globus_rsl_t *                      rsl,
    const char *                        variable,
    const char *                        value);

static
int
globus_l_gram_init_scratchdir(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_t *                      rsl,
    const char *                        scratch_dir_base,
    char **                             scratchdir);

static
void
globus_l_gram_destroy_scratchdir(
    globus_gram_jobmanager_request_t *  request,
    const char *                        scratchdir);

static
int
globus_l_gram_nftw_func(
    const char *                        pathname,
    const struct stat *                 stat,
    int                                 info,
    struct FTW *                        ftw_struct);

static
int
globus_l_gram_validate_rsl(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_t *                      stdout_position_hack,
    globus_rsl_t *                      stderr_position_hack);

static
int
globus_l_gram_remote_io_url_file_create(
    globus_gram_jobmanager_request_t *  request,
    const char *                        remote_io_url,
    const char *                        job_dir,
    char **                             remote_io_url_filep);

static
int
globus_l_gram_export_cred(
    globus_gram_jobmanager_request_t *  request,
    gss_cred_id_t                       cred,
    const char *                        job_directory,
    char **                             proxy_filename);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * Allocate and initialize a request.
 *
 * This function allocates a new request structure and clears all of the
 * values in the structure. It also creates a script argument file which
 * will be used when the job request is submitted.
 *
 * @param request
 *     A pointer to a globus_gram_jobmanager_request_t pointer. This
 *     will be modified to point to a freshly allocated request structure.
 * @param manager
 *     Job manager state and configuration.
 * @param rsl
 *     Job request or restart RSL string
 * @param delegated_credential
 *    Credential delegated with the job request.
 * @param response_ctx
 *    Security context to use for sending the job request response, may be
 *    GSS_C_NO_CONTEXT if the job RSL came from the command-line.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL
 *     Bad RSL
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED
 *     RSL evaluation failed
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SCRATCH
 *     Invalid scratchdir RSL attribute
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRATCH
 *     Invalid scratchdir path
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_PARAMETER_NOT_SUPPORTED
 *     RSL attribute not supported.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SUBMIT_ATTRIBUTE
 *     Invalid submit RSL attribute.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_RESTART_ATTRIBUTE
 *     Invalid restart RSL attribute.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_STDIO_UPDATE_ATTRIBUTE
 *     Invalid stdio_update RSL attribute.
 */
int 
globus_gram_job_manager_request_init(
    globus_gram_jobmanager_request_t ** request,
    globus_gram_job_manager_t *         manager,
    char *                              rsl,
    gss_cred_id_t                       delegated_credential,
    gss_ctx_id_t                        response_ctx)
{
    globus_gram_jobmanager_request_t *  r;
    uint64_t                            uniq1, uniq2;
    int                                 rc;
    const char *                        tmp_string;
    globus_rsl_t *                      stdout_position_hack = NULL;
    globus_rsl_t *                      stderr_position_hack = NULL;

    /*** creating request structure ***/
    r = malloc(sizeof(globus_gram_jobmanager_request_t));

    /* Order more-or-less matches that of struct declaration in
     * globus_gram_job_manager.h
     */
    r->config = manager->config;
    r->manager = manager;

    r->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED;
    r->status_update_time = 0;
    r->failure_code = 0;
    /* Won't be set until job has been submitted to the LRM */
    r->job_id = NULL;
    r->poll_frequency = 30;
    r->commit_extend = 0;
    r->scratchdir = NULL;
    globus_gram_job_manager_output_init(r);
    r->creation_time = time(NULL);
    r->queued_time = time(NULL);
    r->cache_tag = NULL;
    rc = globus_symboltable_init(
            &r->symbol_table,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto symboltable_init_failed;
    }
    rc = globus_symboltable_create_scope(&r->symbol_table);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto symboltable_create_scope_failed;
    }
    rc = globus_l_gram_symbol_table_populate(r);
    if (rc != GLOBUS_SUCCESS)
    {
        goto symboltable_populate_failed;
    }

    globus_gram_job_manager_request_log(
            r,
            "Pre-parsed RSL string: %s\n",
            rsl);
    
    r->rsl = globus_rsl_parse(rsl);
    if (r->rsl == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;

        goto rsl_parse_failed;
    }
    globus_l_gram_log_rsl(r, "Job Request RSL");

    rc = globus_rsl_assist_attributes_canonicalize(r->rsl);
    if(rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;

        goto rsl_canonicalize_failed;
    }
    r->rsl_spec = globus_rsl_unparse(r->rsl);
    if (r->rsl_spec == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto rsl_unparse_failed;
    }

    globus_l_gram_log_rsl(r, "Job Request RSL (canonical)");
    
    rc = globus_gram_job_manager_rsl_add_substitutions_to_symbol_table(r);
    if(rc != GLOBUS_SUCCESS)
    {
        goto add_substitutions_to_symbol_table_failed;
    }

    /* If this is a restart job, the id will come from the restart RSL
     * value; otherwise, it will be generated from current pid and time
     */
    rc = globus_l_gram_generate_id(
            r,
            &r->jm_restart,
            &uniq1,
            &uniq2);

    /* Unique ID is used to have a handle to a job that has its state saved
     * and then the job is later restarted
     */
    r->uniq_id = globus_common_create_string(
            "%"PRIu64".%"PRIu64,
            uniq1,
            uniq2);
    if (r->uniq_id == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto failed_set_uniq_id;
    }
    /* The job contact is how the client is able to send signals or cancel this 
     * job.
     */
    r->job_contact = globus_common_create_string(
            "%s%"PRIu64"/%"PRIu64"/",
            r->manager->url_base,
            uniq1,
            uniq2);

    if (r->job_contact == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto failed_set_job_contact;
    }
    rc = globus_l_gram_symboltable_add(
            &r->symbol_table,
            "GLOBUS_GRAM_JOB_CONTACT",
            r->job_contact);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_add_contact_to_symboltable;
    }

    rc = setenv("GLOBUS_GRAM_JOB_CONTACT", r->job_contact, 1);
    if (rc != 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto failed_setenv_job_contact;
    }

    r->job_contact_path = globus_common_create_string(
            "/%"PRIu64"/%"PRIu64"/",
            uniq1,
            uniq2);
    if (r->job_contact_path == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto failed_set_job_contact_path;
    }

    rc = globus_gram_job_manager_state_file_set(
        r,
        &r->job_state_file,
        &r->job_state_lock_file);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_state_file_set;
    }
    r->job_state_lock_fd = -1;

    if (r->jm_restart)
    {
        rc = globus_l_gram_restart(
                r,
                &stdout_position_hack,
                &stderr_position_hack);

        if (rc != GLOBUS_SUCCESS)
        {
            goto failed_restart;
        }
    }
    else
    {
        r->cache_tag = strdup(r->job_contact);
        if (r->cache_tag == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            goto cache_tag_alloc_failed;
        }
    }

    rc = globus_gram_job_manager_rsl_eval_string(
            r,
            r->config->scratch_dir_base,
            &r->scratch_dir_base);
    if(rc != GLOBUS_SUCCESS)
    {
        goto failed_eval_scratch_dir_base;
    }

    rc = globus_l_gram_init_scratchdir(
            r,
            r->rsl,
            r->scratch_dir_base,
            &r->scratchdir);
    if(rc != GLOBUS_SUCCESS)
    {
        goto init_scratchdir_failed;
    }

    rc = globus_l_gram_init_cache(
            r,
            &r->cache_location,
            &r->cache_handle);
    if (rc != GLOBUS_SUCCESS)
    {
        goto init_cache_failed;
    }

    /* At this point, all of the RSL substitutions have been populated,
     * including those based on runtime values, so we can validate the RSL
     */
    rc = globus_l_gram_validate_rsl(
            r,
            stdout_position_hack,
            stderr_position_hack);
    if(rc != GLOBUS_SUCCESS)
    {
        goto validate_rsl_failed;;
    }

    rc = globus_gram_job_manager_rsl_attribute_get_boolean_value(
            r->rsl,
            GLOBUS_GRAM_PROTOCOL_DRY_RUN_PARAM,
            &r->dry_run);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_DRYRUN;
        goto get_dry_run_failed;
    }

    rc = globus_gram_job_manager_rsl_attribute_get_boolean_value(
            r->rsl,
            GLOBUS_GRAM_PROTOCOL_SAVE_STATE_PARAM,
            &r->save_state);
    if (rc == GLOBUS_GRAM_PROTOCOL_ERROR_UNDEFINED_ATTRIBUTE)
    {
        r->save_state = GLOBUS_FALSE;
        rc = GLOBUS_SUCCESS;
    }
    else if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SAVE_STATE;
        goto get_save_state_failed;
    }

    /* Some clients send (two_phase_commit = yes), others send
     * (two_phase_commit = timeout)
     */
    rc = globus_gram_job_manager_rsl_attribute_get_int_value(
            r->rsl,
            GLOBUS_GRAM_PROTOCOL_TWO_PHASE_COMMIT_PARAM,
            &r->two_phase_commit);
    if (rc == GLOBUS_GRAM_PROTOCOL_ERROR_UNDEFINED_ATTRIBUTE)
    {
        r->two_phase_commit = 0;
    }
    else if (rc != GLOBUS_SUCCESS)
    {
        globus_bool_t tmp_bool;

        rc = globus_gram_job_manager_rsl_attribute_get_boolean_value(
                r->rsl,
                GLOBUS_GRAM_PROTOCOL_TWO_PHASE_COMMIT_PARAM,
                &tmp_bool);

        if (rc == GLOBUS_SUCCESS)
        {
            r->two_phase_commit  =
                    tmp_bool ? GRAM_JOB_MANAGER_COMMIT_TIMEOUT : 0;
        }
        else
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_TWO_PHASE_COMMIT;
            goto get_two_phase_commit_failed;
        }

        globus_gram_job_manager_rsl_remove_attribute(
                r,
                GLOBUS_GRAM_PROTOCOL_TWO_PHASE_COMMIT_PARAM);
    }

    rc = globus_gram_job_manager_rsl_attribute_get_string_value(
            r->rsl,
            GLOBUS_GRAM_PROTOCOL_REMOTE_IO_URL_PARAM,
            &tmp_string);

    switch (rc)
    {
    case GLOBUS_SUCCESS:
        r->remote_io_url = strdup(tmp_string);
        if (r->remote_io_url == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            goto get_remote_io_url_failed;
        }
        break;
    case GLOBUS_GRAM_PROTOCOL_ERROR_UNDEFINED_ATTRIBUTE:
        r->remote_io_url = NULL;
        break;
    default:
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_REMOTE_IO_URL;
        goto get_remote_io_url_failed;
    }
    rc = globus_gram_job_manager_output_make_job_dir(r);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_make_job_dir;

    }

    rc = globus_l_gram_remote_io_url_file_create(
            r,
            r->remote_io_url,
            r->job_dir,
            &r->remote_io_url_file);

    if (rc != GLOBUS_SUCCESS)
    {
        goto make_remote_io_url_file_failed;
    }

    if (globus_gram_job_manager_rsl_attribute_exists(
            r->rsl,
            GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM))
    {
        const char * tmp;

        rc = globus_gram_job_manager_rsl_attribute_get_string_value(
                r->rsl,
                GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM,
                &tmp);

        /* Only error is undefined, but we know it is defined */
        globus_assert(rc == GLOBUS_SUCCESS);

        r->local_stdout = strdup(tmp);

        /* Non-string literal */
        if (r->local_stdout == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDOUT;
            goto failed_get_stdout_path;
        }
        rc = globus_symboltable_insert(
                &r->symbol_table,
                "GLOBUS_CACHED_STDOUT",
                r->local_stdout);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            goto failed_insert_cached_stdout_into_symboltable;
        }
    }
    else
    {
        r->local_stdout = strdup("/dev/null");
        if (r->local_stdout == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            goto failed_malloc_local_stdout;
        }
    }

    if (globus_gram_job_manager_rsl_attribute_exists(
            r->rsl,
            GLOBUS_GRAM_PROTOCOL_STDERR_PARAM))
    {
        const char * tmp;
        rc = globus_gram_job_manager_rsl_attribute_get_string_value(
                r->rsl,
                GLOBUS_GRAM_PROTOCOL_STDERR_PARAM,
                &tmp);

        /* Only error is undefined, but we know it is defined */
        globus_assert(rc == GLOBUS_SUCCESS);

        /* Non-string literal */
        r->local_stderr = strdup(tmp);
        if (r->local_stderr == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDERR;
            goto failed_get_stderr_path;
        }
        rc = globus_symboltable_insert(
                &r->symbol_table,
                "GLOBUS_CACHED_STDERR",
                r->local_stderr);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            goto failed_insert_cached_stderr_into_symboltable;
        }
    }
    else
    {
        r->local_stderr = strdup("/dev/null");
        if (r->local_stderr == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            goto failed_malloc_local_stderr;
        }
    }
    rc = globus_mutex_init(&r->mutex, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        goto mutex_init_failed;
    }
    rc = globus_cond_init(&r->cond, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        goto cond_init_failed;
    }
    r->client_contacts = NULL;
    r->stage_in_todo = NULL;
    r->stage_in_shared_todo = NULL;
    r->stage_out_todo = NULL;
    rc = globus_gram_job_manager_staging_create_list(r);
    if(rc != GLOBUS_SUCCESS)
    {
        goto staging_list_create_failed;
    }
    
    r->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_START;
    r->restart_state = GLOBUS_GRAM_JOB_MANAGER_STATE_START;
    r->unsent_status_change = GLOBUS_FALSE;
    r->poll_timer = GLOBUS_NULL_HANDLE;
    rc = globus_fifo_init(&r->pending_queries);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto pending_queries_init_failed;
    }
    rc = globus_l_gram_export_cred(
            r,
            delegated_credential,
            r->job_dir,
            &r->x509_user_proxy);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_export_cred;
    }

    rc = globus_l_gram_populate_environment(r);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_populate_environment;
    }
    r->streaming_requested = GLOBUS_FALSE;

    rc = globus_gram_job_manager_history_file_set(r);
    if (rc != GLOBUS_SUCCESS)
    {
        goto history_file_set_failed;
    }
    r->job_history_status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED;

    r->response_context = response_ctx;

    rc = globus_gram_job_manager_state_file_write(r);

    if (rc != GLOBUS_SUCCESS)
    {
failed_insert_cached_stderr_into_symboltable:
        if (r->local_stderr)
        {
            free(r->local_stderr);
        }
failed_malloc_local_stderr:
failed_get_stderr_path:
failed_insert_cached_stdout_into_symboltable:
        if (r->local_stdout)
        {
            free(r->local_stdout);
        }
failed_malloc_local_stdout:
failed_get_stdout_path:
        if (r->job_history_file)
        {
            free(r->job_history_file);
            r->job_history_file = NULL;
        }
history_file_set_failed:
        globus_gass_cache_close(&r->cache_handle);
        if (r->cache_location)
        {
            free(r->cache_location);
        }
    /* TODO: Remove job dir */
failed_populate_environment:
failed_export_cred:
pending_queries_init_failed:
staging_list_create_failed:
        globus_cond_destroy(&r->cond);
cond_init_failed:
        globus_mutex_destroy(&r->mutex);
mutex_init_failed:
        if (r->remote_io_url_file)
        {
            remove(r->remote_io_url_file);
            free(r->remote_io_url_file);
        }
failed_make_job_dir:
make_remote_io_url_file_failed:
        if (r->remote_io_url)
        {
            free(r->remote_io_url);
        }
get_remote_io_url_failed:
get_two_phase_commit_failed:
get_save_state_failed:
get_dry_run_failed:
validate_rsl_failed:
init_cache_failed:
        if (r->scratchdir)
        {
            globus_l_gram_destroy_scratchdir(r, r->scratchdir);
            free(r->scratchdir);
            r->scratchdir = NULL;
        }
init_scratchdir_failed:
        if (r->scratch_dir_base)
        {
            free(r->scratch_dir_base);
        }
failed_eval_scratch_dir_base:
        free(r->cache_tag);
cache_tag_alloc_failed:
failed_restart:
        free(r->job_state_lock_file);
        free(r->job_state_file);
failed_state_file_set:
        free(r->job_contact_path);
failed_set_job_contact_path:
failed_setenv_job_contact:
failed_add_contact_to_symboltable:
        free(r->job_contact);
failed_set_job_contact:
        free(r->uniq_id);
failed_set_uniq_id:
add_substitutions_to_symbol_table_failed:
        free(r->rsl_spec);
rsl_unparse_failed:
rsl_canonicalize_failed:
        globus_rsl_free_recursive(r->rsl);
rsl_parse_failed:
symboltable_populate_failed:
symboltable_create_scope_failed:
        globus_symboltable_destroy(&r->symbol_table);
symboltable_init_failed:
        free(r);
        r = NULL;
    }
    *request = r;
    return rc;
}
/* globus_gram_job_manager_request_init() */

/**
 * Load request and security context, initialize structures, and send reply.
 *
 * @param manager
 *     Job manager state
 * @param http_body_fd
 *     File descriptor of the HTTP body file
 * @param context_fd
 *     File descriptor pointing to the GSSAPI security context to use for the
 *     response.
 * @param request
 *     Pointer to be set to the new job request
 * @param context
 *     Pointer to be set to the security context of the initial job request
 * @param contact
 *     Pointer to be set to the job contact of the client to send job state
 *     change notifications to.
 * @param job_state_mask
 *     Pointer to be set to the job state mask for which job state changes
 *     the client is interested in.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED
 *     Unable to import security context
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED
 *     Unable to read job request from http_body_fd
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL
 *     Bad RSL
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED
 *     RSL evaluation failed
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SCRATCH
 *     Invalid scratchdir RSL attribute
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRATCH
 *     Invalid scratchdir path
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_PARAMETER_NOT_SUPPORTED
 *     RSL attribute not supported.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SUBMIT_ATTRIBUTE
 *     Invalid submit RSL attribute.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_RESTART_ATTRIBUTE
 *     Invalid restart RSL attribute.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_STDIO_UPDATE_ATTRIBUTE
 *     Invalid stdio_update RSL attribute.
 *
 * @note Even if this function returns a failure code, the @a context 
 * may still be initialized to the security context. If it points to a
 * value other than GSS_C_NO_CONTEXT then it can be used by the caller
 * to send the failure response.
 */
int
globus_gram_job_manager_request_load(
    globus_gram_job_manager_t *         manager,
    int                                 http_body_fd,
    int                                 context_fd,
    gss_cred_id_t                       cred,
    globus_gram_jobmanager_request_t ** request,
    gss_ctx_id_t *                      context,
    char **                             contact,
    int *                               job_state_mask)
{
    int                                 rc;
    char *                              rsl;

    *request = NULL;
    *context = GSS_C_NO_CONTEXT;
    *contact = NULL;
    *job_state_mask = 0;

    rc = globus_gram_job_manager_import_sec_context(
            manager,
            context_fd,
            context);
    if (rc != GLOBUS_SUCCESS)
    {
        goto import_context_failed;
    }

    rc = globus_gram_job_manager_read_request(
            manager,
            http_body_fd,
            &rsl,
            contact,
            job_state_mask);
    if (rc != GLOBUS_SUCCESS)
    {
        goto read_request_failed;
    }
    rc = globus_gram_job_manager_request_init(
            request,
            manager,
            rsl,
            cred,
            *context);
    if (rc != GLOBUS_SUCCESS)
    {
        goto request_init_failed;
    }
request_init_failed:
read_request_failed:
import_context_failed:
    return rc;
}
/* globus_gram_job_manager_request_load() */

/** Verify that the job request is authorized, send a reply, and start the state machine for this request
 *
 * @param manager
 *     Job manager state
 * @param request
 *     Job request to start
 * @param client_contact
 *     Client to send job state changes to (may be NULL)
 * @param job_state_mask
 *    Job state mask for sending state changes to the client
 * @param reply_fd
 */
int
globus_gram_job_manager_request_start(
    globus_gram_job_manager_t *         manager,
    globus_gram_jobmanager_request_t *  request,
    FILE *                              response_fp,
    const char *                        client_contact,
    int                                 job_state_mask)
{
    int                                 rc;
    int                                 rc2;

    rc = globus_gram_job_manager_add_request(
        manager,
        request->job_contact_path,
        request);

    globus_mutex_lock(&request->mutex);
    if (rc != GLOBUS_SUCCESS)
    {
        goto add_request_failed;
    }

    rc = globus_gram_job_manager_call_authz_callout(
            request->response_context,
            request->response_context,
            request->uniq_id,
            request->rsl,
            "start");
    if (rc != GLOBUS_SUCCESS)
    {
        goto authz_denied;
    }

    rc = globus_gram_job_manager_validate_username(request);
    if (rc != 0)
    {
        goto username_denied;
    }

    if (client_contact != NULL)
    {
        rc = globus_gram_job_manager_contact_add(
                request,
                client_contact,
                job_state_mask);
        if (rc != GLOBUS_SUCCESS)
        {
            goto contact_add_failed;
        }
    }

    if (request->dry_run)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_DRYRUN;
        rc = globus_gram_job_manager_request_set_status(
                request,
                GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
    }
contact_add_failed:
username_denied:
authz_denied:
add_request_failed:
    /* Reply to request with unsubmitted (and optionally two-phase-commit
     * needed)
     */
    rc2 = globus_gram_job_manager_reply(request, response_fp);
    if (rc == GLOBUS_SUCCESS && rc2 == GLOBUS_SUCCESS)
    {
        globus_result_t                 result;
        globus_reltime_t                delay;

        GlobusTimeReltimeSet(delay, 0, 0);

        result = globus_callback_register_oneshot(
                NULL,
                &delay,
                globus_gram_job_manager_state_machine_callback,
                request);
        if (result != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        }
    }
    else if (rc == GLOBUS_SUCCESS && rc2 != GLOBUS_SUCCESS)
    {
        rc = rc2;
    }
    globus_mutex_unlock(&request->mutex);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = globus_gram_job_manager_remove_reference(
                manager,
                request->job_contact_path);
    }
    return rc;
}
/* globus_gram_job_manager_request_start() */

/**
 * Deallocate memory related to a request.
 *
 * This function frees the data within the request, and then frees the request.
 * The caller must not access the request after this function has returned.
 *
 * @param request
 *        Job request to destroy.
 *
 * @return GLOBUS_SUCCESS
 */
void
globus_gram_job_manager_request_destroy(
    globus_gram_jobmanager_request_t *  request)
{
    if (!request)
    {
        return;
    }

    if (request->job_id)
    {
        free(request->job_id);
    }
    if (request->uniq_id)
    {
        free(request->uniq_id);
    }
    if (request->local_stdout)
    {
        free(request->local_stdout);
    }
    if (request->local_stderr)
    {
        free(request->local_stderr);
    }
    if (request->jm_restart)
    {
        free(request->jm_restart);
    }
    if (request->scratchdir)
    {
        globus_l_gram_destroy_scratchdir(request, request->scratchdir);
        free(request->scratchdir);
    }
    /* TODO: clean up: request->output? */
    /* TODO: clean up: request->cache_handle? */
    if (request->cache_tag)
    {
        free(request->cache_tag);
    }
    globus_symboltable_destroy(&request->symbol_table);
    if (request->rsl_spec)
    {
        free(request->rsl_spec);
    }
    if (request->rsl)
    {
        globus_rsl_free_recursive(request->rsl);
    }
    if (request->remote_io_url)
    {
        free(request->remote_io_url);
    }
    if (request->remote_io_url_file)
    {
        free(request->remote_io_url_file);
    }
    if (request->x509_user_proxy)
    {
        free(request->x509_user_proxy);
    }
    if (request->job_state_file)
    {
        free(request->job_state_file);
    }
    if (request->job_state_lock_file)
    {
        free(request->job_state_lock_file);
    }
    if (request->job_state_lock_fd >= 0)
    {
        close(request->job_state_lock_fd);
    }
    globus_mutex_destroy(&request->mutex);
    globus_cond_destroy(&request->cond);
    globus_gram_job_manager_contact_list_free(request);
    /* TODO: clean up request->stage_in_todo */
    /* TODO: clean up request->stage_in_shared_todo */
    /* TODO: clean up request->stage_in_out_todo */
    globus_assert(request->poll_timer == GLOBUS_NULL_HANDLE);
    if (request->job_contact)
    {
        free(request->job_contact);
    }
    if (request->job_contact_path)
    {
        free(request->job_contact_path);
    }
    /* TODO: clean up request->pending_queries */
    if (request->job_history_file)
    {
        free(request->job_history_file);
    }
    if (request->job_dir)
    {
        free(request->job_dir);
    }
}
/* globus_gram_job_manager_request_destroy() */

/**
 * Change the status associated with a job request
 *
 * Changes the status associated with a job request.
 * There is now additional tracking data associated with the
 * status that must be updated when the status is.  This function
 * handles managing it.  It is NOT recommended that you directly
 * change the status.
 *
 * @param request
 *        Job request to change status of.
 * @param status
 *        Status to set the job request to.
 *
 * @return GLOBUS_SUCCESS assuming valid input.
 *         If the request is null, returns GLOBUS_FAILURE.
 */
int
globus_gram_job_manager_request_set_status(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_job_state_t    status)
{
    return globus_gram_job_manager_request_set_status_time(
            request,
            status,
            time(0));
}
/* globus_gram_job_manager_request_set_status() */


/**
 * Change the status associated with a job request
 *
 * Changes the status associated with a job request.
 * There is now additional tracking data associated with the
 * status that must be updated when the status is.  This function
 * handles managing it.  It is NOT recommended that you directly
 * change the status.
 *
 * @param request
 *        Job request to change status of.
 * @param status
 *        Status to set the job request to.
 * @param valid_time
 *        The status is known good as of this time (seconds since epoch)
 *
 * @return GLOBUS_SUCCESS assuming valid input.
 *         If the request is null, returns GLOBUS_FAILURE.
 */
int
globus_gram_job_manager_request_set_status_time(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_job_state_t    status,
    time_t valid_time)
{
    if( ! request )
        return GLOBUS_FAILURE;
    request->status = status;
    request->status_update_time = valid_time;
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_request_set_status() */

/**
 * Write data to the job manager log file
 *
 * This function writes data to the passed file, using a printf format
 * string. Data is prefixed with a timestamp when written.
 *
 * @param log_fp
 *        Log file to write to.
 * @param format
 *        Printf-style format string to be written.
 * @param ...
 *        Parameters substituted into the format string, if needed.
 *
 * @return This function returns the value returned by vfprintf.
 */
int
globus_gram_job_manager_request_log(
    globus_gram_jobmanager_request_t *  request,
    const char *                        format,
    ... )
{
    struct tm *curr_tm;
    time_t curr_time;
    va_list ap;
    int rc;

    if (!request)
    {
        return -1;
    }

    if ( request->manager->jobmanager_log_fp == NULL )
    {
        return -1;
    }

    time( &curr_time );
    curr_tm = localtime( &curr_time );

    fprintf(request->manager->jobmanager_log_fp,
         "%d/%d %02d:%02d:%02d ",
             curr_tm->tm_mon + 1, curr_tm->tm_mday,
             curr_tm->tm_hour, curr_tm->tm_min,
             curr_tm->tm_sec );

    va_start(ap, format);

    rc = vfprintf(request->manager->jobmanager_log_fp, format, ap);

    va_end(ap);

    return rc;
}
/* globus_gram_job_manager_request_log() */

/**
 * Write data to the job manager accounting file.
 * Also use syslog() to allow for easy central collection.
 *
 * This function writes data to the passed file descriptor, if any,
 * using a printf format string.
 * Data is prefixed with a timestamp when written.
 *
 * @param format
 *        Printf-style format string to be written.
 * @param ...
 *        Parameters substituted into the format string, if needed.
 *
 * @return This function returns the value returned by write().
 */
int
globus_gram_job_manager_request_acct(
    globus_gram_jobmanager_request_t *  request,
    const char *                        format,
    ... )
{
    static const char *jm_syslog_id  = "gridinfo";
    static int         jm_syslog_fac = LOG_DAEMON;
    static int         jm_syslog_lvl = LOG_NOTICE;
    static int         jm_syslog_init;
    struct tm *curr_tm;
    time_t curr_time;
    va_list ap;
    int rc = -1;
    int fd;
    const char * gk_acct_fd_var = "GATEKEEPER_ACCT_FD";
    const char * gk_acct_fd;
    int n;
    int t;
    char buf[1024 * 128];

    time( &curr_time );
    curr_tm = localtime( &curr_time );

    n = t = sprintf( buf, "JMA %04d/%02d/%02d %02d:%02d:%02d ",
                curr_tm->tm_year + 1900,
                curr_tm->tm_mon + 1, curr_tm->tm_mday,
                curr_tm->tm_hour, curr_tm->tm_min,
                curr_tm->tm_sec );

    va_start( ap, format );

    /*
     * FIXME: we should use vsnprintf() here...
     */

    n += vsprintf( buf + t, format, ap );

    if (!jm_syslog_init)
    {
        const char *s;

        if ((s = globus_libc_getenv( "JOBMANAGER_SYSLOG_ID"  )) != 0)
        {
            jm_syslog_id = *s ? s : 0;
        }

        if ((s = globus_libc_getenv( "JOBMANAGER_SYSLOG_FAC" )) != 0)
        {
            if (sscanf( s, "%u", &jm_syslog_fac ) != 1)
            {
                jm_syslog_id = 0;
            }
        }

        if ((s = globus_libc_getenv( "JOBMANAGER_SYSLOG_LVL" )) != 0) {
            if (sscanf( s, "%u", &jm_syslog_lvl ) != 1) {
                jm_syslog_id = 0;
            }
        }

        if (jm_syslog_id)
        {
            openlog( jm_syslog_id, LOG_PID, jm_syslog_fac );
        }

        jm_syslog_init = 1;
    }

    if (jm_syslog_id)
    {
        char *p, *q = buf;

        while ((p = q) < buf + n) {
            char c;

            while ((c = *q) != 0 && c != '\n') {
                q++;
            }

            *q = 0;

            syslog( jm_syslog_lvl, "%s", p );

            *q++ = c;
        }
    }

    if (!(gk_acct_fd = globus_libc_getenv( gk_acct_fd_var )))
    {
        return -1;
    }

    if (sscanf( gk_acct_fd, "%d", &fd ) != 1)
    {
        globus_gram_job_manager_request_log( request,
            "ERROR: %s has bad value: '%s'\n", gk_acct_fd_var, gk_acct_fd );
        return -1;
    }

    if (fcntl( fd, F_SETFD, FD_CLOEXEC ) < 0)
    {
        globus_gram_job_manager_request_log( request,
            "ERROR: cannot set FD_CLOEXEC on %s '%s': %s\n",
            gk_acct_fd_var, gk_acct_fd, strerror( errno ) );
    }

    if ((rc = write( fd, buf, n )) != n)
    {
        globus_gram_job_manager_request_log( request,
            "ERROR: only wrote %d bytes to %s '%s': %s\n%s\n",
            rc, gk_acct_fd_var, gk_acct_fd, strerror( errno ), buf + t );

        rc = -1;
    }

    return rc;
}
/* globus_gram_job_manager_request_acct() */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Populate the request symbol table with values from the job manager config
 *
 * @param request
 *     Request to update the symbol table of
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed
 */
static
int
globus_l_gram_symbol_table_populate(
    globus_gram_jobmanager_request_t *  request)
{
    int                                 rc = GLOBUS_SUCCESS;

    rc = globus_l_gram_symboltable_add(
            &request->symbol_table,
            "HOME",
            request->config->home);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_insert_home;
    }

    rc = globus_l_gram_symboltable_add(
            &request->symbol_table,
            "LOGNAME",
            request->config->logname);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_insert_logname;
    }

    rc = globus_l_gram_symboltable_add(
            &request->symbol_table,
            "GLOBUS_ID",
            request->config->subject);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_insert_globusid;
    }

    rc = globus_l_gram_symboltable_add(
            &request->symbol_table,
            "GLOBUS_CONDOR_OS",
            request->config->condor_os);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_insert_condor_os;
    }
    rc = globus_l_gram_symboltable_add(
            &request->symbol_table,
            "GLOBUS_CONDOR_ARCH",
            request->config->condor_arch);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failed_insert_condor_arch;
    }

    rc = globus_l_gram_symboltable_add(
            &request->symbol_table,
            "GLOBUS_LOCATION",
            request->config->target_globus_location);
    if (rc != GLOBUS_SUCCESS)
    {
        globus_symboltable_remove(&request->symbol_table, "GLOBUS_CONDOR_ARCH");
failed_insert_condor_arch:
        globus_symboltable_remove(&request->symbol_table, "GLOBUS_CONDOR_OS");
failed_insert_condor_os:
        globus_symboltable_remove(&request->symbol_table, "GLOBUS_ID");
failed_insert_globusid:
        globus_symboltable_remove(&request->symbol_table, "LOGNAME");
failed_insert_logname:
        globus_symboltable_remove(&request->symbol_table, "HOME");
    }
failed_insert_home:
    return rc;
}
/* globus_gram_symbol_table_populate() */

/**
 * Insert a symbol into the RSL evaluation symbol table
 * 
 * Also checks that the value is non-NULL and transforms the return
 * value to a GRAM error code.
 *
 * @param symboltable
 *     Symbol table to insert the value to.
 * @param symbol
 *     Symbol name to add to the table.
 * @pram value
 *     Symbol value to add to the table. If NULL nothing is inserted.
 * 
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed
 */
static
int
globus_l_gram_symboltable_add(
    globus_symboltable_t *              symbol_table,
    const char *                        symbol,
    const char *                        value)
{
    int                                 rc = GLOBUS_SUCCESS;

    if (value != NULL)
    {
        rc = globus_symboltable_insert(
            symbol_table,
            (void *) symbol,
            (void *) value);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        }
    }
    return rc;
}
/* globus_l_gram_symboltable_add() */

/**
 * Dump an RSL specification to the request's log file
 */
static
void
globus_l_gram_log_rsl(
    globus_gram_jobmanager_request_t *  request,
    const char *                        label)
{
    char *                              tmp_str;

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
/* globus_l_gram_log_rsl() */

static
int
globus_l_gram_generate_id(
    globus_gram_jobmanager_request_t *  request,
    char **                             jm_restart,
    uint64_t *                          uniq1p,
    uint64_t *                          uniq2p)
{
    int                                 rc = GLOBUS_SUCCESS;

    if(globus_gram_job_manager_rsl_need_restart(request))
    {
        globus_gram_job_manager_request_log(
                request,
                "Job Request is a Job Restart\n");

        /* Need to do this before unique id is set */
        rc = globus_gram_job_manager_rsl_eval_one_attribute(
                request,
                GLOBUS_GRAM_PROTOCOL_RESTART_PARAM,
                jm_restart);

        if (rc != GLOBUS_SUCCESS)
        {
            goto failed_jm_restart_eval;
        }
        else if (request->jm_restart == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_RESTART;
            goto failed_jm_restart_eval;
        }
        globus_gram_job_manager_request_log(
                request,
                "Will try to restart job %s\n",
                request->jm_restart);

        rc = sscanf(
                request->jm_restart,
                "https://%*[^:]:%*d/%"PRIu64"/%"PRIu64,
                uniq1p,
                uniq2p);

        if (rc < 2)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_RESTART;
            goto failed_jm_restart_scan;
        }
        rc = GLOBUS_SUCCESS;
    }
    else
    {
        globus_uuid_t                   uuid;

        rc = globus_uuid_create(&uuid);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        }

        request->jm_restart = NULL;

        memcpy(uniq1p, uuid.binary.bytes, 8);
        memcpy(uniq2p, uuid.binary.bytes, 8);
    }

    if (rc != GLOBUS_SUCCESS)
    {
failed_jm_restart_scan:
        if (request->jm_restart != NULL)
        {
            free(request->jm_restart);
        }
    }
failed_jm_restart_eval:
    return rc;
}
/* globus_l_gram_generate_id() */

/**
 * Determine the cache location to use for this job
 *
 * If the gass_cache RSL attribute is present, it is evaluated and used.
 * Otherwise, if -cache-location was in the configuration, it used. Otherwise,
 * the GASS cache library default is used.
 *
 * As a side-effect, the GLOBUS_GASS_CACHE_DEFAULT environment variable is set
 * when the non-default value is to be used.
 *
 * @param request
 *     Request to use to find which value to use.
 * @param cache_locationp
 *     Pointer to set to the job-specific cache location.
 * @param cache_handlep
 *     Pointer to the GASS cache handle to initialize for this job
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_RSL_CACHE
 *     Invalid gass_cache RSL parameter.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_CACHE
 *     Invalid cache path.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE
 *     Error opening cache.
 */
static
int
globus_l_gram_init_cache(
    globus_gram_jobmanager_request_t *  request,
    char **                             cache_locationp,
    globus_gass_cache_t  *              cache_handlep)
{
    int                                 rc = GLOBUS_SUCCESS;

    if (globus_gram_job_manager_rsl_attribute_exists(
                request->rsl,
                GLOBUS_GRAM_PROTOCOL_GASS_CACHE_PARAM))
    {
        /* If gass_cache is in RSL, we'll evaluate that and use it. */
        rc = globus_gram_job_manager_rsl_eval_one_attribute(
                request,
                GLOBUS_GRAM_PROTOCOL_GASS_CACHE_PARAM,
                cache_locationp);

        if (rc != GLOBUS_SUCCESS)
        {
            goto failed_cache_eval;
        }

        /* cache location in rsl, but not a literal after eval */
        if ((*cache_locationp) == NULL)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "Poorly-formed RSL gass_cache attribute\n");

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_CACHE;

            goto failed_cache_eval;
        }

        globus_gram_job_manager_request_log(
                request,
                "Overriding system gass_cache location %s "
                " with RSL-supplied %s\n",
                request->config->cache_location
                    ? request->config->cache_location : "NULL",
                *(cache_locationp));
    }
    else if (request->config->cache_location != NULL)
    {
        /* If -cache-location was on command-line or config file, then 
         * eval and use it
         */
        globus_gram_job_manager_request_log(
                request,
                "gass_cache location: %s\n",
                request->config->cache_location);

        rc = globus_gram_job_manager_rsl_eval_string(
                request,
                request->config->cache_location,
                cache_locationp);

        if(rc != GLOBUS_SUCCESS)
        {
            goto failed_cache_eval;
        }
        globus_gram_job_manager_request_log(
                request,
                "gass_cache location (post-eval): %s\n",
                *cache_locationp);
    }
    else
    {
        /* I'd like to use GASS-default location for the cache for this, 
         * but we can't rely on being able to set the environment and having
         * it remain valid if multiple jobs are being processed. Instead, we'll
         * force it to what the library would do anyway.
         */
        *cache_locationp = globus_common_create_string(
                "%s/.globus/gass_cache",
                request->config->home);
    }

    rc = globus_gass_cache_open(*cache_locationp, cache_handlep);
    if(rc != GLOBUS_SUCCESS)
    {
        if (*cache_locationp)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_CACHE;
        }
        else
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE;
        }

        goto failed_cache_open;
    }
failed_cache_open:
        if (*cache_locationp)
        {
            free(*cache_locationp);
            *cache_locationp = NULL;
        }
failed_cache_eval:
    return rc;
}
/* globus_l_gram_init_cache() */

static
int
globus_l_gram_restart(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_t **                     stdout_position_hack,
    globus_rsl_t **                     stderr_position_hack)
{
    int                                 rc;
    globus_rsl_t *                      restart_rsl;
    globus_rsl_t *                      original_rsl;

    rc = globus_rsl_eval(request->rsl, &request->symbol_table);
    if(rc != GLOBUS_SUCCESS)
    {
        request->failure_code =
            GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
        goto rsl_eval_failed;
    }

    rc = globus_gram_job_manager_validate_rsl(
            request,
            GLOBUS_GRAM_VALIDATE_JOB_MANAGER_RESTART);
    if(rc != GLOBUS_SUCCESS)
    {
        goto rsl_validate_failed;
    }
    /*
     * Eval after validating, as validation may insert
     * RSL substitions when processing default values of
     * RSL attributes
     */
    rc = globus_rsl_eval(request->rsl, &request->symbol_table);
    if(rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
        goto post_validate_eval_failed;
    }

    /* Free the restart RSL spec. Make room for the job
     * request RSL which we'll read from the state file
     */
    free(request->rsl_spec);
    request->rsl_spec = NULL;

    /* Remove the restart parameter from the RSL spec. */
    globus_gram_job_manager_rsl_remove_attribute(
            request,
            GLOBUS_GRAM_PROTOCOL_RESTART_PARAM);

    /* Read the job state file. This has all sorts of side-effects on
     * the request structure
     */
    rc = globus_gram_job_manager_state_file_read(request);
    if(rc != GLOBUS_SUCCESS)
    {
        goto state_file_read_failed;
    }

    globus_gram_job_manager_request_log(
        request,
        "Pre-parsed Original RSL string: %s\n",
        request->rsl_spec);

    original_rsl = globus_rsl_parse(request->rsl_spec);
    if (!original_rsl)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
        goto parse_original_rsl_failed;
    }

    restart_rsl = request->rsl;

    request->rsl = original_rsl;

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
    *stdout_position_hack =
        globus_gram_job_manager_rsl_extract_relation(
            restart_rsl,
            GLOBUS_GRAM_PROTOCOL_STDOUT_POSITION_PARAM);

    *stderr_position_hack = 
        globus_gram_job_manager_rsl_extract_relation(
            restart_rsl,
            GLOBUS_GRAM_PROTOCOL_STDERR_POSITION_PARAM);

    request->rsl = globus_gram_job_manager_rsl_merge(
                original_rsl,
                restart_rsl);

    if(request->rsl == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }
parse_original_rsl_failed:
state_file_read_failed:
post_validate_eval_failed:
rsl_validate_failed:
rsl_eval_failed:
    return rc;
}
/* globus_l_gram_restart() */

/**
 * Add default environment variables to the job environment
 *
 * Adds GLOBUS_GASS_CACHE_DEFAULT, LOGNAME, HOME, and anything that
 * is defined from the -extra-envar command-line option.
 * 
 * @param request
 *     Request to modify
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
 *     Malloc failed.
 */
static
int
globus_l_gram_populate_environment(
    globus_gram_jobmanager_request_t *  request)
{
    int                                 rc;

    rc = globus_l_gram_add_environment(
            request->rsl,
            "GLOBUS_GASS_CACHE_DEFAULT",
            request->cache_location);

    if (rc != GLOBUS_SUCCESS)
    {
        goto add_cache_default_failed;
    }

    rc = globus_l_gram_add_environment(
            request->rsl,
            "LOGNAME",
            request->config->logname);
    if (rc != GLOBUS_SUCCESS)
    {
        goto add_logname_failed;
    }

    rc = globus_l_gram_add_environment(
            request->rsl,
            "HOME",
            request->config->home);
    if (rc != GLOBUS_SUCCESS)
    {
        goto add_home_failed;
    }

    if (request->config->x509_cert_dir)
    {
        rc = globus_l_gram_add_environment(
                request->rsl,
                "X509_CERT_DIR",
                request->config->x509_cert_dir);
        if (rc != GLOBUS_SUCCESS)
        {
            goto add_x509_cert_dir_failed;
        }
    }

    rc = globus_l_gram_add_environment(
            request->rsl,
            "GLOBUS_GRAM_JOB_CONTACT",
            request->job_contact);
    if (rc != GLOBUS_SUCCESS)
    {
        goto add_gram_job_contact_failed;
    }

    rc = globus_l_gram_add_environment(
            request->rsl,
            "GLOBUS_LOCATION",
            request->config->target_globus_location);
    if (rc != GLOBUS_SUCCESS)
    {
        goto add_globus_location_failed;
    }

    if (request->config->tcp_port_range)
    {
        rc = globus_l_gram_add_environment(
                request->rsl,
                "GLOBUS_TCP_PORT_RANGE",
                request->config->tcp_port_range);
        if (rc != GLOBUS_SUCCESS)
        {
            goto add_tcp_port_range_failed;
        }
    }

    if (request->remote_io_url_file)
    {
        rc = globus_l_gram_add_environment(
                request->rsl,
                "GLOBUS_REMOTE_IO_URL",
                request->remote_io_url_file);
        if (rc != GLOBUS_SUCCESS)
        {
            goto add_remote_io_url_file;
        }
    }

    if (request->x509_user_proxy)
    {
        rc = globus_l_gram_add_environment(
                request->rsl,
                "X509_USER_PROXY",
                request->x509_user_proxy);
        if (rc != GLOBUS_SUCCESS)
        {
            goto add_x509_user_proxy_failed;
        }
    }
    if (request->config->extra_envvars)
    {
        char *  p = request->config->extra_envvars;
        while (p && *p)
        {
            char * val = NULL;
            char * q   = strchr(p,',');
            if (q) *q = '\0';
            if (*p && (val = getenv(p)))
            {
                globus_gram_job_manager_request_log(
                        request,
                        "Appending extra env.var %s=%s\n",
                        p,
                        val);
                rc = globus_l_gram_add_environment(
                        request->rsl,
                        p,
                        val);

                if (rc != GLOBUS_SUCCESS)
                {
                    goto add_extra_envvar_failed;
                }
            }
            p = (q) ? q+1 : NULL;
        }
    }

add_extra_envvar_failed:
add_x509_user_proxy_failed:
add_remote_io_url_file:
add_tcp_port_range_failed:
add_globus_location_failed:
add_gram_job_contact_failed:
add_x509_cert_dir_failed:
add_home_failed:
add_logname_failed:
add_cache_default_failed:
    return rc;
}
/* globus_l_gram_populate_environment() */

/**
 * Add an environment variable to the job environment
 * 
 * @param rsl
 *     RSL to modify
 * @param variable
 *     Environment variable name
 * @param value
 *     Environment variable value. If NULL, this variable is ignored.
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
 *     Malloc failed.
 */
static
int
globus_l_gram_add_environment(
    globus_rsl_t *                      rsl,
    const char *                        variable,
    const char *                        value)
{
    int                                 rc = GLOBUS_SUCCESS;
    if (value != NULL)
    {
        rc = globus_gram_job_manager_rsl_env_add(
                rsl,
                variable,
                value);
        if (rc != 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        }
    }
    return rc;
}
/* globus_l_gram_add_environment() */

/**
 * Initialize the scratchdir member of the job request if needed
 *
 * As a side effect, the path named by scratchdir will be created and
 * variable SCRATCH_DIRECTORY will be added to both the symbol table and
 * the job environment.
 *
 * @param request
 *     Request to act on.
 * @param rsl
 *     RSL to check for "scratchdir" attribute
 * @param scratch_dir_base
 *     Job-specific scratch_dir_base
 * @param scratchdir
 *     Pointer to set to the new scratchdir
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SCRATCH
 *     Invalid scratchdir RSL attribute
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRATCH
 *     Invalid scratchdir path
 */
static
int
globus_l_gram_init_scratchdir(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_t *                      rsl,
    const char *                        scratch_dir_base,
    char **                             scratchdir)
{
    int                                 rc = GLOBUS_SUCCESS;
    char *                              dir;
    char *                              template;
    int                                 i;
    int                                 created = 0;
    enum { GLOBUS_GRAM_MKDIR_TRIES = 100 };
    /* In the case of a restart, this might have already been done */
    if (request->jm_restart && request->scratchdir != NULL)
    {
        return rc;
    }
    if (! globus_gram_job_manager_rsl_attribute_exists(
            rsl,
            GLOBUS_GRAM_PROTOCOL_SCRATCHDIR_PARAM))
    {
        *scratchdir = NULL;
        return rc;
    }

    globus_gram_job_manager_request_log(
            request,
            "Evaluating scratch directory RSL\n");

    rc = globus_gram_job_manager_rsl_eval_one_attribute(
            request,
            GLOBUS_GRAM_PROTOCOL_SCRATCHDIR_PARAM,
            &dir);
    if(rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_request_log(
                request,
                "Evaluation of scratch directory RSL failed\n");
        goto eval_scratchdir_failed;
    }
    else if (dir == NULL)
    {
        globus_gram_job_manager_request_log(
                request,
                "Evaluation of scratch directory RSL didn't "
                "yield string\n");
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SCRATCH;
        goto eval_scratchdir_failed;
    }
    globus_gram_job_manager_request_log(
            request,
            "Scratch Directory RSL -> %s\n",
            dir);

    if (dir[0] == '/')
    {
        template = globus_common_create_string(
                "%s",
                dir);
    }
    else 
    {
        template = globus_common_create_string(
                "%s/%s",
                scratch_dir_base,
                dir);
    }
    if (template == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto template_malloc_failed;
    }

    for (i = 0, created = 0; i < GLOBUS_GRAM_MKDIR_TRIES && !created; i++)
    {
        *scratchdir = tempnam(template, "gram_scratch_");

        if (mkdir(*scratchdir, S_IRWXU) != 0)
        {
            if (errno != EEXIST && errno != EINTR)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRATCH;
                goto fatal_mkdir_err;
            }
            else
            {
                free(*scratchdir);
                *scratchdir = NULL;
            }
        }
        else
        {
            created = 1;
        }
    }

    if (*scratchdir == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRATCH;
        goto fatal_mkdir_err;
    }

    rc = globus_symboltable_insert(
            &request->symbol_table,
            "SCRATCH_DIRECTORY",
            *scratchdir);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto insert_symbol_failed;
    }

    rc = globus_l_gram_add_environment(
            request->rsl,
            "SCRATCH_DIRECTORY",
            *scratchdir);
    if (rc != GLOBUS_SUCCESS)
    {
        goto add_environment_failed;
    }

    if (rc != GLOBUS_SUCCESS)
    {
add_environment_failed:
        globus_symboltable_remove(
                &request->symbol_table,
                "SCRATCH_DIRECTORY");
insert_symbol_failed:
        rmdir(*scratchdir);
fatal_mkdir_err:
        free(*scratchdir);
        *scratchdir = NULL;
    }
    /* Always free these intermediate values */
    free(template);
template_malloc_failed:
    free(dir);
eval_scratchdir_failed:
    return rc;
}
/* globus_l_gram_init_scratchdir() */

/**
 * Remove the scratchdir and all of its contents
 * 
 * @param request
 *     Request related to this scratch directory.
 * @param scratchdir
 *     Scratch directory to remove.
 */
static
void
globus_l_gram_destroy_scratchdir(
    globus_gram_jobmanager_request_t *  request,
    const char *                        scratchdir)
{
    int                                 rc;

    if (!scratchdir)
    {
        return;
    }

    rc = nftw(scratchdir, globus_l_gram_nftw_func, 5, FTW_DEPTH|FTW_MOUNT);

    if (rc != 0)
    {
        globus_gram_job_manager_request_log(
                request,
                "Error walking scratchdir tree for removal\n");
    }
}
/* globus_l_gram_destroy_scratchdir() */

static
int
globus_l_gram_nftw_func(
    const char *                        pathname,
    const struct stat *                 stat,
    int                                 info,
    struct FTW *                        ftw_struct)
{
    switch (info)
    {
    case FTW_F:
    case FTW_SL:
    case FTW_SLN:
        remove(pathname);
        break;
    case FTW_D:
    case FTW_DP:
        if (strcmp(pathname, ".") != 0 && strcmp(pathname, "..") != 0)
        {
            rmdir(pathname);
        }
        break;
    case FTW_DNR:
    case FTW_NS:
        break;
    }
    return 0;
}
/* globus_l_gram_nftw_func() */

/**
 * Evaluate and validate the job RSL
 * 
 * As a side-effect, if stdout_position_hack or stderr_position_hack are
 * non-NULL, they will be either moved into the request's job RSL or
 * freed.
 *
 * @param request
 *     Job request to validate
 * @param stdout_position_hack
 *     Replacement for stdout position if the job is a restart job
 * @param stderr_position_hack
 *     Replacement for stderr position if the job is a restart job
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED
 *     RSL evaluation failed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL
 *     Invalid RSL.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_PARAMETER_NOT_SUPPORTED
 *     RSL attribute not supported.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SUBMIT_ATTRIBUTE
 *     Invalid submit RSL attribute.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_RESTART_ATTRIBUTE;
 *     Invalid restart RSL attribute.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_STDIO_UPDATE_ATTRIBUTE;
 *     Invalid stdio_update RSL attribute.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
 *     Malloc failed.
 */
static
int
globus_l_gram_validate_rsl(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_t *                      stdout_position_hack,
    globus_rsl_t *                      stderr_position_hack)
{
    int                                 rc = GLOBUS_SUCCESS;

    rc = globus_rsl_eval(request->rsl, &request->symbol_table);
    if(rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
        goto rsl_eval_failed;
    }
    rc = globus_gram_job_manager_validate_rsl(
            request,
            GLOBUS_GRAM_VALIDATE_JOB_SUBMIT);
    if(rc != GLOBUS_SUCCESS)
    {
        goto validate_rsl_failed;
    }
    /*
     * Insert stdout_position and stderr_position back to rsl if they were
     * present in restart RSL
     */
    if (stdout_position_hack != NULL)
    {
        rc = globus_gram_job_manager_rsl_add_relation(
            request->rsl,
            stdout_position_hack);

        if (rc != GLOBUS_SUCCESS)
        {
            goto add_stdout_position_failed;
        }
        stdout_position_hack = NULL;
    }
    if (stderr_position_hack != NULL)
    {
        rc = globus_gram_job_manager_rsl_add_relation(
            request->rsl,
            stderr_position_hack);
        if (rc != GLOBUS_SUCCESS)
        {
            goto add_stderr_position_failed;
        }
        stderr_position_hack = NULL;
    }

    rc = globus_rsl_eval(request->rsl, &request->symbol_table);
    if(rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED;
        goto rsl_eval_failed2;
    }

rsl_eval_failed2:
add_stderr_position_failed:
add_stdout_position_failed:
validate_rsl_failed:
rsl_eval_failed:
    if (stdout_position_hack)
    {
        globus_rsl_free_recursive(stdout_position_hack);
    }
    if (stderr_position_hack)
    {
        globus_rsl_free_recursive(stderr_position_hack);
    }
    return rc;
}
/* globus_l_gram_validate_rsl() */

/**
 * Create remote_io_url file in the job directory
 *
 * @param request
 *     Request to log messages for
 * @param remote_io_url
 *     Value to write to the remote_io_url file
 * @param remote_io_url_filep
 *     Pointer to be set to the remote_io_url_file path upon success.
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_RSL_REMOTE_IO_URL
 *     Unable to create remote_io_url file.
 */
static
int
globus_l_gram_remote_io_url_file_create(
    globus_gram_jobmanager_request_t *  request,
    const char *                        remote_io_url,
    const char *                        job_dir,
    char **                             remote_io_url_filep)
{
    int                                 rc = GLOBUS_SUCCESS;
    FILE *                              fp;

    if (!remote_io_url)
    {
        *remote_io_url_filep = NULL;
        goto out;
    }

    globus_gram_job_manager_request_log(
            request,
            "creating remote_io_url file for %s\n",
            remote_io_url);

    *remote_io_url_filep = globus_common_create_string(
                "%s/remote_io_file",
                job_dir);
    if (remote_io_url_filep == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto set_remote_io_url_file_failed;
    }
    fp = fopen(*remote_io_url_filep, "w");
    if (fp == NULL)
    {
        globus_gram_job_manager_request_log(
                request,
                "error opening remote_io_url_file %s\n",
                *remote_io_url_filep);
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_REMOTE_IO_URL;
        goto fopen_failed;
    }

    globus_gram_job_manager_request_log(
            request,
            "writing remote_io_url to %s\n",
            *remote_io_url_filep);
    rc = fprintf(fp, "%s\n", remote_io_url);
    if (rc < (1+strlen(remote_io_url)))
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_REMOTE_IO_URL;
    }
    rc = GLOBUS_SUCCESS;

    fclose(fp);
    if (rc != GLOBUS_SUCCESS)
    {
fopen_failed:
        free(*remote_io_url_filep);
        *remote_io_url_filep = NULL;
    }
set_remote_io_url_file_failed:
out:
    return rc;
}
/* globus_l_gram_remote_io_url_file_create() */

static
int
globus_l_gram_export_cred(
    globus_gram_jobmanager_request_t *  request,
    gss_cred_id_t                       cred,
    const char *                        job_directory,
    char **                             proxy_filename)
{
    OM_uint32                           major_status, minor_status;
    char *                              filename = NULL;
    FILE *                              file;
    gss_buffer_desc                     buffer;
    int                                 rc = GLOBUS_SUCCESS;

    if (cred == GSS_C_NO_CREDENTIAL)
    {
        goto no_cred;
    }
    major_status = gss_export_cred(
            &minor_status,
            cred,
            GSS_C_NO_OID,
            0,
            &buffer);

    if (GSS_ERROR(major_status))
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
        goto export_cred_failed;
    }

    filename = globus_common_create_string(
            "%s/x509_user_proxy",
            job_directory);
    if (filename == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto malloc_filename_failed;
    }

    file = fopen(filename, "w");
    if (file == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
        goto fopen_failed;
    }

    rc = fwrite(buffer.value, 1, buffer.length, file);
    if (rc < buffer.length)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY;
        goto fwrite_failed;
    }
    rc = GLOBUS_SUCCESS;

fwrite_failed:
    fclose(file);
fopen_failed:
    if (rc != GLOBUS_SUCCESS)
    {
        free(filename);
        filename = NULL;
    }
malloc_filename_failed:
    gss_release_buffer(&minor_status, &buffer);
export_cred_failed:
no_cred:
    *proxy_filename = filename;

    return rc;
}
/* globus_l_gram_export_cred() */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
