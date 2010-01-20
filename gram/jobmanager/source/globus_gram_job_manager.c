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
 * @file globus_gram_job_manager.c LRM-Specific state
 *
 * CVS Information:
 * 
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */

#include "globus_common.h"
#include "globus_gram_job_manager.h"

/* This value (in seconds) is the length of time after a job hits a waiting
 * for SEG state before freeing its memory
 */
static int globus_l_gram_swap_out_delay = 10;
/*
 * This value (in seconds) is the length of time after all jobs have been
 * completed that the job manager will terminate
 */
static int globus_l_gram_grace_period_delay = 60;

typedef struct globus_gram_job_id_ref_s
{
    /* Local copy of the unique job id used as the key to the job_id_hash */
    char *                              job_id;
    /* Local copy of the request job_contact_path */
    char *                              job_contact_path;
}
globus_gram_job_id_ref_t;

static
int
globus_l_gram_mkdir(
    char *                              path);


static
void
globus_l_gram_job_manager_grace_period_expired(
    void *                              arg);


static
void
globus_l_gram_ref_swap_out(
    void *                              arg);

static
int
globus_l_gram_add_reference_locked(
    globus_gram_job_manager_t *         manager,
    const char *                        key,
    const char *                        reason,
    globus_gram_jobmanager_request_t ** request);


static
int
globus_l_gram_restart_job(
    globus_gram_job_manager_t *         manager,
    globus_gram_jobmanager_request_t ** request,
    const char *                        job_contact_path);

static
int
globus_l_gram_read_job_manager_cred(
    globus_gram_job_manager_t *         manager,
    const char *                        cred_path,
    gss_cred_id_t *                     cred);
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * Initialize runtime state associated with a LRM instance
 *
 * @param manager
 *     Job manager structure to initialize
 * @param cred
 *     Credential to use for this job manager.
 * @param config
 *     Configuration parameters defining this service instance
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_REQUEST
 *     Invalid request.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES
 *     No resources.
 */
int
globus_gram_job_manager_init(
    globus_gram_job_manager_t *         manager,
    gss_cred_id_t                       cred,
    globus_gram_job_manager_config_t *  config)
{
    int                                 rc;
    char *                              dir_prefix = NULL;

    if (manager == NULL || config == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto out;
    }
    
    manager->usagetracker = NULL;
    manager->config = config;
    manager->stop = GLOBUS_FALSE;

    rc = globus_mutex_init(&manager->mutex, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        goto mutex_init_failed;
    }
    rc = globus_cond_init(&manager->cond, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        goto cond_init_failed;
    }
    /* Lock this, as we might have callbacks happen in the allow attach and
     * proxy timeout code before we finish initializing everything
     */
    GlobusGramJobManagerLock(manager);

    manager->seg_last_timestamp = 0;
    manager->seg_started = GLOBUS_FALSE;

    rc = globus_gram_job_manager_validation_init(manager);
    if (rc != GLOBUS_SUCCESS)
    {
        goto validation_init_failed;
    }

    rc = globus_hashtable_init(
            &manager->request_hash,
            89,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto request_hashtable_init_failed;
    }

    rc = globus_hashtable_init(
            &manager->job_id_hash,
            89,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto job_id_hashtable_init_failed;
    }
    dir_prefix = globus_common_create_string(
            "%s/.globus/job/%s",
            manager->config->home,
            manager->config->hostname);
    if (dir_prefix == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto malloc_dir_prefix_failed;
    }
    rc = globus_l_gram_mkdir(dir_prefix);
    if (rc != GLOBUS_SUCCESS)
    {
        goto mkdir_failed;
    }

    manager->cred_path = globus_common_create_string(
            "%s/%s.%s.cred",
            dir_prefix,
            manager->config->jobmanager_type,
            manager->config->service_tag);
    if (manager->cred_path == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto malloc_cred_path_failed;
    }

    if (cred == GSS_C_NO_CREDENTIAL)
    {
        rc = globus_l_gram_read_job_manager_cred(
                manager,
                manager->cred_path,
                &cred);
        if (rc != GLOBUS_SUCCESS)
        {
            goto read_credentials_failed;
        }
    }

    rc = globus_gram_protocol_set_credentials(cred);
    if (rc != GLOBUS_SUCCESS)
    {
        goto set_credentials_failed;
    }
    rc = globus_gram_protocol_allow_attach(
            &manager->url_base,
            globus_gram_job_manager_query_callback,
            manager);
    if (rc != GLOBUS_SUCCESS)
    {
        goto allow_attach_failed;
    }

    GlobusGramJobManagerLock(manager);
    if (cred != GSS_C_NO_CREDENTIAL)
    {
        manager->cred_expiration_time = 1;
        rc = globus_gram_job_manager_gsi_register_proxy_timeout(
                manager,
                cred,
                manager->config->proxy_timeout,
                &manager->proxy_expiration_timer);

        if (rc != GLOBUS_SUCCESS)
        {
            goto proxy_timeout_init_failed;
        }
    }
    else
    {
        manager->proxy_expiration_timer = GLOBUS_NULL_HANDLE;
    }

    manager->active_job_manager_handle = NULL;
    manager->socket_fd = -1;
    manager->lock_fd = -1;
    manager->lock_path = globus_common_create_string(
            "%s/%s.%s.lock",
            dir_prefix,
            manager->config->jobmanager_type,
            manager->config->service_tag);
    if (manager->lock_path == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto malloc_lock_path_failed;
    }

    manager->socket_path = globus_common_create_string(
            "%s/%s.%s.sock",
            dir_prefix,
            manager->config->jobmanager_type,
            manager->config->service_tag);
    if (manager->socket_path == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto malloc_socket_path_failed;
    }

    manager->pid_path = globus_common_create_string(
            "%s/%s.%s.pid",
            dir_prefix,
            manager->config->jobmanager_type,
            manager->config->service_tag);
    if (manager->pid_path == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto malloc_pid_path_failed;
    }

    rc = globus_fifo_init(&manager->script_fifo);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto script_fifo_init_failed;
    }

    /* Default number of scripts which can be run simultaneously */
    manager->script_slots_available = 5;

    rc = globus_fifo_init(&manager->script_handles);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto script_handles_fifo_init_failed;
    }

    rc = globus_fifo_init(&manager->state_callback_fifo);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto state_callback_fifo_init_failed;
    }
    /* Default number of job state callback notifications that can
     * occur simultaneously
     */
    manager->state_callback_slots = 5;

    GlobusGramJobManagerUnlock(manager);

    free(dir_prefix);

    manager->done = GLOBUS_FALSE;
    manager->grace_period_timer = GLOBUS_NULL_HANDLE;

    manager->seg_pause_count = 0;
    rc = globus_fifo_init(&manager->seg_event_queue);

    manager->usagetracker = 
        globus_calloc(1, sizeof(globus_i_gram_usage_tracker_t));   

    if (rc != GLOBUS_SUCCESS)
    {
state_callback_fifo_init_failed:
        globus_fifo_destroy(&manager->script_handles);
script_handles_fifo_init_failed:
        globus_fifo_destroy(&manager->script_fifo);
script_fifo_init_failed:
        free(manager->pid_path);
        manager->pid_path = NULL;
malloc_pid_path_failed:
        free(manager->socket_path);
        manager->socket_path = NULL;
malloc_socket_path_failed:
        free(manager->lock_path);
        manager->lock_path = NULL;
malloc_lock_path_failed:
proxy_timeout_init_failed:
        globus_gram_protocol_callback_disallow(manager->url_base);
        free(manager->url_base);
allow_attach_failed:
set_credentials_failed:
read_credentials_failed:
        free(manager->cred_path);
        manager->cred_path = NULL;
malloc_cred_path_failed:
mkdir_failed:
        free(dir_prefix);
        dir_prefix = NULL;
malloc_dir_prefix_failed:
        globus_hashtable_destroy(&manager->job_id_hash);
job_id_hashtable_init_failed:
        globus_hashtable_destroy(&manager->request_hash);
request_hashtable_init_failed:
        globus_gram_job_manager_validation_destroy(
                manager->validation_records);
        manager->validation_records = NULL;
        
validation_init_failed:
        globus_cond_destroy(&manager->mutex);
cond_init_failed:
        GlobusGramJobManagerUnlock(manager);
        globus_mutex_destroy(&manager->mutex);
mutex_init_failed:
        ;
    }

out:
    return rc;
}
/* globus_gram_job_manager_init() */

/**
 * Destroy job manager state
 * 
 * Memory used for runtime processing is freed, the GRAM listener and the SEG
 * are shut down.
 * 
 * @param manager
 *     Manager to destroy
 */
void
globus_gram_job_manager_destroy(
    globus_gram_job_manager_t *         manager)
{
    if (!manager)
    {
        return;
    }
    globus_gram_job_manager_shutdown_seg(manager->config->seg_module);

    globus_gram_protocol_callback_disallow(manager->url_base);
    free(manager->url_base);
    manager->url_base = NULL;


    globus_gram_job_manager_validation_destroy(
            manager->validation_records);
    manager->validation_records = NULL;
    
    globus_hashtable_destroy(&manager->request_hash);

    globus_fifo_destroy(&manager->state_callback_fifo);
    globus_fifo_destroy(&manager->script_fifo);
    globus_fifo_destroy(&manager->script_handles);
    
    if(manager->usagetracker)
    {
        free(manager->usagetracker);
    }
                              
    return;
}
/* globus_gram_job_manager_destroy() */

void
globus_gram_job_manager_log(
    globus_gram_job_manager_t *         manager,
    globus_gram_job_manager_log_level_t level,
    const char *                        format,
    ...)
{
    va_list                             ap;
    time_t                              now;
    struct tm *                         nowtm;
    globus_bool_t                       logged = GLOBUS_FALSE;

    if (globus_i_gram_job_manager_log_sys != NULL)
    {
        va_start(ap, format);
        globus_logging_vwrite(
                globus_i_gram_job_manager_log_sys,
                level,
                format,
                ap);
        va_end(ap);
        logged = GLOBUS_TRUE;
    }

    if (globus_i_gram_job_manager_log_stdio != NULL)
    {
        va_start(ap, format);
        globus_logging_vwrite(
                globus_i_gram_job_manager_log_stdio,
                level,
                format,
                ap);
        va_end(ap);
        logged = GLOBUS_TRUE;
    }
    
    if (!logged)
    {
        /* Hack to write to stderr in the case the error happens before we
         * have parsed command-line options to figure out where log messages
         * ought to go
         */
        now = time(NULL);
        nowtm = gmtime(&now);
        fprintf(stderr, "ts=%04d-%02d-%02dT%02d:%02d:%02dZ id=%lu ",
                nowtm->tm_year + 1900,
                nowtm->tm_mon + 1,
                nowtm->tm_mday,
                nowtm->tm_hour,
                nowtm->tm_min,
                nowtm->tm_sec,
                (unsigned long) getpid());

        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);
    }
}
/* globus_gram_job_manager_log() */

/**
 * Add a job request to a reference-counting hashtable
 *
 * Adds the job request to the reference-counting hashtable with an initial
 * reference count of 0. Calls to globus_gram_job_manager_add_reference() and
 * globus_gram_job_manager_remove_reference() will increase and decrease the
 * reference count. Callbacks and job status queries, etc should call those
 * to dereference the job's unique key to a pointer to a
 * globus_gram_jobmanager_request_t structure and then release that reference
 * when the callback has been completely processed.
 * If at any time the reference count equals 0, it becomes a candidate to be
 * swapped out of memory. This can happen when the job is being processed,
 * after a submit to LRM but while waiting for the SEG to change
 * state. When the job is completed and the reference count equals 0, the
 * job reference stub is removed.
 *
 * @param manager
 *     Job manager state
 * @param key
 *     String key that uniquely identifies the job request
 * @param request
 *     Request to add to manager's set of requests
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed.
 *
 */
int
globus_gram_job_manager_add_request(
    globus_gram_job_manager_t *         manager,
    const char *                        key,
    globus_gram_jobmanager_request_t *  request)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_gram_job_manager_ref_t *     ref;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.add_request.start "
            "level=TRACE "
            "gramid=%s "
            "\n",
            key);

    GlobusGramJobManagerLock(manager);
    if (manager->stop)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.add_request.end "
                "level=WARN "
                "gramid=%s "
                "status=%d "
                "reason=\"%s\" "
                "\n",
                key,
                -rc,
                globus_gram_protocol_error_string(rc));

        goto stop;
    }

    ref = globus_hashtable_lookup(&manager->request_hash, (void *) key);
    if (ref != NULL)
    {
        if (ref->request != NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE;

            goto ref_already_exists;
        }
        else
        {
            ref->request = request;
            goto ref_already_exists;
        }
    }

    ref = malloc(sizeof(globus_gram_job_manager_ref_t));
    if (ref == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.add_request.end "
                "level=ERROR "
                "gramid=%s "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                key,
                -rc,
                globus_gram_protocol_error_string(rc),
                errno,
                strerror(errno));
        goto ref_malloc_failed;
    }
    ref->manager = manager;
    ref->cleanup_timer = GLOBUS_NULL_HANDLE;
    ref->job_state = request->status;
    ref->failure_code = request->failure_code;
    ref->exit_code = request->exit_code;
    ref->status_count = 0;

    ref->key = strdup(key);
    if (ref->key == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.add_request.end "
                "level=ERROR "
                "gramid=%s "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                key,
                -rc,
                globus_gram_protocol_error_string(rc),
                errno,
                strerror(errno));
        goto key_malloc_failed;
    }

    ref->request = request;
    ref->reference_count = 0;

    rc = globus_hashtable_insert(
            &manager->request_hash,
            ref->key,
            ref);

ref_already_exists:
    if(rc == GLOBUS_SUCCESS)
    {
        manager->usagetracker->count_current_jobs++;

        if(manager->usagetracker->count_peak_jobs < 
            manager->usagetracker->count_current_jobs)
        {
            manager->usagetracker->count_peak_jobs = 
                manager->usagetracker->count_current_jobs;
        }
    }

    if (rc != GLOBUS_SUCCESS)
    {
        if (globus_hashtable_lookup(
                &manager->request_hash,
                ref->key) == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        }
        else
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE;
        }

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.add_request.end "
                "level=ERROR "
                "gramid=%s "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                key,
                -rc,
                "Error inserting request into hashtable",
                globus_gram_protocol_error_string(rc));

        goto insert_failed;
    }
    if (manager->grace_period_timer != GLOBUS_NULL_HANDLE)
    {
        globus_callback_unregister(
                manager->grace_period_timer,
                NULL,
                NULL,
                NULL);

        if (manager->done)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED;

            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                    "event=gram.add_request.end "
                    "level=WARN "
                    "gramid=%s "
                    "status=%d "
                    "msg=\"%s\" "
                    "reason=\"%s\" "
                    "\n",
                    key,
                    -rc,
                    "Manager is exiting",
                    globus_gram_protocol_error_string(rc));
            goto grace_period_expired;
        }
        manager->grace_period_timer = GLOBUS_NULL_HANDLE;
    }
    if (rc != GLOBUS_SUCCESS)
    {
insert_failed:
grace_period_expired:
        free(ref->key);
key_malloc_failed:
        free(ref);
ref_malloc_failed:
stop:
        ;
    }
    else
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.add_request.end "
                "level=TRACE "
                "gramid=%s "
                "status=%d "
                "\n",
                key,
                0);
    }
    GlobusGramJobManagerUnlock(manager);
    return rc;
}
/* globus_gram_job_manager_add_request() */

/**
 * Add a reference to a job request based on its unique key identifier
 *
 * Looks up a job request in the manager's request table and returns it in
 * the value pointed to by @a request. The caller must make a corresponding
 * call to globus_gram_job_manager_remove_reference() for each time this
 * or globus_gram_job_manager_add_request() is called for a particular job
 * request.
 *
 * @param manager
 *     Job manager state
 * @param key
 *     String key that uniquely identifies the job request
 * @param reason
 *     String describing why the reference is being added for logging
 * @param request
 *     Pointer to be set to the corresponding job request if found in the
 *     table. May be NULL if the caller already has a reference and wants to
 *     add one.
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND
 *     Job contact not found.
 */
int
globus_gram_job_manager_add_reference(
    globus_gram_job_manager_t *         manager,
    const char *                        key,
    const char *                        reason,
    globus_gram_jobmanager_request_t ** request)
{
    int                                 rc = GLOBUS_SUCCESS;

    GlobusGramJobManagerLock(manager);
    rc = globus_l_gram_add_reference_locked(
            manager,
            key,
            reason,
            request);
    GlobusGramJobManagerUnlock(manager);

    return rc;
}
/* globus_gram_job_manager_add_reference() */

/**
 * Remove a reference to a job request based on its unique key identifier
 *
 * Looks up a job request in the manager's request table and dereferences its
 * reference count. When the reference count reaches 0, also removes
 * the request from the request table destroys it.
 *
 * @param manager
 *     Job manager state
 * @param key
 *     String key that uniquely identifies the job request
 * @param reason
 *     String describing why the reference is being removed.
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND
 *     Job contact not found.
 */
int
globus_gram_job_manager_remove_reference(
    globus_gram_job_manager_t *         manager,
    const char *                        key,
    const char *                        reason)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_gram_jobmanager_request_t *  request = NULL;
    globus_gram_job_manager_ref_t *     ref;
    char                                gramid[64];

    strncpy(gramid, key, sizeof(gramid));

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.remove_reference.start "
            "level=TRACE "
            "gramid=%s "
            "reason=\"%s\" "
            "\n",
            key,
            reason);

    GlobusGramJobManagerLock(manager);
    ref = globus_hashtable_lookup(&manager->request_hash, (void *) key);
    if (ref)
    {
        ref->reference_count--;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.remove_reference.info "
                "level=TRACE "
                "gramid=%s "
                "refcount=%d "
                "reason=\"%s\" "
                "\n",
                key,
                ref->reference_count,
                reason);

        if (ref->reference_count == 0)
        {
            /* Don't need to lock the request here---nothing else
             * refers to it
             */
            request = ref->request;

            /* If the request is complete we can destroy it
             */
            if (request->jobmanager_state ==
                    GLOBUS_GRAM_JOB_MANAGER_STATE_DONE ||
                request->jobmanager_state ==
                    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE)
            {
                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                        "event=gram.remove_reference.info "
                        "level=TRACE "
                        "gramid=%s "
                        "refcount=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\" "
                        "\n",
                        key,
                        ref->reference_count,
                        "Freeing state for unreferenced, completed job",
                        reason);

                globus_hashtable_remove(
                        &manager->request_hash,
                        (void *) key);
                if (globus_hashtable_empty(&manager->request_hash))
                {
                    if (manager->stop)
                    {
                        globus_gram_job_manager_log(
                                manager,
                                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                                "event=gram.remove_reference.info "
                                "level=TRACE "
                                "msg=\"%s\" "
                                "\n",
                                "No jobs remain, stopping job manager",
                                reason);
                        manager->done = GLOBUS_TRUE;
                        globus_cond_signal(&manager->cond);
                    }
                    else
                    {
                        globus_gram_job_manager_log(
                                manager,
                                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                                "event=gram.remove_reference.info "
                                "level=TRACE "
                                "msg=\"%s\" "
                                "\n",
                                "No jobs remain, setting job manager termination timer");
                        globus_gram_job_manager_set_grace_period_timer(manager);
                    }
                }

                globus_gram_job_manager_request_destroy(ref->request);
                free(ref->request);
                free(ref->key);
                free(ref);
            }
            /* If we're waiting for a SEG event or stopped in a way that we
             * know the job is completed, we can swap the job out
             */
            else if ((request->jobmanager_state ==
                        GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2 &&
                    request->config->seg_module &&
                    request->manager->seg_started &&
                    request->jobmanager_state !=
                        GLOBUS_GRAM_JOB_MANAGER_STATE_STOP) ||
                     (request->jobmanager_state == 
                        GLOBUS_GRAM_JOB_MANAGER_STATE_STOP &&
                        (manager->stop == GLOBUS_TRUE ||
                         manager->seg_started == GLOBUS_FALSE || 
                         request->restart_state == GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END ||
                  request->restart_state == GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE)))
            {
                globus_reltime_t        delay;
                globus_result_t         result;

                /* We can swap out if we waiting for SEG events */
                GlobusTimeReltimeSet(delay, globus_l_gram_swap_out_delay, 0);
                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                        "event=gram.remove_reference.info "
                        "level=TRACE "
                        "gramid=%s "
                        "refcount=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\" "
                        "\n",
                        key,
                        ref->reference_count,
                        "Setting idle timeout for unreferenced job",
                        reason);

                result = globus_callback_register_oneshot(
                        &ref->cleanup_timer,
                        &delay,
                        globus_l_gram_ref_swap_out,
                        ref);
                if (result != GLOBUS_SUCCESS)
                {
                    char *              errstr;
                    char *              errstr_escaped;

                    errstr = globus_error_print_friendly(
                            globus_error_peek(result));
                    errstr_escaped = globus_gram_prepare_log_string(errstr);

                    globus_gram_job_manager_log(
                            manager,
                            GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                            "event=gram.remove_reference.info "
                            "level=WARN "
                            "gramid=%s "
                            "refcount=%d "
                            "msg=\"%s\" "
                            "\n",
                            key,
                            ref->reference_count,
                            "Unable to set idle timeout, leak possible",
                            errstr_escaped ? errstr_escaped : "");

                    if (errstr)
                    {
                        free(errstr);
                    }
                    if (errstr_escaped)
                    {
                        free(errstr_escaped);
                    }
                }
            }
        }
    }
    else
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.remove_reference.end "
                "level=WARN "
                "gramid=%s "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                gramid,
                -rc,
                "Error resolving job",
                globus_gram_protocol_error_string(rc));
    }

    if (rc == GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.remove_reference.end "
                "level=TRACE "
                "gramid=%s "
                "status=%d "
                "\n",
                gramid,
                0);
    }
    GlobusGramJobManagerUnlock(manager);

    return rc;
}
/* globus_gram_job_manager_remove_reference() */

/**
 * Register a mapping between a LRM job ID and job request's unique job_contact_path
 *
 * @param manager
 *     Job manager state
 * @param job_id
 *     Job identifier
 * @param request
 *     Request to associate with this job id.
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed.
 */
int
globus_gram_job_manager_register_job_id(
    globus_gram_job_manager_t *         manager,
    char *                              job_id,
    globus_gram_jobmanager_request_t *  request)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_gram_job_id_ref_t *          ref;
    globus_gram_job_id_ref_t *          old_ref;
    globus_list_t                       *subjobs = NULL, *tmp_list;
    char *                              subjob_id;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.job_id_register.start "
            "level=TRACE "
            "gramid=%s "
            "jobid=\"%s\" "
            "\n",
            request->job_contact_path,
            job_id);

    if (manager->config->seg_module != NULL)
    {
        /* If we're using the SEG, split on /,/ so that seg events can be
         * matched to the relevant job requests
         */
        rc = globus_gram_split_subjobs(job_id, &subjobs);
        if (rc != GLOBUS_SUCCESS)
        {
            goto split_job_id_failed;
        }
    }
    else
    {
        char *                          tmp;

        tmp = strdup(job_id);
        if (tmp == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto dup_job_id_failed;
        }

        rc = globus_list_insert(&subjobs, tmp);
        if (tmp == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            free(tmp);

            goto insert_dup_failed;
        }
    }

    GlobusGramJobManagerLock(manager);
    for (tmp_list = subjobs;
         tmp_list != NULL;
         tmp_list = globus_list_rest(tmp_list))
    {
        subjob_id = globus_list_first(tmp_list);

        old_ref = globus_hashtable_lookup(
                &manager->job_id_hash,
                subjob_id);

        if (old_ref != NULL)
        {
            if (strcmp(old_ref->job_contact_path,
                        request->job_contact_path) != 0)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                        "event=gram.job_id_register.end "
                        "level=ERROR "
                        "gramid=%s "
                        "jobid=\"%s\" "
                        "msg=\"%s\" "
                        "status=%d "
                        "reason=\"%s\" "
                        "\n",
                        request->job_contact_path,
                        job_id,
                        "Job ID references another job",
                        -rc,
                        globus_gram_protocol_error_string(rc));

                goto old_ref_exists;
            }
            else
            {
                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                        "event=gram.job_id.register.end "
                        "level=TRACE "
                        "gramid=%s "
                        "jobid=%s "
                        "status=%d "
                        "msg=\"%s\" "
                        "\n",
                        request->job_contact_path,
                        job_id,
                        0,
                        "Job already registered, ignoring reregistration");

                goto old_ref_exists;
            }
        }

        ref = malloc(sizeof(globus_gram_job_id_ref_t));
        if (ref == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.job_id.register.end "
                    "level=ERROR "
                    "gramid=%s "
                    "jobid=%s "
                    "status=%d "
                    "msg=\"%s\" "
                    "errno=%d "
                    "reason=\"%s\" "
                    "\n",
                    job_id,
                    request->job_contact_path,
                    -rc,
                    "Malloc failed",
                    errno,
                    strerror(errno));

            goto ref_malloc_failed;
        }

        ref->job_id = strdup(subjob_id);
        if (ref->job_id == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.job_id.register.end "
                    "level=ERROR "
                    "gramid=%s "
                    "jobid=%s "
                    "status=%d "
                    "msg=\"%s\" "
                    "errno=%d "
                    "reason=\"%s\" "
                    "\n",
                    job_id,
                    request->job_contact_path,
                    -rc,
                    "Malloc failed",
                    errno,
                    strerror(errno));

            goto job_id_strdup_failed;
        }
        ref->job_contact_path = strdup(request->job_contact_path);
        if (ref->job_contact_path == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.job_id.register.end "
                    "level=ERROR "
                    "gramid=%s "
                    "jobid=%s "
                    "status=%d "
                    "msg=\"%s\" "
                    "errno=%d "
                    "reason=\"%s\" "
                    "\n",
                    job_id,
                    request->job_contact_path,
                    -rc,
                    "Malloc failed",
                    errno,
                    strerror(errno));

            goto job_contact_path_strdup_failed;
        }
        rc = globus_hashtable_insert(
                &manager->job_id_hash,
                ref->job_id,
                ref);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.job_id.register.end "
                    "level=ERROR "
                    "gramid=%s "
                    "jobid=%s "
                    "status=%d "
                    "msg=\"%s\" "
                    "reason=\"%s\" "
                    "\n",
                    job_id,
                    request->job_contact_path,
                    -rc,
                    "Hashtable insert failed",
                    globus_gram_protocol_error_string(rc));

            goto hash_insert_failed;
        }
    }

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.job_id.register.end "
            "level=TRACE "
            "gramid=%s "
            "jobid=%s "
            "status=%d "
            "\n",
            job_id,
            request->job_contact_path,
            0);

    if (rc != GLOBUS_SUCCESS)
    {
hash_insert_failed:
        free(ref->job_contact_path);
job_contact_path_strdup_failed:
        free(ref->job_id);
job_id_strdup_failed:
        free(ref);
    }
ref_malloc_failed:
old_ref_exists:
    GlobusGramJobManagerUnlock(manager);
    globus_list_destroy_all(subjobs, free);
insert_dup_failed:
dup_job_id_failed:
split_job_id_failed:
    return rc;
}
/* globus_gram_job_manager_register_job_id() */

/**
 * Unregister a mapping between a LRM job ID and job request's unique job_contact_path
 *
 * @param manager
 *     Job manager state
 * @param job_id
 *     Job identifier
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed.
 */
int
globus_gram_job_manager_unregister_job_id(
    globus_gram_job_manager_t *         manager,
    char *                              job_id)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_gram_job_id_ref_t *          ref;

    if (job_id == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;
        goto null_job_id;
    }
    GlobusGramJobManagerLock(manager);
    ref = globus_hashtable_remove(&manager->job_id_hash, (void *) job_id);
    if (!ref)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;
        goto no_such_job;
    }
    free(ref->job_contact_path);
    free(ref->job_id);
    free(ref);

no_such_job:
    GlobusGramJobManagerUnlock(manager);
null_job_id:
    return rc;
}
/* globus_gram_job_manager_unregister_job_id() */

/**
 * resolve a local job id to a request, adding a reference to it.
 *
 * @param manager
 *     Job manager state. Must have its mutex locked.
 * @param jobid
 *     individual lrm job id string.
 * @param request
 *     pointer to be set to the corresponding job request if found in the
 *     table. may be null if the caller already has a reference and wants to
 *     add one.
 *
 * @retval globus_success
 *     success.
 * @retval globus_gram_protocol_error_job_contact_not_found
 *     job contact not found.
 */
int
globus_gram_job_manager_add_reference_by_jobid(
    globus_gram_job_manager_t *         manager,
    const char *                        jobid,
    const char *                        reason,
    globus_gram_jobmanager_request_t ** request)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_gram_job_id_ref_t *          jobref;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.add_reference.start "
            "level=TRACE "
            "jobid=\"%s\" "
            "reason=\"%s\" "
            "\n",
            jobid,
            reason);

    if (request)
    {
        *request = NULL;
    }

    if (manager->stop)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.add_reference.end "
                "level=WARN "
                "jobid=\"%s\" "
                "status=%d "
                "reason=\"%s\" "
                "\n",
                jobid,
                -rc,
                globus_gram_protocol_error_string(rc));

        goto stop;
    }

    jobref = globus_hashtable_lookup(&manager->job_id_hash, (void *) jobid);
    if (!jobref)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_INFO,
                "event=gram.add_reference.end "
                "level=INFO "
                "jobid=\"%s\" "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                jobid,
                -rc,
                "Unknown job ID",
                globus_gram_protocol_error_string(rc));

        goto no_such_job;
    }

    rc = globus_l_gram_add_reference_locked(
            manager,
            jobref->job_contact_path,
            reason,
            request);

    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.add_reference.end "
                "level=ERROR "
                "jobid=\"%s\" "
                "status=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                jobid,
                -rc,
                "Adding reference failed",
                globus_gram_protocol_error_string(rc));
    }
    else
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.add_reference.end "
                "level=TRACE "
                "jobid=\"%s\" "
                "status=%d "
                "\n",
                jobid,
                0);
    }

no_such_job:
stop:

    return rc;
}
/* globus_gram_job_manager_add_reference_by_jobid() */

/**
 * Store the job state in the manager so that the request can be swapped out
 *
 * @param manager
 *     Job manager state
 * @param key
 *     Job request key
 * @param state
 *     Job state
 * @param failure_code
 *     Job failure code
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND
 *     Job contact not found
 */
int
globus_gram_job_manager_set_status(
    globus_gram_job_manager_t *         manager,
    const char *                        key,
    globus_gram_protocol_job_state_t    state,
    int                                 failure_code,
    int                                 exit_code)
{
    globus_gram_job_manager_ref_t *     ref;
    int                                 rc = GLOBUS_SUCCESS;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.set_job_status.start "
            "level=TRACE "
            "gramid=%s "
            "state=%d "
            "failure_code=%d "
            "\n",
            key,
            state,
            failure_code);

    GlobusGramJobManagerLock(manager);
    ref = globus_hashtable_lookup(
            &manager->request_hash,
            (void *) key);
    if (ref == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND,
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.set_job_status.end "
                "level=WARN "
                "gramid=%s "
                "state=%d "
                "failure_code=%d "
                "status=%d "
                "reason=\"%s\" "
                "\n",
                key,
                state,
                failure_code,
                -rc,
                globus_gram_protocol_error_string(rc));

        goto not_found;
    }

    ref->job_state = state;
    ref->failure_code = failure_code;
    ref->exit_code = exit_code;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.set_job_status.end "
            "level=TRACE "
            "gramid=%s "
            "state=%d "
            "failure_code=%d "
            "status=%d "
            "\n",
            key,
            state,
            failure_code,
            0);

not_found:
    GlobusGramJobManagerUnlock(manager);

    return rc;
}
/* globus_gram_job_manager_set_status() */

/**
 * Look up the job state for a request without reloading the request
 *
 * @param manager
 *     Job manager state
 * @param key
 *     Job request key
 * @param state
 *     Pointer to set to the value of the job state
 * @param failure_code
 *     Pointer to set to the value of the failure code
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND
 *     Job contact not found
 */
int
globus_gram_job_manager_get_status(
    globus_gram_job_manager_t *         manager,
    const char *                        key,
    globus_gram_protocol_job_state_t *  state,
    int *                               failure_code,
    int *                               exit_code)
{
    int                                 rc = GLOBUS_SUCCESS;

    globus_gram_job_manager_ref_t *     ref;
    GlobusGramJobManagerLock(manager);
    ref = globus_hashtable_lookup(
            &manager->request_hash,
            (void *) key);

    if (ref == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;
        goto not_found;
    }

    ref->status_count++;
    *state = ref->job_state;
    *failure_code = ref->failure_code;
    *exit_code = ref->exit_code;

not_found:
    GlobusGramJobManagerUnlock(manager);

    return rc;
}
/* globus_gram_job_manager_get_status() */

int
globus_gram_job_manager_get_job_id_list(
    globus_gram_job_manager_t *         manager,
    globus_list_t **                    job_id_list)
{
    char *                              job_id;
    globus_gram_job_id_ref_t *          ref;
    int                                 rc = GLOBUS_SUCCESS;

    *job_id_list = NULL;

    GlobusGramJobManagerLock(manager);
    for (ref = globus_hashtable_first(&manager->job_id_hash);
         ref != NULL;
         ref = globus_hashtable_next(&manager->job_id_hash))
    {
        job_id = strdup(ref->job_id);

        if (job_id == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto job_id_strdup_failed;
        }
        rc = globus_list_insert(job_id_list, job_id);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto job_id_insert_failed;
        }
    }

    if (rc != GLOBUS_SUCCESS)
    {
job_id_insert_failed:
        free(job_id);
job_id_strdup_failed:
        globus_list_destroy_all(*job_id_list, free);
        *job_id_list = NULL;
    }
    GlobusGramJobManagerUnlock(manager);

    return rc;
}
/* globus_gram_job_manager_get_job_id_list() */

globus_bool_t
globus_gram_job_manager_request_exists(
    globus_gram_job_manager_t *         manager,
    const char *                        key)
{
    globus_bool_t                       result;
    globus_gram_job_manager_ref_t  *    ref;
    GlobusGramJobManagerLock(manager);

    ref = globus_hashtable_lookup(&manager->request_hash, (void *) key);

    result = (ref != NULL && ref->request != NULL);
    GlobusGramJobManagerUnlock(manager);

    return result;
}
/* globus_gram_job_manager_request_exists() */

void
globus_gram_job_manager_set_grace_period_timer(
    globus_gram_job_manager_t *         manager)
{
    if (globus_hashtable_empty(&manager->request_hash))
    {
        globus_reltime_t        delay;
        globus_result_t         result;

        GlobusTimeReltimeSet(delay, globus_l_gram_grace_period_delay, 0);

        result = globus_callback_register_oneshot(
                &manager->grace_period_timer,
                &delay,
                globus_l_gram_job_manager_grace_period_expired,
                manager);
        if (result != GLOBUS_SUCCESS)
        {
            manager->done = GLOBUS_TRUE;
            globus_cond_signal(&manager->cond);
        }
    }
}
/* globus_gram_job_manager_set_grace_period_timer() */

void
globus_gram_job_manager_stop_all_jobs(
    globus_gram_job_manager_t *         manager)
{
    globus_list_t *                     job_refs = NULL;
    globus_list_t *                     tmp = NULL;
    globus_gram_job_manager_ref_t *     ref;
    globus_gram_jobmanager_request_t *  request;
    int                                 rc;

    GlobusGramJobManagerLock(manager);
    manager->stop = GLOBUS_TRUE;
    rc = globus_hashtable_to_list(
            &manager->request_hash,
            &job_refs);

    if (rc != GLOBUS_SUCCESS)
    {
        GlobusGramJobManagerUnlock(manager);
        return;
    }

    tmp = job_refs;
    while (!globus_list_empty(tmp))
    {
        ref = globus_list_first(tmp);
        tmp = globus_list_rest(tmp);

        /* Force request into memory if it isn't yet. */
        rc = globus_l_gram_add_reference_locked(
                manager,
                ref->key,
                "stop all jobs",
                NULL);
        assert(rc == GLOBUS_SUCCESS);
    }
    GlobusGramJobManagerUnlock(manager);

    tmp = job_refs;

    while (!globus_list_empty(tmp))
    {
        ref = globus_list_first(tmp);
        tmp = globus_list_rest(tmp);
        request = ref->request;

        GlobusGramJobManagerRequestLock(request);
        request->stop_reason = GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED;
        request->restart_state = request->jobmanager_state;

        switch (request->jobmanager_state)
        {
        case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
            break;

        case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
            request->unsent_status_change = GLOBUS_TRUE;

            globus_gram_job_manager_state_machine_register(
                    request->manager,
                    request,
                    NULL);
            break;
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH:
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
            request->unsent_status_change = GLOBUS_TRUE;
            break;
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT:
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
            break;

        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END:
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
            break;

        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED:
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
            break;

        case GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP:
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
            break;

        case GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP:
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
            break;

        case GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP:
            request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
            break;

        case GLOBUS_GRAM_JOB_MANAGER_STATE_DONE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP:
            break;
        }
        if (request->poll_timer)
        {
            globus_reltime_t            delay;

            GlobusTimeReltimeSet(delay, 0, 0);

            globus_callback_adjust_oneshot(
                    request->poll_timer,
                    &delay);
        }
        GlobusGramJobManagerRequestUnlock(request);

        globus_gram_job_manager_remove_reference(
                manager,
                ref->key,
                "stop all jobs");
    }
    globus_list_free(job_refs);
}
/* globus_gram_job_manager_stop_all_jobs() */

int
globus_gram_job_manager_request_load_all(
    globus_gram_job_manager_t *         manager,
    globus_list_t **                    requests)
{
    int                                 rc = GLOBUS_SUCCESS;
    char *                              state_dir_path = NULL;
    char *                              state_file_pattern = NULL;
    int                                 lock;
    DIR *                               dir;
    struct dirent *                     entry;
    uint64_t                            uniq1, uniq2;
    globus_gram_jobmanager_request_t *  request;

    *requests = NULL;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_INFO,
            "event=gram.reload_requests.start "
            "level=INFO "
            "\n");

    if(manager->config->job_state_file_dir == NULL)
    {
        state_dir_path = globus_common_create_string(
                "%s/tmp/gram_job_state/",
                manager->config->globus_location);
    }
    else
    {
        state_dir_path = globus_common_create_string(
                "%s",
                manager->config->job_state_file_dir);
    }

    if (state_dir_path == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.reload_requests.end "
                "level=ERROR "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                -rc,
                "Malloc failed",
                errno,
                strerror(errno));

        goto state_dir_path_alloc_failed;
    }

    if(manager->config->job_state_file_dir == NULL)
    {
        state_file_pattern = globus_common_create_string(
                "%s.%s.%%"PRIu64".%%"PRIu64"%%n",
                manager->config->logname,
                manager->config->hostname);
    }
    else
    {
        state_file_pattern = globus_common_create_string(
                "job.%s.%%"PRIu64".%%"PRIu64"%%n",
                manager->config->hostname);
    }
    if (state_file_pattern == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.reload_requests.end "
                "level=ERROR "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                -rc,
                "Malloc failed",
                errno,
                strerror(errno));

        goto state_file_pattern_alloc_failed;
    }

    dir = globus_libc_opendir(state_dir_path);
    if (dir == NULL)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.reload_requests.end "
                "level=ERROR "
                "statedir=\"%s\" "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\"\n",
                state_dir_path,
                "opendir failed",
                errno,
                strerror(errno));

        goto opendir_failed;
    }

    while ((rc = globus_libc_readdir_r(dir, &entry)) == 0)
    {
        if ((sscanf( entry->d_name,
                    state_file_pattern,
                    &uniq1,
                    &uniq2,
                    &lock) == 2)
            && (strlen(entry->d_name + lock) == 0))
        {
            /* Found candidate job state file. */
            char * key = globus_common_create_string(
                    "%"PRIu64"/%"PRIu64"/",
                    uniq1,
                    uniq2);

            if (key == NULL)
            {
                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                        "event=gram.reload_requests.info "
                        "level=WARN "
                        "statedir=\"%s\" "
                        "file=\"%s\" "
                        "msg=\"%s\" "
                        "gramid=%"PRIu64"/%"PRIu64" "
                        "errno=%d "
                        "reason=\"%s\"\n",
                        state_dir_path,
                        entry->d_name,
                        "Error constructing filename, ignoring state file",
                        uniq1,
                        uniq2,
                        errno,
                        strerror(errno));

                free(entry);
                continue;
            }

            rc = globus_l_gram_restart_job(
                    manager,
                    &request,
                    key);
            free(entry);
            free(key);

            if (rc != GLOBUS_SUCCESS)
            {
                if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE)
                {
                    globus_gram_job_manager_log(
                            manager,
                            GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                            "event=gram.reload_requests.info "
                            "level=WARN "
                            "statedir=\"%s\" "
                            "msg=\"%s\" "
                            "gramid=%"PRIu64"/%"PRIu64" "
                            "status=%d "
                            "reason=\"%s\"\n",
                            state_dir_path,
                            "Error restarting job",
                            uniq1,
                            uniq2,
                            -rc,
                            globus_gram_protocol_error_string(rc));
                }

                continue;
            }
            rc = globus_list_insert(
                    requests,
                    request);
            if (rc != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                        "event=gram.reload_requests.info "
                        "level=WARN "
                        "statedir=\"%s\" "
                        "msg=\"%s\" "
                        "gramid=%"PRIu64"/%"PRIu64" "
                        "errno=%d "
                        "reason=\"%s\"\n",
                        state_dir_path,
                        "Error inserting job into request list",
                        uniq1,
                        uniq2,
                        globus_gram_protocol_error_string(rc));

                globus_gram_job_manager_request_free(request);
                free(request);
            }

            if (manager->seg_last_timestamp == 0 ||
                manager->seg_last_timestamp > request->seg_last_timestamp)
            {
                manager->seg_last_timestamp = request->seg_last_timestamp;
            }
        }
        else
        {
            free(entry);
        }
    }
    rc = 0;
    globus_libc_closedir(dir);

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_INFO,
            "event=gram.reload_requests.end "
            "level=INFO "
            "statedir=\"%s\" "
            "status=%d "
            "requests=%d "
            "\n",
            state_dir_path,
            0,
            (int) globus_list_size(*requests));

opendir_failed:
    free(state_file_pattern);
state_file_pattern_alloc_failed:
    free(state_dir_path);
state_dir_path_alloc_failed:
    return rc;
}
/* globus_gram_job_manager_request_load_all() */

static
int
globus_l_gram_mkdir(
    char *                              path)
{
    char *                              tmp;
    int                                 rc;
    struct stat                         statbuf;

    if ((rc = stat(path, &statbuf)) < 0)
    {
        tmp = path;

        while (tmp != NULL)
        {
            tmp = strchr(tmp+1, '/');
            if (tmp != path)
            {
                if (tmp != NULL)
                {
                    *tmp = '\0';
                }
                if ((rc = stat(path, &statbuf)) < 0)
                {
                    mkdir(path, S_IRWXU);
                }
                if ((rc = stat(path, &statbuf)) < 0)
                {
                    rc = GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;

                    goto error_exit;
                }
                if (tmp != NULL)
                {
                    *tmp = '/';
                }
            }
        }
    }
    rc = GLOBUS_SUCCESS;
error_exit:
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
    }
    return rc;
}
/* globus_l_gram_mkdir() */

static
void
globus_l_gram_job_manager_grace_period_expired(
    void *                              arg)
{
    globus_gram_job_manager_t *         manager;

    manager = arg;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.grace_period_expired.start "
            "level=TRACE "
            "\n");
    GlobusGramJobManagerLock(manager);
    if (manager->grace_period_timer != GLOBUS_NULL_HANDLE)
    {
        (void) globus_callback_unregister(
                manager->grace_period_timer,
                NULL,
                NULL,
                NULL);
        if (globus_hashtable_empty(&manager->request_hash))
        {
            manager->done = GLOBUS_TRUE;
            globus_cond_signal(&manager->cond);
        }
        manager->grace_period_timer = GLOBUS_NULL_HANDLE;
    }
    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.grace_period_expired.end "
            "level=TRACE "
            "status=%d "
            "terminating=%s "
            "\n",
            0,
            manager->done ? "true" : "false");
    GlobusGramJobManagerUnlock(manager);
}
/* globus_l_gram_job_manager_grace_period_expired() */

static
void
globus_l_gram_ref_swap_out(
    void *                              arg)
{
    globus_result_t                     result;

    globus_gram_job_manager_ref_t *     ref = arg;
    globus_gram_jobmanager_request_t *  request;
    int                                 rc;

    globus_gram_job_manager_request_log(
            request,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.job_ref_swap_out.start "
            "level=TRACE "
            "gramid=%s\n",
            ref->key);

    GlobusGramJobManagerLock(ref->manager);
    if (ref->cleanup_timer != GLOBUS_NULL_HANDLE)
    {
        result = globus_callback_unregister(
                ref->cleanup_timer,
                NULL,
                NULL,
                NULL);
        ref->cleanup_timer = GLOBUS_NULL_HANDLE;

        if (result != GLOBUS_SUCCESS)
        {
            char *                      errstr;
            char *                      errstr_escaped;

            errstr = globus_error_print_friendly(
                    globus_error_peek(result));
            errstr_escaped = globus_gram_prepare_log_string(errstr);

            globus_gram_job_manager_request_log(
                    request,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                    "event=gram.job_ref_swap_out.info "
                    "level=WARN "
                    "gramid=%s "
                    "msg=\"%s\" "
                    "reason=\"%s\" "
                    "\n",
                    ref->key,
                    "Error cancelling callback",
                    errstr_escaped ? errstr_escaped : "");

            if (errstr)
            {
                free(errstr);
            }

            if (errstr_escaped)
            {
                free(errstr_escaped);
            }
        }
    }
    else
    {
        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.job_ref_swap_out.end "
                "level=TRACE "
                "gramid=%s "
                "msg=\"%s\" "
                "\n",
                ref->key,
                "This job was reactivated before the callback, not freeing");

        goto unregistered;
    }
    if (ref->reference_count == 0)
    {
        request = ref->request;
        request->manager->usagetracker->count_current_jobs--;

        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.job_ref_swap_out.info "
                "level=WARN "
                "gramid=%s "
                "msg=\"%s\" "
                "\n",
                ref->key,
                "No new references to job, writing state and freeing data");

        rc = globus_gram_job_manager_state_file_write(ref->request);

        globus_gram_job_manager_request_free(ref->request);
        free(ref->request);
        ref->request = NULL;
    }
    else
    {
        globus_gram_job_manager_request_log(
                request,
                GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
                "event=gram.job_ref_swap_out.info "
                "level=TRACE "
                "gramid=%s "
                "msg=\"%s\" "
                "\n",
                ref->key,
                "New references to job, not freeing");
    }
unregistered:
    GlobusGramJobManagerUnlock(ref->manager);
}
/* globus_l_gram_ref_swap_out() */

static
int
globus_l_gram_add_reference_locked(
    globus_gram_job_manager_t *         manager,
    const char *                        key,
    const char *                        reason,
    globus_gram_jobmanager_request_t ** request)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_result_t                     result;
    globus_gram_job_manager_ref_t *     ref;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.add_reference.start "
            "level=TRACE "
            "gramid=%s "
            "ref_reason=\"%s\"\n",
            key,
            reason);

    ref = globus_hashtable_lookup(&manager->request_hash, (void *) key);
    if (ref)
    {
        ref->reference_count++;

        if (ref->cleanup_timer != GLOBUS_NULL_HANDLE)
        {
            result = globus_callback_unregister(
                    ref->cleanup_timer,
                    NULL,
                    NULL,
                    NULL);
            ref->cleanup_timer = GLOBUS_NULL_HANDLE;
        }
        if (ref->request == NULL)
        {
            rc = globus_l_gram_restart_job(
                    manager,
                    &ref->request,
                    key+1);

            if (rc != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
                ref->reference_count--;

                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                        "event=gram.add_reference.end "
                        "level=WARN "
                        "gramid=%s "
                        "ref_reason=\"%s\" "
                        "status=%d "
                        "reason=\"%s\" "
                        "\n",
                        key,
                        reason,
                        -rc,
                        globus_gram_protocol_error_string(rc));

                goto request_init_failed;
            }
            ref->request->jobmanager_state = ref->request->restart_state;
            ref->request->job_stats.status_count += ref->status_count;
            ref->status_count = 0;
        }
        if (request)
        {
            *request = ref->request;
        }
    }
    else
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;
        if (request)
        {
            *request = NULL;
        }

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.add_reference.end "
                "level=WARN "
                "gramid=%s "
                "status=%d "
                "reason=\"%s\" "
                "ref_reason=\"%s\"\n",
                key,
                -rc,
                globus_gram_protocol_error_string(rc),
                reason);

        goto not_found;
    }
    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.add_reference.end "
            "level=TRACE "
            "gramid=%s "
            "status=%d "
            "ref_reason=\"%s\"\n",
            key,
            0,
            reason);
not_found:
request_init_failed:

    return rc;
}
/* globus_l_gram_add_reference_locked() */

static
int
globus_l_gram_restart_job(
    globus_gram_job_manager_t *         manager,
    globus_gram_jobmanager_request_t ** request,
    const char *                        job_contact_path)
{
    char *                              restart_rsl;
    int                                 rc;

    /* Reload request state */
    restart_rsl = globus_common_create_string(
            "&(restart = '%s%s')(restartcontacts = yes)",
            manager->url_base,
            job_contact_path);
    if (restart_rsl == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto malloc_restart_rsl_failed;
    }

    rc = globus_gram_job_manager_request_init(
            request,
            manager,
            restart_rsl,
            GSS_C_NO_CREDENTIAL,
            GSS_C_NO_CONTEXT,
            GLOBUS_TRUE,
            NULL,
            NULL,
            NULL);
    free(restart_rsl);
malloc_restart_rsl_failed:
    return rc;
}
/* globus_l_gram_restart_job() */

static
int
globus_l_gram_read_job_manager_cred(
    globus_gram_job_manager_t *         manager,
    const char *                        cred_path,
    gss_cred_id_t *                     cred)
{
    int                                 rc;
    FILE *                              fp;
    struct stat                         stat;
    gss_buffer_desc                     buffer;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;

    fp = fopen(manager->cred_path, "r");
    if (fp == NULL)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.read_cred.end cred=%s errno=%d reason=\"%s\"\n",
                manager->cred_path,
                errno,
                strerror(errno));
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;

        goto fopen_failed;
    }

    if (fstat(fileno(fp), &stat) != 0)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.read_cred.end level=ERROR cred=%s errno=%d "
                "reason=\"%s\"\n",
                manager->cred_path,
                errno,
                strerror(errno));
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
        goto fstat_failed;
    }

    if (stat.st_uid != getuid() || (stat.st_mode & (S_IRWXG|S_IRWXO)))
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.read_cred.end level=ERROR cred=%s error=%d "
                "reason=\"%s\"\n",
                manager->cred_path,
                GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY,
                "Invalid file ownership or permissions");

        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
        goto perm_check_failed;
    }

    buffer.length = (size_t) stat.st_size;

    buffer.value = malloc(buffer.length+1);
    if (buffer.value == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto buffer_malloc_failed;
    }
    rc = fread(buffer.value, 1, buffer.length, fp);
    ((char *)buffer.value)[buffer.length] = 0;
    if (rc != buffer.length)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;

        goto fread_failed;
    }
    major_status = gss_import_cred(
            &minor_status,
            cred,
            GSS_C_NO_OID,
            0,
            &buffer,
            0,
            NULL);
    if (GSS_ERROR(major_status))
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.read_cred.end level=ERROR cred=%s major_status=%d "
                "reason=\"%s\"\n",
                manager->cred_path,
                major_status,
                "import cred failed");
        goto import_failed;
    }

    rc = GLOBUS_SUCCESS;
import_failed:
    free(buffer.value);
fread_failed:
buffer_malloc_failed:
perm_check_failed:
fstat_failed:
    fclose(fp);
fopen_failed:

    return rc;
}
/* globus_l_gram_read_job_manager_cred() */

int
globus_gram_split_subjobs(
    const char *                        job_id,
    globus_list_t **                    subjobs)
{
    char *                              tok_end = NULL;
    char *                              job_id_string;
    char *                              job_id_string_copy;
    int                                 rc = GLOBUS_SUCCESS;

    job_id_string_copy = strdup(job_id);
    if (job_id_string_copy == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto job_id_copy_failed;
    }

    for (tok_end = NULL,
                job_id_string = strtok_r(job_id_string_copy, ",", &tok_end);
         job_id_string != NULL;
         job_id_string = strtok_r(NULL, ",", &tok_end))
    {
        char *                      subjob_id = NULL;
        subjob_id = strdup(job_id_string);
        if (subjob_id == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

            goto strdup_failed;
        }
        rc = globus_list_insert(subjobs, subjob_id);
        if (rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            free(subjob_id);

            goto insert_failed;
        }
    }

    if (rc != GLOBUS_SUCCESS)
    {
insert_failed:
strdup_failed:
        globus_list_destroy_all(*subjobs, free);
        free(job_id_string_copy);
job_id_copy_failed:
        *subjobs = NULL;
    }
    return rc;
}
/* globus_gram_split_subjobs() */
