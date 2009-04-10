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

static
void
globus_l_gram_job_manager_open_logfile(
    globus_gram_job_manager_t *         manager);

typedef struct globus_gram_job_manager_ref_s
{
    /* Local copy of the unique hashtable key */
    char *                              key;
    /* Pointer to the request */
    globus_gram_jobmanager_request_t *  request;
    /* Count of callbacks, queries, etc that have access to this now.
     * When 0, the request is eligible for removal
     */
    int                                 reference_count;
}
globus_gram_job_manager_ref_t;

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

    manager->config = config;

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
    globus_mutex_lock(&manager->mutex);

    manager->seg_last_timestamp = (time_t) 0;
    manager->seg_started = GLOBUS_FALSE;

    globus_l_gram_job_manager_open_logfile(manager);

    rc = globus_gram_job_manager_validation_init(manager);
    if (rc != GLOBUS_SUCCESS)
    {
        goto validation_init_failed;
    }

    rc = globus_hashtable_init(
            &manager->request_hash,
            13,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto request_hashtable_init_failed;
    }

    rc = globus_hashtable_init(
            &manager->job_id_hash,
            13,
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
            "%s/%s.cred",
            dir_prefix,
            manager->config->jobmanager_type);
    if (manager->cred_path == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto malloc_cred_path_failed;
    }

    if (cred != GSS_C_NO_CREDENTIAL)
    {
        rc = globus_gram_protocol_set_credentials(cred);
    }
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

    globus_mutex_lock(&manager->mutex);
    if (cred != GSS_C_NO_CREDENTIAL)
    {
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
            "%s/%s.lock",
            dir_prefix,
            manager->config->jobmanager_type);
    if (manager->lock_path == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto malloc_lock_path_failed;
    }

    manager->socket_path = globus_common_create_string(
            "%s/%s.sock",
            dir_prefix,
            manager->config->jobmanager_type);
    if (manager->socket_path == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto malloc_socket_path_failed;
    }

    rc = globus_fifo_init(&manager->script_fifo);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto script_fifo_init_failed;
    }

    /* Default number of scripts which can be run simultaneously */
    manager->script_slots_available = 5;

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

    globus_mutex_unlock(&manager->mutex);

    free(dir_prefix);

    manager->done = GLOBUS_FALSE;
    manager->grace_period_timer = GLOBUS_NULL_HANDLE;

    manager->seg_pause_count = 0;
    rc = globus_fifo_init(&manager->seg_event_queue);

    if (rc != GLOBUS_SUCCESS)
    {
state_callback_fifo_init_failed:
        globus_fifo_destroy(&manager->script_fifo);
script_fifo_init_failed:
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
        if (manager->jobmanager_logfile)
        {
            free(manager->jobmanager_logfile);
            manager->jobmanager_logfile = NULL;
        }
        if (manager->jobmanager_log_fp)
        {
            fclose(manager->jobmanager_log_fp);
            manager->jobmanager_log_fp = NULL;
        }
        globus_cond_destroy(&manager->mutex);
cond_init_failed:
        globus_mutex_unlock(&manager->mutex);
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
    
    if (manager->jobmanager_logfile)
    {
        free(manager->jobmanager_logfile);
        manager->jobmanager_logfile = NULL;
    }
    if (manager->jobmanager_log_fp)
    {
        fclose(manager->jobmanager_log_fp);
        manager->jobmanager_log_fp = NULL;
    }
    globus_hashtable_destroy(&manager->request_hash);

    globus_fifo_destroy(&manager->state_callback_fifo);
    globus_fifo_destroy(&manager->script_fifo);

    return;
}
/* globus_gram_job_manager_destroy() */

static
void
globus_l_gram_job_manager_open_logfile(
    globus_gram_job_manager_t *         manager)
{
    if (manager->config->logfile_flag == GLOBUS_GRAM_JOB_MANAGER_DONT_SAVE)
    {
        /* don't write a log file */
        manager->jobmanager_logfile = strdup("/dev/null");
        manager->jobmanager_log_fp = NULL;
    }
    else
    {
        /*
         * Open the gram logfile just for testing!
         */
        manager->jobmanager_logfile = globus_common_create_string(
                "%s/gram_job_mgr_%lu.log",
                manager->config->home,
                (unsigned long) getpid());

        manager->jobmanager_log_fp =
                fopen(manager->jobmanager_logfile, "a");
        
        if (manager->jobmanager_log_fp == NULL)
        {
            free(manager->jobmanager_logfile);
            manager->jobmanager_logfile = strdup("/dev/null");
        }
    }

    if (manager->jobmanager_log_fp == NULL)
    {
        manager->jobmanager_log_fp =
                fopen(manager->jobmanager_logfile, "a");
    }

    if (manager->jobmanager_log_fp != NULL)
    {
        int fd;

        setbuf(manager->jobmanager_log_fp, NULL);

        fd = fileno(manager->jobmanager_log_fp);

        while(fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        {
            if(errno != EINTR)
            {
                break;
            }
        }
    }

    return;
}
/* globus_l_gram_job_manager_open_logfile() */

int
globus_gram_job_manager_read_rsl(
    globus_gram_job_manager_t *         manager,
    char **                             rsl,
    char **                             contact,
    int *                               job_state_mask)
{
    int                                 rc;
    char *                              args_fd_str;
    int                                 args_fd;
    globus_size_t                       jrbuf_size;
    globus_byte_t                       buffer[
                                        GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];

    args_fd_str = getenv("GRID_SECURITY_HTTP_BODY_FD");
    if ((!args_fd_str) || ((args_fd = atoi(args_fd_str)) == 0))
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    jrbuf_size = (globus_size_t) lseek(args_fd, 0, SEEK_END);
    (void) lseek(args_fd, 0, SEEK_SET);
    if (jrbuf_size > GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE)
    {
        globus_gram_job_manager_log(manager, "JM: RSL file too big\n");
        return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    if (read(args_fd, buffer, jrbuf_size) != jrbuf_size)
    {
        globus_gram_job_manager_log(
                manager,
                "JM: Error reading the RSL file\n");
        return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    close(args_fd);

    rc = globus_gram_protocol_unpack_job_request(
            buffer,
            jrbuf_size,
            job_state_mask,
            contact,
            rsl);
    if(rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_log(
                manager,
                "JM: request unpack failed because %s\n",
                globus_gram_protocol_error_string(rc));
        return rc;
    }
    return rc;
}
/* globus_gram_job_manager_read_rsl() */


int
globus_gram_job_manager_log(
    globus_gram_job_manager_t *         manager,
    const char *                        format,
    ...)
{
    struct tm *                         curr_tm;
    time_t                              curr_time;
    int                                 rc;
    va_list                             ap;

    if (!manager)
    {
        return -1;
    }

    if ( !manager->jobmanager_log_fp)
    {
        return -1;
    }

    time(&curr_time);
    curr_tm = localtime(&curr_time);

    fprintf(manager->jobmanager_log_fp,
            "%d/%d %02d:%02d:%02d ",
             curr_tm->tm_mon + 1, curr_tm->tm_mday,
             curr_tm->tm_hour, curr_tm->tm_min,
             curr_tm->tm_sec );

    va_start(ap, format);
    rc = vfprintf(manager->jobmanager_log_fp, format, ap);
    va_end(ap);

    return rc;
}
/* globus_gram_job_manager_log() */

/**
 * Add a job request to a reference-counting hashtable
 *
 * Adds the job request to the reference-counting hashtable with an initial
 * reference count of 1. Calls to globus_gram_job_manager_add_reference() and
 * globus_gram_job_manager_remove_reference() will increase and decrease the
 * reference count. Callbacks and job status queries, etc should call those
 * to dereference the job's unique key to a globus_gram_jobmanager_request_t
 * structure and then release that reference. The final reference should be
 * released when the job terminates or fails.
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
            "Adding request %s -> %p\n",
            key,
            request);
    ref = malloc(sizeof(globus_gram_job_manager_ref_t));

    if (ref == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto ref_malloc_failed;
    }

    ref->key = strdup(key);
    if (ref->key == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto key_malloc_failed;
    }

    ref->request = request;
    ref->reference_count = 1;

    globus_mutex_lock(&manager->mutex);
    if (manager->grace_period_timer != GLOBUS_NULL_HANDLE)
    {
        globus_callback_unregister(
                manager->grace_period_timer,
                NULL,
                NULL,
                NULL);

        if (manager->done)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
            goto grace_period_expired;
        }
        manager->grace_period_timer = GLOBUS_NULL_HANDLE;
    }
    rc = globus_hashtable_insert(
            &manager->request_hash,
            ref->key,
            ref);
    globus_mutex_unlock(&manager->mutex);

    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto insert_failed;
    }
    if (rc != GLOBUS_SUCCESS)
    {
insert_failed:
grace_period_expired:
        free(ref->key);
key_malloc_failed:
        free(ref);
ref_malloc_failed:
        ;
    }
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
    globus_gram_jobmanager_request_t ** request)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_gram_job_manager_ref_t *     ref;
    globus_mutex_lock(&manager->mutex);
    ref = globus_hashtable_lookup(&manager->request_hash, (void *) key);
    if (ref)
    {
        ref->reference_count++;
        if (request)
        {
            *request = ref->request;
        }
        globus_gram_job_manager_log(
                manager,
                "Adding reference %s -> %p\n",
                ref->key,
                ref->request);
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
                "Adding reference %s -> NOT FOUND\n",
                key);
    }
    globus_mutex_unlock(&manager->mutex);

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
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND
 *     Job contact not found.
 */
int
globus_gram_job_manager_remove_reference(
    globus_gram_job_manager_t *         manager,
    const char *                        key)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_gram_job_manager_ref_t *     ref;
    globus_mutex_lock(&manager->mutex);
    ref = globus_hashtable_lookup(&manager->request_hash, (void *) key);
    if (ref)
    {
        ref->reference_count--;

        globus_gram_job_manager_log(
                manager,
                "Removing %sreference %s -> %p\n",
                ref->reference_count ? "" : "last ",
                key,
                ref->request);
        if (ref->reference_count == 0)
        {
            globus_hashtable_remove(&manager->request_hash, (void *) key);
            globus_gram_job_manager_request_destroy(ref->request);
            free(ref->request);
            free(ref->key);
            free(ref);

            if (globus_hashtable_empty(&manager->request_hash))
            {
                globus_gram_job_manager_set_grace_period_timer(manager);
            }
        }
    }
    else
    {
        globus_gram_job_manager_log(
                manager,
                "Removing spurious reference %s -> NOT FOUND\n",
                key);
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;
    }
    globus_mutex_unlock(&manager->mutex);

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

    globus_gram_job_manager_log(
            manager,
            "Registering job id %s -> %s (%p)\n",
            job_id,
            request->job_contact_path,
            request);

    ref = malloc(sizeof(globus_gram_job_id_ref_t));
    if (ref == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto ref_malloc_failed;
    }

    ref->job_id = strdup(job_id);
    if (ref->job_id == NULL)
    {
        goto job_id_strdup_failed;
    }
    ref->job_contact_path = strdup(request->job_contact_path);
    if (ref->job_contact_path == NULL)
    {
        goto job_contact_path_strdup_failed;
    }
    globus_mutex_lock(&manager->mutex);
    rc = globus_hashtable_insert(
            &manager->job_id_hash,
            ref->job_id,
            ref);
    globus_mutex_unlock(&manager->mutex);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        goto hash_insert_failed;
    }

    if (rc != GLOBUS_SUCCESS)
    {
hash_insert_failed:
        free(ref->job_contact_path);
job_contact_path_strdup_failed:
        free(ref->job_id);
job_id_strdup_failed:
        free(ref);
ref_malloc_failed:
        ;
    }
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
    globus_mutex_lock(&manager->mutex);
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
    globus_mutex_unlock(&manager->mutex);
null_job_id:
    return rc;
}
/* globus_gram_job_manager_unregister_job_id() */

/**
 * resolve a local job id to a request, adding a reference to it.
 *
 * @param manager
 *     job manager state
 * @param jobid
 *     individual lrm job id string.
 * @param locked
 *     boolean flag: true if the manager is currently locked
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
    globus_bool_t                       locked,
    globus_gram_jobmanager_request_t ** request)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_gram_job_id_ref_t *          jobref;
    globus_gram_job_manager_ref_t *     ref;

    globus_gram_job_manager_log(
            manager,
            "Resolving job id %s\n",
            jobid);

    if (request)
    {
        *request = NULL;
    }

    if (!locked)
    {
        globus_mutex_lock(&manager->mutex);
    }
    jobref = globus_hashtable_lookup(&manager->job_id_hash, (void *) jobid);
    if (!jobref)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;
        goto no_such_job;
    }
    ref = globus_hashtable_lookup(
            &manager->request_hash,
            jobref->job_contact_path);

    if (ref)
    {
        ref->reference_count++;
        if (request)
        {
            *request = ref->request;
        }
        globus_gram_job_manager_log(
                manager,
                "Adding reference %s -> %p\n",
                ref->key,
                ref->request);
    }
    else
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;
        globus_gram_job_manager_log(
                manager,
                "Adding reference %s -> NOT FOUND\n",
                jobref->job_contact_path);
    }

no_such_job:
    if (!locked)
    {
        globus_mutex_unlock(&manager->mutex);
    }

    return rc;
}
/* globus_gram_job_manager_add_reference_by_jobid() */

int
globus_gram_job_manager_get_job_id_list(
    globus_gram_job_manager_t *         manager,
    globus_list_t **                    job_id_list)
{
    char *                              job_id;
    globus_gram_job_id_ref_t *          ref;
    int                                 rc = GLOBUS_SUCCESS;

    *job_id_list = NULL;

    globus_mutex_lock(&manager->mutex);
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
    globus_mutex_unlock(&manager->mutex);

    return rc;
}
/* globus_gram_job_manager_get_job_id_list() */

globus_bool_t
globus_gram_job_manager_request_exists(
    globus_gram_job_manager_t *         manager,
    const char *                        key)
{
    globus_bool_t                       result ;
    globus_mutex_lock(&manager->mutex);
    if (globus_hashtable_lookup(&manager->request_hash, (void *) key) != NULL)
    {
        result = GLOBUS_TRUE;
    }
    else
    {
        result = GLOBUS_FALSE;
    }
    globus_mutex_unlock(&manager->mutex);

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

        GlobusTimeReltimeSet(delay, 60, 0);

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


    globus_mutex_lock(&manager->mutex);
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
    globus_mutex_unlock(&manager->mutex);
}
/* globus_l_gram_job_manager_grace_period_expired() */
