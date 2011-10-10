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
#include "globus_gass_cache.h"
#include "globus_gram_jobmanager_callout_error.h"

#include <sys/wait.h>

static
int
globus_l_gram_job_manager_activate(void);

static
int
globus_l_gram_deactivate(void);

static
globus_result_t
globus_l_gram_create_stack(
    const char *                        driver_name,
    globus_xio_stack_t *                stack,
    globus_xio_driver_t *               driver);

static
void
globus_l_waitpid_callback(
    void *                              user_arg);

static
void
reply_and_exit(
    globus_gram_job_manager_t *         manager,
    int                                 rc,
    char *                              gt3_failure_message);

static
void
globus_l_gram_process_pending_restarts(
    void *                              arg);

static
globus_mutex_t                          globus_l_waitpid_callback_lock;
static
globus_callback_handle_t                globus_l_waitpid_callback_handle =
        GLOBUS_NULL_HANDLE;
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

int
main(
    int                                 argc,
    char **                             argv)
{
    int                                 rc;
    globus_gram_job_manager_config_t    config;
    globus_gram_job_manager_t           manager;
    char *                              sleeptime_str;
    long                                sleeptime = 0;
    globus_bool_t                       debug_mode_service = GLOBUS_FALSE;
    globus_bool_t                       located_active_jm = GLOBUS_FALSE;
    int                                 http_body_fd = -1;
    int                                 context_fd = -1;
    gss_cred_id_t                       cred = GSS_C_NO_CREDENTIAL;
    OM_uint32                           major_status, minor_status;
    pid_t                               forked_starter = 0;

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
    /* Don't export these to the perl scripts */
    fcntl(STDIN_FILENO, F_SETFD, (int) 1);
    fcntl(STDOUT_FILENO, F_SETFD, (int) 1);
    fcntl(STDERR_FILENO, F_SETFD, (int) 1);

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
    rc = globus_gram_job_manager_config_init(&config, argc, argv);
    if (rc != GLOBUS_SUCCESS)
    {
        reply_and_exit(NULL, rc, NULL);
    }

    globus_thread_key_create(
            &globus_i_gram_request_key,
            NULL);

    rc = globus_gram_job_manager_logging_init(&config);
    if (rc != GLOBUS_SUCCESS)
    {
        exit(1);
    }
    if (getenv("GRID_SECURITY_HTTP_BODY_FD") == NULL)
    {
        debug_mode_service = GLOBUS_TRUE;
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
    if(config.tcp_source_range != NULL)
    {
        globus_libc_setenv("GLOBUS_TCP_SOURCE_RANGE",
                           config.tcp_source_range,
                           GLOBUS_TRUE);
    }

    /* Activate all of the modules we will be using */
    rc = globus_l_gram_job_manager_activate();
    if(rc != GLOBUS_SUCCESS)
    {
        exit(1);
    }

    /*
     * Get the delegated credential (or the default credential if we are
     * run without a client. Don't care about errors in the latter case.
     */
    major_status = globus_gss_assist_acquire_cred(
            &minor_status,
            GSS_C_BOTH,
            &cred);
    if ((!debug_mode_service) && GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status(
                stderr,
                "Error acquiring security credential\n",
                major_status,
                minor_status,
                0);
        exit(1);
    }

    if (cred != GSS_C_NO_CREDENTIAL)
    {
        unsigned long hash;
        char * newtag;

        rc = globus_gram_gsi_get_dn_hash(
                cred,
                &hash);
        if (rc == GLOBUS_SUCCESS)
        {
            newtag = globus_common_create_string("%s%s%lx",
                    strcmp(config.service_tag, "untagged") == 0
                            ? "" : config.service_tag,
                    strcmp(config.service_tag, "untagged") == 0
                            ? "" : ".",
                    hash);
            free(config.service_tag);
            config.service_tag = newtag;
        }
    }

    /*
     * Remove delegated proxy from disk.
     */
    if ((!debug_mode_service) && getenv("X509_USER_PROXY") != NULL)
    {
        remove(getenv("X509_USER_PROXY"));
    }

    /* Set up LRM-specific state based on our configuration. This will create
     * the job contact listener, start the SEG if needed, and open the log
     * file if needed.
     */
    rc = globus_gram_job_manager_init(&manager, cred, &config);
    if(rc != GLOBUS_SUCCESS)
    {
        reply_and_exit(NULL, rc, manager.gt3_failure_message);
    }

    /*
     * Pull out file descriptor numbers for security context and job request
     * from the environment (set by the gatekeeper)
     */
    if (!debug_mode_service)
    {
        char * fd_env = getenv("GRID_SECURITY_HTTP_BODY_FD");

        rc = sscanf(fd_env ? fd_env : "-1", "%d", &http_body_fd);
        if (rc != 1 || http_body_fd < 0)
        {
            fprintf(stderr, "Error locating http body fd\n");
            exit(1);
        }
        fcntl(http_body_fd, F_SETFD, 1);

        fd_env = getenv("GRID_SECURITY_CONTEXT_FD");
        rc = sscanf(fd_env ? fd_env : "-1", "%d", &context_fd);
        if (rc != 1 || context_fd < 0)
        {
            fprintf(stderr, "Error locating security context fd\n");
            exit(1);
        }
        fcntl(context_fd, F_SETFD, 1);
    }


    /* Redirect stdin from /dev/null, we'll handle stdout after the reply is
     * sent
     */
    freopen("/dev/null", "r", stdin);

    /* Here we'll either become the active job manager to process all
     * jobs for this user/host/lrm combination, or we'll hand off the
     * file descriptors containing the info to the active job manager
     */
    while (!located_active_jm)
    {
        /* We'll try to get the lock file associated with being the
         * active job manager here. If we get the OLD_JM_ALIVE error
         * somebody else has it
         */
        rc = globus_gram_job_manager_startup_lock(
                &manager,
                &manager.lock_fd);
        if (rc == GLOBUS_SUCCESS)
        {
            /* We've acquired the lock. We will fork a new process to act like
             * all other job managers which don't have the lock, and continue
             * on in this process managing jobs for this LRM.  Note that the
             * child process does not inherit the lock
             */
            if (!debug_mode_service)
            {
                int save_errno = 0;

                /* We've acquired the manager lock */
                forked_starter = fork();
                save_errno = errno;

                if (forked_starter < 0)
                {
                    if (sleeptime != 0)
                    {
                        sleep(sleeptime);
                    }

                    fprintf(stderr, "fork failed: %s", strerror(save_errno));
                    exit(1);
                }
                else if (forked_starter == 0)
                {
                    /* We are the child process. We'll close our reference to
                     * the lock and let the other process deal with jobs
                     */
                    close(manager.lock_fd);
                    manager.lock_fd = -1;
                }
                globus_logging_update_pid();
                if (sleeptime != 0)
                {
                    sleep(sleeptime);
                }

            }

            if (manager.lock_fd >= 0)
            {
                /* We hold the manager lock, so we'll store our credential, and
                 * then, try to accept socket connections. If the socket
                 * connections fail, we'll exit, and another process
                 * will be forked to handle them.
                 */
                rc = globus_gram_job_manager_gsi_write_credential(
                        NULL,
                        cred,
                        manager.cred_path);

                if (rc != GLOBUS_SUCCESS)
                {
                    fprintf(stderr, "write cred failed\n");
                    exit(1);
                }
                if (!debug_mode_service)
                {
                    close(http_body_fd);
                    http_body_fd = -1;
                }

                rc = globus_gram_job_manager_startup_socket_init(
                        &manager,
                        &manager.active_job_manager_handle,
                        &manager.socket_fd);
                if (rc != GLOBUS_SUCCESS)
                {
                    /* This releases our lock. Either the child process will
                     * attempt to acquire the lock again or some another job
                     * manager will acquire the lock
                     */
                    exit(0);
                }
                assert(manager.socket_fd != -1);
            }
        }
        else if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE)
        {
            /* Some system error. Try again */
            continue;
        }

        /* If manager.socket_fd != -1 then we are the main job manager for this
         * LRM.
         * We will restart all existing jobs and then allow the startup
         * socket to accept new jobs from other job managers.
         */
        if (manager.socket_fd != -1)
        {
            GlobusTimeAbstimeGetCurrent(manager.usagetracker->jm_start_time);            
            globus_i_gram_usage_stats_init(&manager);
            globus_i_gram_usage_start_session_stats(&manager);

            located_active_jm = GLOBUS_TRUE;

            /* Load existing jobs. The show must go on if this fails, unless it
             * fails with a misconfiguration error
             */
            rc = globus_gram_job_manager_request_load_all(
                    &manager);
            if (rc == GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED)
            {
                if (forked_starter > 0)
                {
                    kill(forked_starter, SIGTERM);
                    forked_starter = 0;
                }
                reply_and_exit(NULL, rc, manager.gt3_failure_message);
            }
            if (context_fd != -1)
            {
                close(context_fd);
                context_fd = -1;
            }
            freopen("/dev/null", "a", stdout);

            /* At this point, seg_last_timestamp is the earliest last timestamp 
             * for any pre-existing jobs. If that is 0, then we don't have any
             * existing jobs so we'll just ignore seg events prior to now.
             */
            if (manager.seg_last_timestamp == 0)
            {
                manager.seg_last_timestamp = time(NULL);
            }

            /* Start off the SEG if we need it.
             */
            if (config.seg_module != NULL || 
                strcmp(config.jobmanager_type, "fork") == 0 ||
                strcmp(config.jobmanager_type, "condor") == 0)
            {
                rc = globus_gram_job_manager_init_seg(&manager);

                /* TODO: If SEG load fails and load_all added some to the 
                 * job_id hash, they will need to be pushed into the state
                 * machine so that polling fallback can happen.
                 */
                if (rc != GLOBUS_SUCCESS)
                {
                    config.seg_module = NULL;
                }
            }
            /* GRAM-128:
             * Register a periodic event to process the GRAM jobs that were
             * reloaded from their job state files at job manager start time.
             * This will acquire and then release a reference to each job,
             * which, behind the scenes, will kick of the state machine
             * for that job if needed.
             */
            if (!globus_list_empty(manager.pending_restarts))
            {
                globus_reltime_t        restart_period;

                GlobusTimeReltimeSet(restart_period, 1, 0);

                rc = globus_callback_register_periodic(
                        &manager.pending_restart_handle,
                        NULL,
                        &restart_period,
                        globus_l_gram_process_pending_restarts,
                        &manager);
                        
            }
        }
        else if (http_body_fd)
        {
            /* If manager.socket_fd == -1 then we are either the child from the
             * fork or another process started somehow (either command-line
             * invocation or via a job submit). If we have a client, then we'll
             * send our fds to the job manager with the lock and let it process
             * the job.
             *
             * If this succeeds, we set located_active_jm and leave the loop.
             * Otherwise, we try again.
             */
            rc = globus_gram_job_manager_starter_send(
                    &manager,
                    http_body_fd,
                    context_fd,
                    fileno(stdout),
                    cred);
            if (rc == GLOBUS_SUCCESS)
            {
                located_active_jm = GLOBUS_TRUE;
                close(http_body_fd);
                close(context_fd);
                manager.done = GLOBUS_TRUE;
            }
            else
            {
                globus_libc_usleep(250000);
            }
        }
        else
        {
            /* We were started by hand, but another process is currently the
             * main job manager
             */
            unsigned long realpid = 0;
            FILE * pidin = fopen(manager.pid_path, "r");
            fscanf(pidin, "%lu", &realpid);
            fclose(pidin);

            fprintf(stderr, "Other job manager process with pid %lu running and processing jobs\n",
                    realpid);

            exit(0);
        }
    }

    globus_mutex_init(&globus_l_waitpid_callback_lock, NULL);

    /*
     * Register periodic event to clean up zombie if we forked a child
     * process
     */
    if (forked_starter != 0)
    {
        globus_reltime_t                delay, period;

        GlobusTimeReltimeSet(delay, 0, 0);
        GlobusTimeReltimeSet(period, 10, 0);

        globus_callback_register_periodic(
                &globus_l_waitpid_callback_handle,
                &delay,
                &period,
                globus_l_waitpid_callback,
                &forked_starter);
    }

    GlobusGramJobManagerLock(&manager);
    if (manager.socket_fd != -1 &&
        globus_hashtable_empty(&manager.request_hash) &&
        manager.grace_period_timer == GLOBUS_NULL_HANDLE)
    {
        globus_gram_job_manager_set_grace_period_timer(&manager);
    }


    /* For the active job manager, this will block until all jobs have
     * terminated. For any other job manager, the monitor.done is set to
     * GLOBUS_TRUE and this falls right through.
     */
    while (! manager.done)
    {
        GlobusGramJobManagerWait(&manager);
    }
    GlobusGramJobManagerUnlock(&manager);

    globus_mutex_lock(&globus_l_waitpid_callback_lock);
    if (globus_l_waitpid_callback_handle != GLOBUS_NULL_HANDLE)
    {
        globus_callback_unregister(
                globus_l_waitpid_callback_handle,
                NULL,
                NULL,
                0);
        globus_l_waitpid_callback_handle = GLOBUS_NULL_HANDLE;
    }
    globus_mutex_unlock(&globus_l_waitpid_callback_lock);


    globus_gram_job_manager_log(
            &manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_INFO,
            "event=gram.end "
            "level=DEBUG "
            "\n");

    /* Clean-up to do if we are the active job manager only */
    if (manager.socket_fd != -1)
    {
        globus_gram_job_manager_script_close_all(&manager);
        globus_i_gram_usage_end_session_stats(&manager);
        globus_i_gram_usage_stats_destroy(&manager);
        remove(manager.pid_path);
        remove(manager.cred_path);
        remove(manager.socket_path);
        remove(manager.lock_path);
    }
    globus_gram_job_manager_destroy(&manager);
    globus_gram_job_manager_config_destroy(&config);

    rc = globus_l_gram_deactivate();
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "deactivation failed with rc=%d\n",
                rc);
        exit(1);
    }

/*
    {
        const char * gk_jm_id_var = "GATEKEEPER_JM_ID";
        const char * gk_jm_id = globus_libc_getenv(gk_jm_id_var);

        globus_gram_job_manager_request_acct(
                request,
                "%s %s JM exiting\n",
                gk_jm_id_var, gk_jm_id ? gk_jm_id : "none");
    }
*/


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
    int                                 rc;
    globus_result_t                     result;
    globus_module_descriptor_t *        modules[] =
    {
        GLOBUS_COMMON_MODULE,
        GLOBUS_CALLOUT_MODULE,
        GLOBUS_GSI_SYSCONFIG_MODULE,
        GLOBUS_GSI_GSSAPI_MODULE,
        GLOBUS_GSI_GSS_ASSIST_MODULE,
        GLOBUS_GRAM_JOBMANAGER_CALLOUT_ERROR_MODULE,
        GLOBUS_XIO_MODULE,
        GLOBUS_GRAM_PROTOCOL_MODULE,
        GLOBUS_GASS_CACHE_MODULE,
        NULL
    };
    globus_module_descriptor_t *        failed_module = NULL;

    rc = globus_module_activate_array(modules, &failed_module);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error (%d) activating %s\n", 
                rc, failed_module->module_name);
        goto activate_failed;
    }
    result = globus_l_gram_create_stack(
            "file",
            &globus_i_gram_job_manager_file_stack,
            &globus_i_gram_job_manager_file_driver);

    if (result != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_FAILURE;
        goto stack_init_failed;
    }

    result = globus_l_gram_create_stack(
            "popen",
            &globus_i_gram_job_manager_popen_stack,
            &globus_i_gram_job_manager_popen_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_file_stack;
    }

    if (rc != GLOBUS_SUCCESS)
    {
destroy_file_stack:
        globus_xio_stack_destroy(globus_i_gram_job_manager_file_stack);
        globus_xio_driver_unload(globus_i_gram_job_manager_file_driver);
stack_init_failed:
activate_failed:
        ;
    }
    return rc;
}
/* globus_l_gram_job_manager_activate() */

static
int
globus_l_gram_deactivate(void)
{
    (void) globus_xio_stack_destroy(
            globus_i_gram_job_manager_file_stack);

    (void) globus_xio_stack_destroy(
            globus_i_gram_job_manager_popen_stack);

    globus_xio_driver_unload(globus_i_gram_job_manager_file_driver);
    globus_xio_driver_unload(globus_i_gram_job_manager_popen_driver);

    return globus_module_deactivate_all();
}
/* globus_l_gram_deactivate(void) */

static
globus_result_t
globus_l_gram_create_stack(
    const char *                        driver_name,
    globus_xio_stack_t *                stack,
    globus_xio_driver_t *               driver)
{
    globus_result_t                     result;

    result = globus_xio_driver_load(
            driver_name,
            driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto driver_load_failed;
    }

    result = globus_xio_stack_init(stack, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        goto stack_init_failed;
    }

    result = globus_xio_stack_push_driver(
            *stack,
            *driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto driver_push_failed;
    }

    if (result != GLOBUS_SUCCESS)
    {
driver_push_failed:
        globus_xio_stack_destroy(*stack);
        *stack = NULL;
stack_init_failed:
        globus_xio_driver_unload(*driver);
        *driver = NULL;
driver_load_failed:
        ;
    }

    return result;
}
/* globus_l_gram_create_stack() */


static
void
globus_l_waitpid_callback(
    void *                              user_arg)
{
    pid_t                               childpid = *(pid_t *) user_arg;
    int                                 statint;

    globus_mutex_lock(&globus_l_waitpid_callback_lock);
    if (waitpid(childpid, &statint, WNOHANG) > 0)
    {
        *(pid_t *) user_arg = 0;

        globus_callback_unregister(
                globus_l_waitpid_callback_handle,
                NULL,
                NULL,
                0);
        globus_l_waitpid_callback_handle = GLOBUS_NULL_HANDLE;
    }

    globus_mutex_unlock(&globus_l_waitpid_callback_lock);
}
/* globus_l_waitpid_callback() */

static
void
reply_and_exit(
    globus_gram_job_manager_t *         manager,
    int                                 rc,
    char *                              gt3_failure_message)
{
    int                                 myrc;
    int                                 context_fd;
    gss_ctx_id_t                        response_context = GSS_C_NO_CONTEXT;
    char *                              fd_env;

    fd_env = getenv("GRID_SECURITY_CONTEXT_FD");
    myrc = sscanf(fd_env ? fd_env : "-1", "%d", &context_fd);
    if (myrc == 1 && context_fd >= 0)
    {
        myrc = globus_gram_job_manager_import_sec_context(
                NULL,
                context_fd,
                &response_context);
    }

    globus_gram_job_manager_reply(
            NULL,
            manager,
            rc,
            NULL,
            1,
            response_context,
            gt3_failure_message);
    
    exit(0);
}
/* reply_and_exit() */

static
void
globus_l_gram_process_pending_restarts(
    void *                              arg)
{
    globus_gram_job_manager_t *         manager = arg;
    void *                              key;
    char                                gramid[64];
    int                                 i;
    int                                 rc;
    int                                 restarted=0;
    globus_gram_jobmanager_request_t *  request;

    GlobusGramJobManagerLock(manager);
    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
            "event=gram.process_pending_restarts.start "
            "level=DEBUG "
            "pending_restarts=%d "
            "\n",
            globus_list_size(manager->pending_restarts));
    GlobusGramJobManagerUnlock(manager);

    for (i = 0; i < 20; i++)
    {
        GlobusGramJobManagerLock(manager);
        if (manager->pending_restarts == NULL)
        {
            GlobusGramJobManagerUnlock(manager);
            break;
        }

        key = globus_list_first(manager->pending_restarts);
        globus_assert(key != NULL);
        strncpy(gramid, key, sizeof(gramid));

        GlobusGramJobManagerUnlock(manager);

        /* 
         * This call below will remove the job from the list when it
         * reloads it and start the state machine. 
         */
        rc = globus_gram_job_manager_add_reference(
                manager,
                gramid,
                "restart job",
                &request);

        /* If this fails, then removing the reference will allow it
         * to potentially hit negative counts
         */
        if (rc == GLOBUS_SUCCESS)
        {
            restarted++;
            /* XXX: What if this fails? */
            rc = globus_gram_job_manager_remove_reference(
                    manager,
                    gramid,
                    "restart job");
        }
    }
    GlobusGramJobManagerLock(manager);
    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
            "event=gram.process_pending_restarts.end "
            "level=DEBUG "
            "processed=%d "
            "pending_restarts=%d "
            "\n",
            restarted,
            globus_list_size(manager->pending_restarts));
    if (manager->pending_restarts == NULL)
    {
        globus_callback_unregister(
                manager->pending_restart_handle,
                NULL,
                NULL,
                NULL);
        manager->pending_restart_handle = GLOBUS_NULL_HANDLE;
        GlobusGramJobManagerUnlock(manager);
        return;
    }
    GlobusGramJobManagerUnlock(manager);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
