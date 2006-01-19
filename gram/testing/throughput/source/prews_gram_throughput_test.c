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

#include "globus_i_prews_gram_throughput_test.h"



/* global to let threads know when to stop submitting jobs */
struct test_monitor_s   test_monitor;


static
void
globus_l_module_activate(
    globus_module_descriptor_t *        module)
{
    int                                 rc;

    rc = globus_module_activate(module);
    if(rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "prews-gram-throughput-test: "
                        "error while activating %s\n",
                module->module_name);
        globus_i_print_error(rc);
        exit(1);
    }
}


static void
globus_l_interrupt_cb(
    void *                              user_arg)
{
    fprintf(stderr, "\nCanceling...\n");

    exit(1);
}



globus_result_t
globus_l_submit_job(
    const char *                        callback_contact,
    const char *                        resource_manager,
    int                                 job_duration,
    char **                             job_contact)
{
    char                                rsl[300];
    int                                 job_status;
    int                                 failure_code;
    int                                 rc = 0;

    globus_libc_sprintf(rsl,
            "&(executable=/bin/sleep)(arguments=%d)",
            job_duration);

    globus_gram_client_job_request(resource_manager,
            rsl,
            0,
            callback_contact,
            job_contact);

    rc = globus_gram_client_job_callback_register(*job_contact,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED | 
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE,
            callback_contact,
            &job_status,
            &failure_code);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Unable to register callback for %s\n", 
                *job_contact);
        globus_i_print_error(rc);
    }

    return GLOBUS_SUCCESS;
}



void
globus_l_test_duration_timeout(
    void *                              user_arg)
{
    globus_mutex_lock(&test_monitor.mutex);
    {
        printf("Test done - waiting for jobs to finish\n");
        test_monitor.done = GLOBUS_TRUE;
        globus_cond_signal(&test_monitor.cond);
    }
    globus_mutex_unlock(&test_monitor.mutex);
}


void
globus_l_gram_client_callback(
    void *  user_callback_arg,
    char *  job_contact,
    int     state,
    int     errorcode)
{
    globus_i_client_thread_t *          client_thread;
    globus_list_t *                     list_entry;
    int                                 job_status;
    int                                 failure_code;
    int                                 rc = 0;

    client_thread = (globus_i_client_thread_t *)user_callback_arg;

    rc = globus_gram_client_job_status(job_contact,
            &job_status, 
            &failure_code);
    if (rc != GLOBUS_SUCCESS)
    {
        globus_i_print_error(rc);
    }

    if (job_status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
    {
        globus_i_stats_job_succeeded();
    }
    else
    {
        globus_i_stats_job_failed();
    }

    globus_mutex_lock(&client_thread->mutex);
    {
        /* find and remove the job from this thread's job list */
        list_entry = client_thread->job_list;
        while (list_entry != NULL &&
                globus_libc_strcmp(list_entry->datum, job_contact) != 0)
        {
            list_entry = list_entry->next;
        }
        if (list_entry == NULL)
        {
            fprintf(stderr, "Could not find job contact: %s\n", job_contact);
            exit(1);
        }
        globus_list_remove(&(client_thread->job_list), list_entry);

        /* globus_gram_client_job_contact_free(job_contact); */

        globus_cond_signal(&client_thread->cond);
    }
    globus_mutex_unlock(&client_thread->mutex);
}


void
globus_l_client_thread(
    void *                              user_arg)
{
    globus_i_info_t *                   info;
    globus_i_client_thread_t            client_thread;
    char *                              callback_contact;
    char *                              job_contact;
    int                                 rc = 0;

    info = (globus_i_info_t *)user_arg;

    printf("New client thread started\n");

    globus_mutex_lock(&test_monitor.mutex);
    test_monitor.active_threads++;
    globus_mutex_unlock(&test_monitor.mutex);

    memset(&client_thread, 0, sizeof(client_thread));
    globus_mutex_init(&client_thread.mutex, NULL);
    globus_cond_init(&client_thread.cond, NULL);

    /* register the callback for job state changes
       use user_arg to pass the client thread information */
    rc = globus_gram_client_callback_allow(&globus_l_gram_client_callback,
                                           &client_thread,
                                           &callback_contact);
    if (rc != GLOBUS_SUCCESS)
    {
        globus_i_print_error(rc);
        exit(1);
    }

    while (!test_monitor.done)
    {
        while (!test_monitor.done &&
               globus_list_size(client_thread.job_list) < info->load)
        {
            globus_i_stats_job_started();
            rc = globus_l_submit_job(callback_contact,
                    info->resource_manager,
                    info->job_duration,
                    &job_contact);
            if (rc != GLOBUS_SUCCESS)
            {
                /* should a failed sbumit be a fatal error for the test? */
                globus_i_print_error(rc);
                globus_i_stats_job_failed();
            }
            else
            {
                globus_list_insert(&client_thread.job_list,
                                   (void *)job_contact);
            }
        }

        globus_mutex_lock(&client_thread.mutex);
        {
            globus_cond_wait(&client_thread.cond, &client_thread.mutex);
        }
        globus_mutex_unlock(&client_thread.mutex);
    }

    /* wait for jobs to finish */
    while (globus_list_size(client_thread.job_list) > 0)
    {
        globus_mutex_lock(&client_thread.mutex);
        {
            globus_cond_wait(&client_thread.cond, &client_thread.mutex);
        }
        globus_mutex_unlock(&client_thread.mutex);
    }

    globus_gram_client_callback_disallow(callback_contact);
    
    globus_mutex_lock(&test_monitor.mutex);
    test_monitor.active_threads--;
    globus_cond_signal(&test_monitor.cond);
    globus_mutex_unlock(&test_monitor.mutex);

    printf("Client thread finished successfully\n");
}


void
globus_i_print_error(
    globus_result_t                     result)
{
    char *                              tmp;

    tmp = globus_error_print_friendly(globus_error_peek(result));
    fprintf(stderr, "prews-gram-throughput-test: %s", tmp);
    globus_free(tmp);
}

void
globus_i_print_warning(
    globus_result_t                     result)
{
    char *                              tmp;

    tmp = globus_error_print_friendly(globus_error_peek(result));
    fprintf(stderr, "prews-gram-throughput-test: Warning: %s", tmp);
    globus_free(tmp);
}


int
main(
    int                                 argc,
    char **                             argv)
{
    globus_i_info_t                     info;
    int                                 rc = 0;
    int                                 i;
    globus_reltime_t                    delay;
    globus_thread_t *                   thread;

    globus_l_module_activate(GLOBUS_COMMON_MODULE);
    globus_l_module_activate(GLOBUS_POLL_MODULE);
    globus_l_module_activate(GLOBUS_IO_MODULE);
    globus_l_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_l_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    globus_l_module_activate(GLOBUS_GRAM_CLIENT_MODULE);

    memset(&info, 0, sizeof(info));

    /* defaults */
    info.resource_manager = globus_common_create_string("localhost");
    info.job_duration     = 5;
    info.load             = 1;
    info.num_threads      = 1;
    info.test_duration    = 1;

    globus_i_parse_arguments(argc, argv, &info);

    rc = globus_callback_register_signal_handler(
        GLOBUS_SIGNAL_INTERRUPT, GLOBUS_TRUE, globus_l_interrupt_cb, NULL);
    if(rc != GLOBUS_SUCCESS)
    {
        globus_i_print_error(rc);
        fprintf(stderr, "registering signal handler\n");
        exit(1);
    }

    globus_mutex_init(&test_monitor.mutex, NULL);
    globus_cond_init(&test_monitor.cond, NULL);
    test_monitor.done = GLOBUS_FALSE;
    test_monitor.active_threads = 0;

    globus_i_stats_start();

    /* starting M client threads, each one maintaining N jobs running */
    for (i = 0; i < info.num_threads; i++)
    {
        thread = (globus_thread_t *)globus_malloc(sizeof(globus_thread_t));
        globus_thread_create(thread, NULL, globus_l_client_thread,
                             (void *)&info);
    }

    /* set up the callback for the test duration timer */
    globus_mutex_lock(&test_monitor.mutex);
    {
        GlobusTimeReltimeSet(delay, info.test_duration, 0);
        globus_callback_register_oneshot(
            NULL,
            &delay,
            globus_l_test_duration_timeout,
            NULL);

        while(!test_monitor.done)
        {
            globus_cond_wait(&test_monitor.cond, &test_monitor.mutex);
        }
    }
    globus_mutex_unlock(&test_monitor.mutex);

    /* wait for outstanding jobs to finish */
    globus_mutex_lock(&test_monitor.mutex);
    {
        while(test_monitor.active_threads > 0)
        {
            printf("%d threads still running\n", test_monitor.active_threads);
            globus_cond_wait(&test_monitor.cond, &test_monitor.mutex);
        }
    }
    globus_mutex_unlock(&test_monitor.mutex);

    globus_i_stats_finish();
    globus_i_stats_summary(info.num_threads, info.load);

    globus_module_deactivate_all();
    return rc;
}


