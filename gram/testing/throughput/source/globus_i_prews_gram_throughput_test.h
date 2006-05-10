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

#ifndef GLOBUS_I_PREWS_GRAM_THROUGHPUT_TEST_H_
#define GLOBUS_I_PREWS_GRAM_THROUGHPUT_TEST_H_

#include "globus_common.h"
#include "globus_gram_protocol.h"
#include "globus_gram_client.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>



#define GlobusLErrorWrapResult(doing__, result__)                           \
    (globus_error_put(                                                      \
        globus_error_construct_error(                                       \
            NULL,                                                           \
            globus_error_get(result__),                                     \
            0, __FILE__, _globus_func_name, __LINE__,                       \
            "Error %s", (doing__))))



typedef struct
{
    /* parsed options */
    globus_bool_t     help;

    char *            resource_manager;

    int               job_duration;
    int               load;
    int               num_threads;
    int               test_duration;

} globus_i_info_t;


typedef struct
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_list_t *                     job_list;
} globus_i_client_thread_t;


struct test_monitor_s
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_bool_t                       done;
    int                                 active_threads;
};


static void
globus_l_interrupt_cb(
    void *   user_arg);

globus_result_t
globus_l_submit_job(
    const char *                        callback_contact,
    const char *                        resource_manager,
    int                                 job_duration,
    char **                             job_contact);

void
globus_i_parse_arguments(
    int                                 argc,
    char **                             argv,
    globus_i_info_t *                   info);

void
globus_l_test_duration_timeout(
    void *                              user_arg);

void
globus_l_client_thread(
    void *                              user_arg);

void
globus_i_print_error(
    globus_result_t                     result);

void
globus_i_print_warning(
    globus_result_t                     result);

void
globus_i_stats_start();

void
globus_i_stats_finish();

void
globus_i_stats_job_started();

void
globus_i_stats_job_failed();

void
globus_i_stats_job_succeeded();

void
globus_i_stats_brief_summary();

void
globus_i_stats_summary(int num_threads, int load);

#endif

