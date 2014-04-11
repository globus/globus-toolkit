/*
 * Copyright 1999-2010 University of Chicago
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
#include "globus_gram_client.h"
#include "globus_preload.h"
#include "globus_gram_protocol.h"

#define test_assert(assertion, message) \
    if (!(assertion)) \
    { \
        printf("# %s:%d ", __FILE__, __LINE__); \
        printf message; \
        printf("\n"); \
        return 1; \
    }

#define TEST_CASE(x) { #x, x }
#define ARRAY_LEN(x) ((int) (sizeof(x)/sizeof(x[0])))

const char * rm_contact;
struct test_case
{
    char * name;
    int (*test_function)(void);
};

struct monitor
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_gram_protocol_job_state_t    job_state;
    globus_gram_protocol_error_t        protocol_error_code;
    volatile globus_bool_t              done;
};

static
void
info_callback(
    void *                              user_callback_arg,
    const char *                        job_contact,
    globus_gram_client_job_info_t *     job_info)
{
    struct monitor *                    monitor = user_callback_arg;

    if (monitor)
    {
        globus_mutex_lock(&monitor->mutex);
        monitor->job_state = job_info->job_state;
        monitor->protocol_error_code = job_info->protocol_error_code;
        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
        globus_mutex_unlock(&monitor->mutex);
    }
}

static
int
null_param_test(void)
{
    int                                 rc;
    rc = globus_gram_client_register_job_status_with_info(
            NULL,
            NULL /* can be NULL, optional param */,
            info_callback,
            NULL /* can be NULL, optional param */);
    test_assert(rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("Unexpected response to bad job contact \"%s\" (%d)",
                    globus_gram_protocol_error_string(rc),
                    rc));
    rc = globus_gram_client_register_job_status_with_info(
            "https://example.org:1234/1234/134/",
            NULL /* can be NULL, optional param */,
            NULL,
            NULL /* can be NULL, optional param */);
    test_assert(rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("Unexpected response to bad info callback \"%s\" (%d)",
                    globus_gram_protocol_error_string(rc),
                    rc));

    rc = GLOBUS_SUCCESS;

    return rc;
}
/* null_param_test() */

static
int
bad_contact_test(void)
{
    int                                 rc;
    struct monitor                      monitor;

    globus_mutex_init(&monitor.mutex, NULL);
    globus_cond_init(&monitor.cond, NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.job_state = GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED;
    monitor.protocol_error_code = GLOBUS_SUCCESS;

    rc = globus_gram_client_register_job_status_with_info(
            "https://grid.example.org:123/1234/1234/",
            NULL /* can be NULL, optional param */,
            info_callback,
            &monitor);
    test_assert(rc == GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER,
            ("Unexpected response to bad job contact \"%s\" (%d)",
                    globus_gram_protocol_error_string(rc),
                    rc));
    rc = GLOBUS_SUCCESS;
    return rc;
}
/* bad_contact_test() */

static
int
job_status_with_info_test(void)
{
    int                                 rc;
    char *                              job_contact = NULL;
    struct monitor                      monitor;

    globus_mutex_init(&monitor.mutex, NULL);
    globus_cond_init(&monitor.cond, NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.job_state = GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED;
    monitor.protocol_error_code = GLOBUS_SUCCESS;

    rc = globus_gram_client_job_request(
            rm_contact,
            "&(executable=/bin/sleep)(arguments=60)",
            0,
            NULL,
            &job_contact);

    test_assert(rc == GLOBUS_SUCCESS,
            ("Failed submitting sleep job because %s (%d)",
                    globus_gram_protocol_error_string(rc),
                    rc));
    rc = globus_gram_client_register_job_status_with_info(
            job_contact,
            NULL,
            info_callback,
            &monitor);
    free(job_contact);

    test_assert(rc == GLOBUS_SUCCESS,
            ("Failed registering job_status because %s (%d)",
                    globus_gram_protocol_error_string(rc),
                    rc));

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);

    test_assert(monitor.protocol_error_code == GLOBUS_SUCCESS,
            ("Failed to determine job status because %s (%d)",
                    globus_gram_protocol_error_string(
                            monitor.protocol_error_code),
                    monitor.protocol_error_code));

    test_assert(monitor.job_state != 0,
            ("Failed to determine job status"));

                    
    rc = GLOBUS_SUCCESS;

    return rc;
}
/* job_status_with_info_test() */

int
main(int argc, char *argv[])
{
    struct test_case                    tests[] =
    {
        TEST_CASE(null_param_test),
        TEST_CASE(bad_contact_test),
        TEST_CASE(job_status_with_info_test)
    };
    int                                 i;
    int                                 rc;
    int                                 not_ok = 0;

    LTDL_SET_PRELOADED_SYMBOLS();
    rm_contact = getenv("CONTACT_STRING");

    if (argc == 2)
    {
        rm_contact = argv[1];
    }

    if (rm_contact == NULL)
    {
        fprintf(stderr, "Usage: %s RM-CONTACT\n", argv[0]);
        return 1;
    }

    printf("1..%d\n", ARRAY_LEN(tests));

    globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    for (i = 0; i < ARRAY_LEN(tests); i++)
    {
        rc = tests[i].test_function();

        if (rc != 0)
        {
            not_ok++;
            printf("not ok # %s\n", tests[i].name);
        }
        else
        {
            printf("ok\n");
        }
    }
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);

    return not_ok;
}
