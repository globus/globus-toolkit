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
typedef struct
{
    char * name;
    int (*test_function)(void);
}
test_case;

struct monitor_s
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_bool_t                       done;
    globus_bool_t                       versions_present;
    int                                 failure_code;
}
monitor;

static
void
info_callback(
    void *                              user_callback_arg,
    const char *                        job_contact,
    globus_gram_client_job_info_t *     job_info)
{
    struct monitor_s *                  m = user_callback_arg;

    globus_mutex_lock(&m->mutex);
    m->done = GLOBUS_TRUE;
    if (globus_hashtable_lookup(&job_info->extensions, "version") != NULL &&
        globus_hashtable_lookup(&job_info->extensions, "toolkit-version") != NULL)
    {
        m->versions_present = GLOBUS_TRUE;
    }
    m->failure_code = job_info->protocol_error_code;
    globus_cond_signal(&m->cond);
    globus_mutex_unlock(&m->mutex);
}
/* info_callback() */

/* Check that passing null parameters to
 * globus_gram_client_register_get_jobmanager_version() don't cause crashes and
 * return reasonable error values.
 */
static
int
null_param_test(void)
{
    int                                 rc;

    rc = globus_gram_client_register_get_jobmanager_version(
            NULL,
            NULL /*optional attr*/,
            info_callback,
            NULL /* optional callback_arg*/);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("globus_gram_client_register_get_jobmanager_version() didn't return expected error: %d (%s)",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_client_register_get_jobmanager_version(
            rm_contact,
            NULL /*optional attr*/,
            NULL,
            NULL /* optional callback_arg*/);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("globus_gram_client_register_get_jobmanager_version() didn't return expected error: %d (%s)",
            rc,
            globus_gram_protocol_error_string(rc)));


    rc = GLOBUS_SUCCESS;

    return rc;
}
/* null_param_test() */

/* Check that passing bad contact string to
 * globus_gram_client_get_jobmanager_version() don't cause crashes and
 * returns a reasonable error value.
 */
static
int
bad_contact_test(void)
{
    int                                 rc;

    monitor.done = monitor.versions_present = GLOBUS_FALSE;
    monitor.failure_code = 0;

    rc = globus_gram_client_register_get_jobmanager_version(
            "grid.example.org:2119",
            NULL,
            info_callback,
            &monitor);

    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER,
            ("globus_gram_client_register_get_jobmanager_version() didn't fail as expected: %d (%s)",
            rc,
            globus_gram_protocol_error_string(rc)));
    rc = GLOBUS_SUCCESS;

    return rc;
}
/* bad_contact_test() */

/* Check that using globus_gram_client_get_jobmanager_version() to talk
 * to the resource management contact specified on the command line yields
 * a response that can be parsed out to include the version and toolkit-version
 * attributes.
 */
static
int
version_test(void)
{
    int                                 rc;

    monitor.done = monitor.versions_present = GLOBUS_FALSE;
    monitor.failure_code = 0;

    rc = globus_gram_client_register_get_jobmanager_version(
            rm_contact,
            NULL,
            info_callback,
            &monitor);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("globus_gram_client_register_get_jobmanager_version() failed: %d (%s)",
            rc,
            globus_gram_protocol_error_string(rc)));

    globus_mutex_lock(&monitor.mutex);
    while (!monitor.done)
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);

    test_assert(
            monitor.failure_code == GLOBUS_SUCCESS,
            ("globus_gram_client_register_get_jobmanager_version() callback indicated failure: %d (%s)",
            rc,
            globus_gram_protocol_error_string(rc)));

    test_assert(
            monitor.versions_present == GLOBUS_TRUE,
            ("globus_gram_client_register_get_jobmanager_version() callback didn't get version info"));

    return rc;
}
/* version_test() */

int main(int argc, char *argv[])
{
    test_case                           tests[] =
    {
        TEST_CASE(null_param_test),
        TEST_CASE(bad_contact_test),
        TEST_CASE(version_test)
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
    globus_mutex_init(&monitor.mutex, NULL);
    globus_cond_init(&monitor.cond, NULL);
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
