/*
 * Copyright 1999-2017 University of Chicago
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

#include "globus_common.h"
#include "globus_error_errno.h"
#include "globus_error_string.h"
#include "globus_test_tap.h"

void
test_errno_construct(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_errno_error(
            GLOBUS_COMMON_MODULE,
            NULL,
            ERANGE);

    ok(error != NULL, __func__);

    globus_object_free(error);
}

void
test_get_errno(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_errno_error(
            GLOBUS_COMMON_MODULE,
            NULL,
            ERANGE);

    ok(globus_error_errno_get_errno(error) == ERANGE, __func__);

    globus_object_free(error);
}

void
test_set_get_errno(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_errno_error(
            GLOBUS_COMMON_MODULE,
            NULL,
            EDOM);
    globus_error_errno_set_errno(error, ERANGE);

    ok(globus_error_errno_get_errno(error) == ERANGE, __func__);

    globus_object_free(error);
}

void
test_wrong_type_get_errno(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_string(
            GLOBUS_COMMON_MODULE,
            NULL,
            "Hello");
    ok (globus_error_errno_get_errno(error) == 0, __func__);

    globus_object_free(error);
}

void
test_wrong_type_set_errno(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_string(
            GLOBUS_COMMON_MODULE,
            NULL,
            "Hello");
    ok ((globus_error_errno_set_errno(error, ERANGE), 1), __func__);

    globus_object_free(error);
}

void
test_errno_match_ok(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_errno_error(
                    GLOBUS_COMMON_MODULE,
                    NULL,
                    ERANGE);
    ok (globus_error_errno_match(error, GLOBUS_COMMON_MODULE, ERANGE),
            __func__);

    globus_object_free(error);
}

void
test_errno_match_wrong_type(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_string(
                    GLOBUS_COMMON_MODULE,
                    NULL,
                    "Hello");
    ok (!globus_error_errno_match(error, GLOBUS_COMMON_MODULE, ERANGE),
            __func__);

    globus_object_free(error);
}

void
test_errno_match_cause_ok(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_string(
            GLOBUS_COMMON_MODULE,
            globus_error_construct_errno_error(
                    GLOBUS_COMMON_MODULE,
                    NULL,
                    ERANGE),
            "Hello");
    ok (globus_error_errno_match(error, GLOBUS_COMMON_MODULE, ERANGE),
            __func__);

    globus_object_free(error);
}

void
test_errno_match_wrong_errno(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_errno_error(
                    GLOBUS_COMMON_MODULE,
                    NULL,
                    ERANGE);
    ok (!globus_error_errno_match(error, GLOBUS_COMMON_MODULE, EDOM),
            __func__);

    globus_object_free(error);
}

void
test_errno_match_wrong_module(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_errno_error(
                    GLOBUS_CALLBACK_MODULE,
                    NULL,
                    ERANGE);
    ok (!globus_error_errno_match(error, GLOBUS_COMMON_MODULE, ERANGE),
            __func__);

    globus_object_free(error);
}

void
test_errno_match_cause_wrong_errno(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_string(
            GLOBUS_COMMON_MODULE,
            globus_error_construct_errno_error(
                    GLOBUS_COMMON_MODULE,
                    NULL,
                    ERANGE),
            "Hello");
    ok (!globus_error_errno_match(error, GLOBUS_COMMON_MODULE, EDOM),
            __func__);

    globus_object_free(error);
}

void
test_errno_match_cause_wrong_module(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_string(
            GLOBUS_COMMON_MODULE,
            globus_error_construct_errno_error(
                    GLOBUS_CALLBACK_MODULE,
                    NULL,
                    ERANGE),
            "Hello");
    ok (!globus_error_errno_match(error, GLOBUS_COMMON_MODULE, ERANGE),
            __func__);

    globus_object_free(error);
}

void
test_errno_search_ok(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_errno_error(
                    GLOBUS_COMMON_MODULE,
                    NULL,
                    ERANGE);
    ok (globus_error_errno_search(error) == ERANGE, __func__);

    globus_object_free(error);
}

void
test_errno_search_cause_ok(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_string(
            GLOBUS_COMMON_MODULE,
            globus_error_construct_errno_error(
                    GLOBUS_CALLBACK_MODULE,
                    NULL,
                    ERANGE),
            "Hello");
    ok (globus_error_errno_search(error) == ERANGE, __func__);

    globus_object_free(error);
}

void
test_errno_search_wrong_type(void)
{
    globus_object_t                    *error = NULL;

    error = globus_error_construct_string(
            GLOBUS_COMMON_MODULE,
            NULL,
            "Hello");
    ok (globus_error_errno_search(error) == 0, __func__);

    globus_object_free(error);
}

typedef void (*test_case)(void);

int main()
{
    test_case tests[] =
    {
        test_errno_construct,
        test_get_errno,
        test_set_get_errno,
        test_wrong_type_get_errno,
        test_wrong_type_set_errno,
        test_errno_match_ok,
        test_errno_match_wrong_type,
        test_errno_match_cause_ok,
        test_errno_match_wrong_errno,
        test_errno_match_wrong_module,
        test_errno_match_cause_wrong_module,
        test_errno_match_cause_wrong_errno,
        test_errno_search_ok,
        test_errno_search_cause_ok,
        test_errno_search_wrong_type,
    };
    size_t num_tests = sizeof(tests)/(sizeof(*tests));
    printf("1..%zu\n", num_tests);

    globus_module_activate(GLOBUS_COMMON_MODULE);
    for (size_t i = 0; i < num_tests; i++)
    {
        tests[i]();
    }
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return TEST_EXIT_CODE;
}
