/*
 * Copyright 1999-2008 University of Chicago
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

#include "xacml.h"
#include "xacml_server.h"

#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define TEST_CASE(a) { #a, a }
#define TEST_ASSERTION(a, message) \
    if (!(a)) \
    { \
        fprintf(stderr, "\nFAILED TEST \"%s\" %s:%d\n   %s\n   Expected: %s\n", \
                __func__, __FILE__, __LINE__, message, #a); \
        return -1; \
    }

typedef struct
{
    const char * name;
    int (*test)(void);
} test_case;


int
test_auth_handler(
    void *                              handler_arg,
    const xacml_request_t               request,
    xacml_response_t                    response)
{
    return XACML_RESULT_INVALID_STATE;
}
/* test_auth_handler() */

int
init_destroy_test(void)
{
    xacml_result_t                      rc;
    xacml_server_t                      server;

    rc = xacml_server_init(NULL, test_auth_handler, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_server_init");

    rc = xacml_server_init(&server, NULL, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_server_init");

    rc = xacml_server_init(&server, test_auth_handler, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_init");


    xacml_server_destroy(server);

    xacml_server_destroy(NULL);

    return 0;
}
/* init_destroy_test() */

int
port_test(void)
{
    xacml_result_t                      rc;
    xacml_server_t                      server;
    unsigned short                      port_orig = 1337;
    unsigned short                      port;

    rc = xacml_server_init(&server, test_auth_handler, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_init");

    rc = xacml_server_set_port(server, port_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_server_set_port");

    rc = xacml_server_set_port(NULL, port_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_server_set_port");

    rc = xacml_server_get_port(server, &port);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_server_set_port");
    TEST_ASSERTION(port == port_orig,
                   "xacml_server_set_port");

    rc = xacml_server_set_port(server, 0);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_server_set_port");

    rc = xacml_server_get_port(server, &port);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_server_set_port");
    TEST_ASSERTION(port == 0,
                   "xacml_server_set_port");

    rc = xacml_server_start(server);
    rc = xacml_server_get_port(server, &port);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_server_set_port");
    TEST_ASSERTION(port != 0,
                   "xacml_server_set_port");

    xacml_server_destroy(server);

    return 0;
}
/* port_test() */

int
start_test(void)
{
    xacml_result_t                      rc;
    xacml_server_t                      server;

    rc = xacml_server_init(&server, test_auth_handler, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_init");

    rc = xacml_server_set_port(server, 0);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_server_set_port");

    rc = xacml_server_start(server);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_server_start");

    rc = xacml_server_start(server);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_STATE,
                   "xacml_server_start");

    rc = xacml_server_set_port(server, 0);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_STATE,
                   "xacml_server_set_port");

    xacml_server_destroy(server);

    return 0;
}
/* start_test() */

int main()
{
    int failed = 0, i;
    test_case test_cases[] =
    {
        TEST_CASE(init_destroy_test),
        TEST_CASE(port_test),
        TEST_CASE(start_test)
    };

    printf("1..%d\n",(int) ARRAY_SIZE(test_cases));

    xacml_init();

    for (i = 0; i < ARRAY_SIZE(test_cases); i++)
    {
        if (test_cases[i].test() != 0)
        {
            printf("not ok # %s\n", test_cases[i].name);
            failed++;
        }
        else
        {
            printf("ok # %s\n", test_cases[i].name);
        }
    }

    return failed;
}
