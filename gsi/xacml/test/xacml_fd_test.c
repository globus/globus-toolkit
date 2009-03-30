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

#include "xacml_client.h"
#include "xacml_server.h"

#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>

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

typedef struct
{
    int                                 socket;
}
example_io_state_t;

static
int
test_auth_handler(
    void *                              handler_arg,
    const xacml_request_t               request,
    xacml_response_t                    response)
{
    int                                 rc;

    rc = xacml_response_set_issuer(response, "me");
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_set_issuer");

    return rc;
}
/* test_auth_handler() */

int
server_fd_test(void)
{
    xacml_result_t                      rc;
    xacml_server_t                      server;
    xacml_request_t                     request;
    xacml_response_t                    response;
    unsigned short                      port;
    char                                endpoint[] = "http://localhost:XXXXXX";
    int                                 fd;
    struct sockaddr_in                  addr;

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_request_init");

    rc = xacml_server_init(&server, test_auth_handler, request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_init");

    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = INADDR_ANY;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERTION(fd >= 0, "socket");

    rc = bind(fd, (struct sockaddr *) &addr, (socklen_t) sizeof(struct sockaddr));
    TEST_ASSERTION(rc == 0, "bind");

    rc = listen(fd, 5);
    TEST_ASSERTION(rc == 0, "listen");

    rc = xacml_server_set_fd(
            server,
            fd);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_server_set_fd");

    rc = xacml_server_start(server);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_start");

    rc = xacml_server_get_port(server, &port);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_get_port");

    sprintf(endpoint, "http://localhost:%hu", port);

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_query(endpoint, request, response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_query");

    xacml_request_destroy(request);
    xacml_response_destroy(response);
    xacml_server_destroy(server);

    return 0;
}
/* server_fd_test() */

int main()
{
    int failed = 0, i;
    test_case test_cases[] =
    {
        TEST_CASE(server_fd_test)
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
