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

static
void *
example_accept(
    int                                 socket,
    struct sockaddr                    *addr,
    socklen_t                          *addr_len,
    int                                *sock_out)
{
    int                                 rc = 0;
    example_io_state_t                 *state;

    state = malloc(sizeof(example_io_state_t));

    state->socket = accept(socket, addr, addr_len);

    if (state->socket < 0)
    {
        rc = -1;
        goto err;
    }
    *sock_out = state->socket;

err:
    if (rc < 0)
    {
        free(state);
        state = NULL;
    }
    return state;
}
/* example_accept() */

static
void *
example_connect(
    const char                         *endpoint,
    const char                         *host,
    int                                 port)
{
    struct addrinfo                     hints;
    struct addrinfo                    *res;
    int                                 rc;
    char                                portstr[24];
    example_io_state_t                 *state;

    state = malloc(sizeof(example_io_state_t));
    if (state == NULL)
    {
        goto out;
    }

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;

    sprintf(portstr, "%d", port);

    rc = getaddrinfo(host, &portstr[0], &hints, &res);
    if (rc != 0)
    {
        goto free_state;
    }
    state->socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (state->socket < 0)
    {
        rc = -1;

        goto freeaddr;
    }
    rc = connect(state->socket, res->ai_addr, res->ai_addrlen);
    if (rc < 0)
    {
        rc = -1;

        goto close;
    }
    rc = XACML_RESULT_SUCCESS;
close:
    if (rc < 0)
    {
        close(state->socket);
    }
freeaddr:
    freeaddrinfo(res);
    if (rc < 0)
    {
free_state:
        free(state);
        state = NULL;
    }
out:
    return state;
}
/* example_connect() */

static
int
example_send(
    void                               *arg,
    const char                         *data,
    size_t                              size)
{
    example_io_state_t *                state = arg;
    int                                 sent;
    int                                 rc;

    for (sent = 0; sent < size; )
    {
        rc = send(state->socket, data+sent, size-sent, 0);

        if (rc < 0)
        {
            return -1;
        }
        else
        {
            sent += rc;
        }
    }

    return 0;
}
/* example_send() */

static
size_t
example_recv(
    void                               *arg,
    char                               *data,
    size_t                              size)
{
    example_io_state_t *                state = arg;

    return recv(state->socket, data, size, 0);
}
/* example_recv() */

static
int
example_close(
    void                               *arg)
{
    example_io_state_t *                state = arg;

    close(state->socket);
    free(state);

    return 0;
}
/* example_close() */

xacml_io_descriptor_t
xacml_io_example_descriptor =
{
    "xacml_io_example_descriptor",
    example_accept,
    example_connect,
    example_send,
    example_recv,
    example_close
};

int
server_io_handler_test(void)
{
    xacml_result_t                      rc;
    xacml_server_t                      server;
    xacml_request_t                     request;
    xacml_response_t                    response;
    unsigned short                      port;
    char                                endpoint[] = "http://localhost:XXXXXX";

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_request_init");

    rc = xacml_server_init(&server, test_auth_handler, request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_init");

    rc = xacml_server_set_io_descriptor(
            NULL,
            &xacml_io_example_descriptor);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_server_set_io_descriptor");

    rc = xacml_server_set_io_descriptor(
            server,
            NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_server_set_io_descriptor");

    rc = xacml_server_set_io_descriptor(
            server,
            &xacml_io_example_descriptor);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_server_set_io_descriptor");

    rc = xacml_server_set_port(server, 0);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_start");

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
/* server_io_handler_test() */

int
client_io_handler_test(void)
{
    xacml_result_t                      rc;
    xacml_server_t                      server;
    xacml_request_t                     request;
    xacml_response_t                    response;
    unsigned short                      port;
    char                                endpoint[] = "http://localhost:XXXXXX";

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_request_init");

    rc = xacml_server_init(&server, test_auth_handler, request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_init");

    rc = xacml_request_set_io_descriptor(
            NULL,
            &xacml_io_example_descriptor);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_request_set_io_descriptor");

    rc = xacml_request_set_io_descriptor(
            request,
            NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_request_set_io_descriptor");

    rc = xacml_request_set_io_descriptor(
            request,
            &xacml_io_example_descriptor);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_set_io_descriptor");

    rc = xacml_server_set_port(server, 0);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_start");

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
/* server_io_handler_test() */


int main()
{
    int failed = 0, i;
    test_case test_cases[] =
    {
        TEST_CASE(server_io_handler_test),
        TEST_CASE(client_io_handler_test)
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
