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

#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>

typedef struct
{
    int                                 socket;
}
example_io_state_t;

static
void *
example_accept(
    int                                 socket,
    struct sockaddr                    *addr,
    socklen_t                          *addr_len,
    int                                *sock_out)
{
    int                                 rc;
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

