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

/**
 * @defgroup xacml_io_gssapi GSSAPI I/O Handler
 * @ingroup xacml_io
 * This module provides an example of writing an XACML I/O handler that
 * uses GSSAPI to authenticate a TCP connection. All messages sent by
 * this handler are encrypted.
 */
#include "xacml_datatypes.h"

#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>

#include <gssapi.h>

/**
 * Connection state
 * @ingroup xacml_io_gssapi
 * This structure contains the state of the GSSAPI connection. A pointer to
 * one of thsese is returned from example_gss_connect(), and then threaded
 * through all other calls to this I/O handler.
 */
typedef struct
{
    /** TCP socket */
    int                                 socket;
    /** GSSAPI Security context */
    gss_ctx_id_t                        ctx;
    /** GSSAPI Read buffer, if we read a token larger than the buffer
     *  passed to exampl_gss_recv()
     */
    gss_buffer_desc                     buffer;
}
example_gss_state_t;

/**
 * Establish connection to an XACML server
 * @ingroup xacml_io_gssapi
 *
 * @param endpoint
 *     URI of the XACML server
 * @param host
 *     Host name of the XACML server
 * @param port
 *     TCP port that the XACML server listens on
 *
 * @return
 *     Returns an #example_gss_state_t containing state information about 
 *     the connection to the server.
 */
static
void *
example_gss_connect(
    const char                         *endpoint,
    const char                         *host,
    int                                 port)
{
    struct addrinfo                     hints;
    struct addrinfo                    *res;
    int                                 rc;
    char                                portstr[24];
    example_gss_state_t                 *state;
    OM_uint32                           maj_stat, min_stat;
    gss_buffer_desc                     inbuf, token, *input;

    state = calloc(1, sizeof(example_gss_state_t));
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

    input = NULL;
    inbuf.value = NULL;
    inbuf.length = 0;
    do
    {
        maj_stat = gss_init_sec_context(
                &min_stat,
                GSS_C_NO_CREDENTIAL,
                &state->ctx,
                GSS_C_NO_NAME,
                GSS_C_NO_OID,
                GSS_C_MUTUAL_FLAG|GSS_C_CONF_FLAG,
                0,
                GSS_C_NO_CHANNEL_BINDINGS,
                input,
                NULL,
                &token,
                NULL,
                NULL);

        if (GSS_ERROR(maj_stat))
        {
            break;
        }
        if (token.length > 0)
        {
            int sent;

            for (sent = 0; sent < token.length; )
            {
                rc = send(state->socket, ((char *) token.value)+sent,
                          token.length-sent, 0);

                if (rc < 0)
                {
                    break;
                }
                else
                {
                    sent += rc;
                }
            }
            gss_release_buffer(&min_stat, &token);
        }
        if (maj_stat == GSS_S_CONTINUE_NEEDED)
        {
            input = &inbuf;
            if (inbuf.value == NULL)
            {
                inbuf.value = malloc(1024);
            }
            inbuf.length = 1024;
            rc = recv(state->socket, inbuf.value, inbuf.length, 0);
            if (rc < 0)
            {
                goto close;
            }
            inbuf.length = rc;
        }
    }
    while (maj_stat == GSS_S_CONTINUE_NEEDED);

    if (GSS_ERROR(maj_stat))
    {
        rc = -1;
    }

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
/* example_gss_connect() */

/**
 * Send a query to an XACML server
 * @ingroup xacml_io_gssapi
 *
 * @param arg
 *     Pointer to the #example_gss_state_t returned from example_gss_connect()
 * @param data
 *     Data to send to the server.
 * @param size
 *     Size of the @a data array.
 *
 * @return 0 on success, nonzero on error.
 */
static
int
example_gss_send(
    void                               *arg,
    const char                         *data,
    size_t                              size)
{
    example_gss_state_t                *state = arg;
    int                                 sent;
    int                                 rc;
    OM_uint32                           maj_stat, min_stat;
    gss_buffer_desc                     input, output;

    input.value = (void *) data;
    input.length = size;

    maj_stat = gss_wrap(&min_stat, state->ctx, 1, GSS_C_QOP_DEFAULT,
                        &input, NULL, &output);

    if (GSS_ERROR(maj_stat))
    {
        return -1;
    }

    for (sent = 0; sent < output.length; )
    {
        rc = send(state->socket, ((char *) output.value)+sent,
                  output.length-sent, 0);

        if (rc < 0)
        {
            goto err;
        }
        else
        {
            sent += rc;
        }
    }

err:
    gss_release_buffer(&min_stat, &output);
    return 0;
}
/* example_send() */

/**
 * Recv response data from an XACML server
 * @ingroup xacml_io_gssapi
 *
 * @param arg
 *     Pointer to the #example_gss_state_t returned from example_gss_connect()
 * @param data
 *     Buffer to hold data returned from the server.
 * @param size
 *     Size of the @a data array.
 *
 * @return Number of bytes read into @a data.
 */
static
size_t
example_gss_recv(
    void                               *arg,
    char                               *data,
    size_t                              size)
{
    example_gss_state_t                *state = arg;
    size_t                              r;
    OM_uint32                           maj_stat, min_stat;
    gss_buffer_desc                     input;
    gss_buffer_desc                     output;

    /* Copy any previously-read data into the data buffer */
    if (state->buffer.length > 0)
    {
        r = state->buffer.length > size ? size : state->buffer.length;
        memcpy(data, state->buffer.value, r);
        
        if (state->buffer.length != r)
        {
            /* If there's still some in our buffer, return what we've copied
             * only
             */
            memmove(state->buffer.value, 
                    ((char *) state->buffer.value)+r, 
                    state->buffer.length - r);
            state->buffer.length -= r;

            return r;
        }
        else
        {
            free(state->buffer.value);
            state->buffer.length = 0;
        }
    }
    /* Read new data from the network and unwrap it */
    r = recv(state->socket, data, size, 0);
    if (r <= 0)
    {
        return 0;
    }

    input.value = data;
    input.length = r;

    output.value = NULL;
    output.length = 0;

    maj_stat = gss_unwrap(&min_stat, state->ctx, &input, &output, NULL, NULL);

    if (GSS_ERROR(maj_stat))
    {
        return 0;
    }

    if (output.length > 0)
    {
        /* Read a full token, copy as much as we can fit into the 
         * data array
         */
        r = output.length > size ? size : output.length;
        memcpy(data, output.value, r);
    }
    if (output.length != r)
    {
        /* Put remaining data into the state's buffer to copy when this
         * is called again
         */
        state->buffer.length = output.length - r;
        state->buffer.value = malloc(state->buffer.length);
        memcpy(state->buffer.value, ((char *)output.value)+r,
               state->buffer.length);
    }

    gss_release_buffer(&min_stat, &output);

    return r;
}
/* example_gss_recv() */

static
int
example_gss_close(
    void                               *arg)
{
    example_gss_state_t *               state = arg;
    OM_uint32                           maj_stat, min_stat;
    gss_buffer_desc                     token;
    ssize_t                             rc;
    int                                 sent;

    token.value = NULL;
    token.length = 0;

    maj_stat = gss_delete_sec_context(&min_stat, &state->ctx, &token);

    if (!GSS_ERROR(maj_stat))
    {
        if (token.length != 0)
        {
            for (sent = 0; sent < token.length; )
            {
                rc = send(state->socket, ((char *) token.value)+sent,
                          token.length-sent, 0);

                if (rc < 0)
                {
                    goto err;
                }
                else
                {
                    sent += rc;
                }
            }
        }
    }

err:
    if (token.length != 0)
    {
        gss_release_buffer(&min_stat, &token);
    }
    close(state->socket);
    free(state);

    return 0;
}
/* example_gss_close() */

void *
example_gss_accept(
    int                                 socket,
    struct sockaddr                    *addr,
    socklen_t                          *addr_len,
    int                                *sock_out)
{
    example_gss_state_t                 *state;
    int                                 rc;
    gss_buffer_desc                     inbuf, token;
    OM_uint32                           maj_stat, min_stat;

    state = malloc(sizeof(example_gss_state_t));

    state->socket = accept(socket, addr, addr_len);

    if (state->socket < 0)
    {
        rc = -1;
        goto err;
    }
    *sock_out = state->socket;

    state->ctx = GSS_C_NO_CONTEXT;
    state->buffer.value = NULL;
    state->buffer.length = 0;

    inbuf.value = malloc(1024);
    do
    {
        inbuf.length = 1024;
        /* Read token */
        rc = recv(state->socket, inbuf.value, inbuf.length, 0);
        if (rc < 0)
        {
            break;
        }
        inbuf.length = rc;

        /* Pass to accept sec context */
        maj_stat = gss_accept_sec_context(
                &min_stat,
                &state->ctx,
                GSS_C_NO_CREDENTIAL,
                &inbuf,
                GSS_C_NO_CHANNEL_BINDINGS,
                NULL,
                NULL,
                &token,
                NULL,
                NULL,
                NULL);
        if (GSS_ERROR(maj_stat))
        {
            break;
        }
        /* Send output token if available */
        if (token.length > 0)
        {
            int sent;

            for (sent = 0; sent < token.length; )
            {
                rc = send(state->socket, ((char *) token.value)+sent,
                          token.length-sent, 0);

                if (rc < 0)
                {
                    break;
                }
                else
                {
                    sent += rc;
                }
            }
            gss_release_buffer(&min_stat, &token);
            token.value = NULL;
            token.length = 0;
        }
    }
    while (maj_stat == GSS_S_CONTINUE_NEEDED);

    if (inbuf.value)
    {
        free(inbuf.value);
    }
    if (GSS_ERROR(maj_stat))
    {
        rc = -1;
    }

err:
    if (rc < 0)
    {
        free(state);
        state = NULL;
    }
    return state;
}
/* example_gss_accept() */

xacml_io_descriptor_t
xacml_io_descriptor =
{
    "xacml_gss_io",
    example_gss_accept,
    example_gss_connect,
    example_gss_send,
    example_gss_recv,
    example_gss_close
};
