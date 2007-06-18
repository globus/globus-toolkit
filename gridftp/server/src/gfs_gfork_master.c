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

/* TODO: 
   1) memory limitation, perhaps just implemented in brain based on
      connection count?

   2) better load balancing.  maintain a 'who needs a beer?' list
*/


#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_gsi.h"
#include "globus_gfork.h"
#include "gfs_i_gfork_plugin.h"

#define GFSGforkError(error_msg, _type)                                     \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            NULL,                                                           \
            NULL,                                                           \
            _type,                                                          \
            __FILE__,                                                       \
            _gfs_gfork_func_name,                                           \
            __LINE__,                                                       \
            "%s",                                                           \
            (error_msg)))

#ifdef __GNUC__
#define GFSGForkFuncName(func) static const char * _gfs_gfork_func_name __attribute__((__unused__)) = #func
#else
#define GFSGForkFuncName(func) static const char * _gfs_gfork_func_name = #func
#endif

static globus_mutex_t                   g_mutex;
static globus_mutex_t                   g_cond;
static globus_bool_t                    g_done = GLOBUS_FALSE;
static globus_xio_server_t              gfs_l_gfork_server_handle;
static globus_fifo_t                    gfs_l_gfork_be_q = NULL;
static int                              g_port = 0;
static int                              g_stripe_count = 0;
static globus_bool_t                    g_use_gsi = GLOBUS_TRUE;
static char *                           g_allowed_dn_file = NULL;
static globus_xio_driver_t              g_tcp_driver;
static globus_xio_driver_t              g_gsi_driver;
static FILE *                           g_log_fptr;
static int                              g_repo_count = 0;
static gfork_child_handle_t             g_handle;
static int                              g_connection_count = 0;

static
globus_result_t
gfs_gfork_master_options(
    int                                 argc,
    char **                             argv);

static
void
gfs_l_gfork_log(
    globus_result_t                     result,
    int                                 level,
    char *                              fmt,
    ...)
{
    va_list                             ap;

    if(g_log_fptr == NULL)
    {
        return;
    }
    va_start(ap, fmt);

    fprintf(g_log_fptr, "[gridftp gfork plugin] : ");
    if(result != GLOBUS_SUCCESS)
    {
        char * err_str = globus_error_print_friendly(
            globus_error_peek(result));

        fprintf(g_log_fptr, "ERROR : %s : ", err_str);
        globus_free(err_str);
    }
    vfprintf(g_log_fptr, fmt, ap);
    va_end(ap);
    fflush(g_log_fptr);
}


static 
void
gfs_l_gfork_timeout(
    void *                              user_arg)
{
    char *                              buffer;

    globus_mutex_lock(&g_mutex);
    {
        buffer = user_arg;
        buffer[GF_VERSION_NDX] = GF_VERSION_TIMEOUT;

        gfs_l_gfork_log(
            GLOBUS_SUCCESS, 2, "Backend registration for %s expired\n",
            &buffer[GF_CS_NDX]);
    }
    globus_mutex_lock(&g_mutex);
}

static
void
gfs_l_gfork_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_free(buffer);

    globus_xio_register_close(
        handle,
        NULL,
        NULL,
        NULL);
}

static
void
gfs_l_gfork_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_byte_t *                     ack_buffer;
    globus_xio_iovec_t                  iov[1];
    globus_bool_t                       ok;
    globus_bool_t                       done;
    int                                 i;
    globus_reltime_t                    delay;
    uint32_t                            tmp_32;
    uint32_t                            converted_32;
    GFSGForkFuncName(gfs_l_gfork_read_cb);

    gfs_l_gfork_log(
        result, 3, "Reading incoming registration message\n");

    globus_mutex_lock(&g_mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        /* before addind to list make sure the packet is ok */
        if(buffer[GF_VERSION_NDX] != GF_VERSION)
        {
            goto error_version;
        }
        if(buffer[GF_MSG_TYPE_NDX] != GFS_GFORK_MSG_TYPE_DYNBE)
        {
            goto error_version;
        }

        done = GLOBUS_FALSE;
        ok = GLOBUS_FALSE;
        for(i = GF_CS_NDX; i < GF_CS_NDX + GF_CS_LEN && !done; i++)
        {
            if(buffer[i] == '\0')
            {
                done = GLOBUS_TRUE;
            }
            else if(!isalnum(buffer[i]) && buffer[i] != '.' &&
                buffer[i] != '-' && buffer[i] != ':')
            {
                ok = GLOBUS_FALSE;
                done = GLOBUS_TRUE;
            }
            else
            {
                ok = GLOBUS_TRUE;
            }
        }

        /* registering client may not be same byte order */
        memcpy(&tmp_32, &buffer[GF_AT_ONCE_NDX], sizeof(uint32_t));
        converted_32 = ntohl(tmp_32);
        memcpy(&buffer[GF_AT_ONCE_NDX], &converted_32, sizeof(uint32_t));

        memcpy(&tmp_32, &buffer[GF_TOTAL_NDX], sizeof(uint32_t));
        converted_32 = ntohl(tmp_32);
        memcpy(&buffer[GF_TOTAL_NDX], &converted_32, sizeof(uint32_t));

        if(!ok)
        {
            gfs_l_gfork_log(
                GLOBUS_SUCCESS, 2, "Registration message not ok\n");
            goto error_cs;
        }
        /* at this point it is fine to add to lsit */
        globus_fifo_enqueue(&gfs_l_gfork_be_q, buffer);

        GlobusTimeReltimeSet(delay, GF_REGISTRATION_TIMEOUT, 0);
        globus_callback_register_oneshot(
            NULL,
            &delay,
            gfs_l_gfork_timeout,
            buffer);

        /* write ack */
        ack_buffer = globus_malloc(GF_REG_PACKET_LEN);
        ack_buffer[GF_VERSION_NDX] = GF_VERSION;
        ack_buffer[GF_MSG_TYPE_NDX] = GFS_GFORK_MSG_TYPE_ACK;

        result = globus_xio_register_write(
            handle,
            ack_buffer,
            GF_REG_PACKET_LEN,
            GF_REG_PACKET_LEN,
            NULL,
            gfs_l_gfork_write_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            globus_xio_register_close(
                handle,
                NULL,
                NULL,
                NULL);
            globus_free(ack_buffer);
        }
        iov[0].iov_base = buffer;
        iov[0].iov_len = GF_REG_PACKET_LEN;

        gfs_l_gfork_log(
            GLOBUS_SUCCESS, 2, "Successful registration from: %s\n",
            &buffer[GF_CS_NDX]);
        /* TODO: keep an "in need" list.  if only 3 were available at
            the time the client asked but wanted 4, send this message,
            otherwise, do not send.

            for now this is fine because all children have knowledge
            of all servers and choose themselves. */
        result = globus_gfork_broadcast(
            g_handle,
            iov,
            1,
            NULL,
            NULL);
        gfs_l_gfork_log(
            result, 3, "Broadcasted new registration\n");
    }
    globus_mutex_unlock(&g_mutex);

    return;

error_cs:
error_version:
error:
    gfs_l_gfork_log(
        result, 3, "Reading registration exit it error.\n");

    /* reuse the buffer we already have */
    buffer[GF_VERSION_NDX] = GF_VERSION;
    buffer[GF_MSG_TYPE_NDX] = GFS_GFORK_MSG_TYPE_NACK;
    result = globus_xio_register_write(
        handle,
        buffer,
        GF_REG_PACKET_LEN,
        GF_REG_PACKET_LEN,
        NULL,
        gfs_l_gfork_write_cb,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        globus_xio_register_close(
            handle,
            NULL,
            NULL,
            NULL);
        globus_free(buffer);
        gfs_l_gfork_log(
            result, 3, "Write NACK failed.\n");
    }
    globus_mutex_unlock(&g_mutex);
}

static
globus_result_t
gfs_l_gfork_dn_ok(
    globus_xio_handle_t                 handle)
{
    FILE *                              fptr;
    gss_name_t                          local;
    gss_name_t                          peer;
    OM_uint32                           min_stat;
    OM_uint32                           maj_stat;
    gss_buffer_desc                     local_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc                     peer_buf = GSS_C_EMPTY_BUFFER;
    char                                line[256];
    globus_result_t                     result;
    globus_bool_t                       found;
    GFSGForkFuncName(gfs_l_gfork_dn_ok);

    /* verify we are ok with the sender */
    result = globus_xio_handle_cntl(
        handle,
        g_gsi_driver,
        GLOBUS_XIO_GSI_GET_PEER_NAME,
        &peer);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_peer;
    }
    maj_stat = gss_display_name(
        &min_stat,
        peer,
        &peer_buf,
        NULL);
    if(maj_stat != GSS_S_COMPLETE)
    {
        goto error_peer;
    }
    /* verify we are ok with the sender */
    result = globus_xio_handle_cntl(
        handle,
        g_gsi_driver,
        GLOBUS_XIO_GSI_GET_LOCAL_NAME,
        &local);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_local;
    }
    maj_stat = gss_display_name(
        &min_stat,
        local,
        &local_buf,
        NULL);
    if(maj_stat != GSS_S_COMPLETE)
    {
        goto error_local;
    }

    /* if no file assume seld */
    if(g_allowed_dn_file == NULL)
    {
        if(memcmp(&local_buf.value, peer_buf.value, peer_buf.length) != 0)
        {
            char *                      tmp_str;

            tmp_str = globus_common_create_string(
                "%s not allowed", peer_buf.value);
            result = GFSGforkError(tmp_str, 0);
            goto error_no_match;
        }
    }
    else
    {
        fptr = fopen(g_allowed_dn_file, "r");
        if(fptr == NULL)
        {
            goto error_fopen;
        }
        found = GLOBUS_FALSE;

        while(fscanf(fptr, "\"%[^\"]\"", line) == 1 && !found)
        {
            if(memcmp(peer_buf.value, line, peer_buf.length) == 0)
            {
                found = GLOBUS_TRUE;
            }
        }
        fclose(fptr);
        if(!found)
        {
            char *                      tmp_str;

            tmp_str = globus_common_create_string(
                "%s not found in file", peer_buf.value);
            result = GFSGforkError(tmp_str, 0);
            goto error_no_match;
        }
    }
    globus_free(peer_buf.value);
    globus_free(local_buf.value);

    return GLOBUS_SUCCESS;
error_no_match:
error_fopen:
error_local:
error_peer:
    return result;
}

static
void
gfs_l_gfork_open_server_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_byte_t *                     buffer;

    buffer = globus_malloc(GF_REG_PACKET_LEN);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_accept;
    }

    if(g_use_gsi)
    {
        /* verify we are ok with the sender */
        result = gfs_l_gfork_dn_ok(handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_not_allowed;
        }
    }

    result = globus_xio_register_read(
        handle,
        buffer,
        GF_REG_PACKET_LEN,
        GF_REG_PACKET_LEN,
        NULL,
        gfs_l_gfork_read_cb,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_read;
    }

    return;

error_read:
error_not_allowed:
error_accept:

    buffer[GF_VERSION_NDX] = GF_VERSION;
    buffer[GF_MSG_TYPE_NDX] = GFS_GFORK_MSG_TYPE_NACK;
    result = globus_xio_register_write(
        handle,
        buffer,
        GF_REG_PACKET_LEN,
        GF_REG_PACKET_LEN,
        NULL,
        gfs_l_gfork_write_cb,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        globus_xio_register_close(
            handle,
            NULL,
            NULL,
            NULL);
        globus_free(buffer);
        gfs_l_gfork_log(
            result, 3, "Write NACK failed.\n");
    }
    gfs_l_gfork_log(
        result, 2, "Open server error.\n");
    return;
}

static
void
gfs_l_gfork_add_server_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_mutex_lock(&g_mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }


       result = globus_xio_register_open(
            handle,
            NULL,
            NULL,
            gfs_l_gfork_open_server_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            gfs_l_gfork_log(
                result, 1, "Failed to open\n");
            goto error;
        }

error:
        result = globus_xio_server_register_accept(
            gfs_l_gfork_server_handle,
            gfs_l_gfork_add_server_accept_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            gfs_l_gfork_log(
                result, 0, "Failed to accept\n");
        }
        gfs_l_gfork_log(
            result, 3, "Accept callback ending.\n");
    }
    globus_mutex_unlock(&g_mutex);
}

static
globus_result_t
gfs_l_gfork_listen()
{
    char *                              contact_string;
    globus_result_t                     res;
    GFSGForkFuncName(gfs_l_gfork_listen);

    res = globus_xio_server_get_contact_string(
        gfs_l_gfork_server_handle,
        &contact_string);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_server;
    }
    gfs_l_gfork_log(
        GLOBUS_SUCCESS, 0, "Listening on %s\n", contact_string);
    globus_free(contact_string);

    res = globus_xio_server_register_accept(
        gfs_l_gfork_server_handle,
        gfs_l_gfork_add_server_accept_cb,
        NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_accept;
    }

    return GLOBUS_SUCCESS;

error_accept:
    globus_free(contact_string);
error_server:

    return res;
}

static
void
gfs_l_gfork_open_cb(
    gfork_child_handle_t                handle,
    void *                              user_arg,
    pid_t                               from_pid)
{
    globus_xio_iovec_t *                iov;
    int                                 i = 0;
    int                                 iovc = 0;
    globus_bool_t                       done = GLOBUS_FALSE;
    char *                              buffer;

    gfs_l_gfork_log(
        GLOBUS_SUCCESS, 2, "Open called for pid %d\n", from_pid);

    iov = (globus_xio_iovec_t *) globus_calloc(g_repo_count,
        sizeof(globus_xio_iovec_t));
    globus_mutex_lock(&g_mutex);
    {
        g_connection_count++;
        while(!done && (i < g_repo_count || g_repo_count == 0))
        {
            if(globus_fifo_empty(&gfs_l_gfork_be_q))
            {
                done = GLOBUS_TRUE;
            }
            else
            {
                buffer = (char *) globus_fifo_dequeue(&gfs_l_gfork_be_q);

                if(buffer[GF_VERSION_NDX] == GF_VERSION_TIMEOUT)
                {
                    gfs_l_gfork_log(
                        GLOBUS_SUCCESS, 2, "Freeing timed-out buffer %s\n",
                        &buffer[GF_CS_NDX]);
                    globus_free(buffer);
                }
                else
                {
                    /* a good buffer */
                    iov[i].iov_base = buffer;
                    iov[i].iov_len = GF_REG_PACKET_LEN;
                    i++;
                }
            }
        }
        iovc = i;

        for(i = 0; i < iovc; i++)
        {
            globus_fifo_enqueue(&gfs_l_gfork_be_q, iov[i].iov_base);
            gfs_l_gfork_log(
                GLOBUS_SUCCESS, 2, "Re-enqueue\n");
        }
        /* put them back in */
        if(iovc > 0)
        {
            gfs_l_gfork_log(
                GLOBUS_SUCCESS, 3, "sending to pid %d\n", from_pid);
            globus_gfork_send(
                handle,
                from_pid,
                iov,
                iovc,
                NULL,
                NULL);
        }
    }
    globus_mutex_unlock(&g_mutex);

    globus_free(iov);
}

/* connection cloesd */
static
void
gfs_l_gfork_closed_cb(
    gfork_child_handle_t                handle,
    void *                              user_arg,
    pid_t                               from_pid)
{
    globus_mutex_lock(&g_mutex);
    {
        g_connection_count--;
        gfs_l_gfork_log(
            GLOBUS_SUCCESS, 2, "Closed called for pid %d\n", from_pid);
    }
    globus_mutex_unlock(&g_mutex);
}

static
void
gfs_l_gfork_incoming_cb(
    gfork_child_handle_t                handle,
    void *                              user_arg,
    pid_t                               from_pid,
    globus_byte_t *                     buffer,
    globus_size_t                       len)
{
}

static
globus_result_t
gfs_l_gfork_xio_setup()
{
    globus_result_t                     result;
    globus_xio_attr_t                   attr;
    globus_xio_stack_t                  stack;

    result = globus_xio_attr_init(&attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr_init;
    }
    result = globus_xio_stack_init(&stack, NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_stack_init;
    }

    result = globus_xio_driver_load("tcp", &g_tcp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_tcp;
    }

    result = globus_xio_stack_push_driver(stack, g_tcp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_tcp_push;
    }
    result = globus_xio_attr_cntl(
        attr,
        g_tcp_driver,
        GLOBUS_XIO_TCP_SET_PORT,
        g_port);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_port;
    }

    if(g_use_gsi)
    {
        result = globus_xio_driver_load("gsi", &g_gsi_driver);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_gsi;
        }
        result = globus_xio_stack_push_driver(stack, g_gsi_driver);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_gsi_push;
        }
    }

    result = globus_xio_server_create(
        &gfs_l_gfork_server_handle, attr, stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server_create;
    }

    return GLOBUS_SUCCESS;

error_server_create:
error_gsi_push:
error_gsi:
error_port:
error_tcp_push:
error_tcp:
error_stack_init:
error_attr_init:

    return result;
}

int
main(
    int                                 argc,
    char **                             argv)
{
    globus_result_t                     result;
    int                                 rc;

    rc = globus_module_activate(GLOBUS_GFORK_CHILD_MODULE);
    if(rc != 0)
    {
        goto error_activate;
    }

    result = gfs_gfork_master_options(argc, argv);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_opts;
    }

    globus_fifo_init(&gfs_l_gfork_be_q);
    globus_mutex_init(&g_mutex, NULL);
    globus_cond_init(&g_cond, NULL);
    g_done = GLOBUS_FALSE;

    result = gfs_l_gfork_xio_setup();
    if(result != GLOBUS_SUCCESS)
    {
        goto error_xio;
    }

    globus_mutex_lock(&g_mutex);
    {
        result = globus_gfork_child_master_start(
            &g_handle,
            NULL,
            gfs_l_gfork_open_cb,
            gfs_l_gfork_closed_cb,
            gfs_l_gfork_incoming_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_start;
        }

        result = gfs_l_gfork_listen();
        if(result != GLOBUS_SUCCESS)
        {
            goto error_listen;
        }

        while(!g_done)
        {
            globus_cond_wait(&g_cond, &g_mutex);
        }
    }
    globus_mutex_unlock(&g_mutex);

    return 0;

error_listen:
error_start:
error_xio:
error_opts:
error_activate:
    gfs_l_gfork_log(result, 0, "");

    return 1;
}

static
globus_result_t
gfs_l_gfork_opts_help(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_options_help(opts_handle);

    printf("This program should be executed from gfork only.  It is "
        "not intended to be a stand alone program.\n");
    exit(0);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfs_l_gfork_opts_port(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_result_t                     result;
    int                                 sc;
    int                                 port;
    GFSGForkFuncName(gfs_l_gfork_opts_port);

    sc = sscanf(opt[0], "%d", &port);
    if(sc != 1)
    {
        result = GFSGforkError("port must be an int",
            GFS_GFORK_ERROR_PARAMETER);
        goto error_format;
    }

    g_port = port;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
error_format:
    return result;
}

static
globus_result_t
gfs_l_gfork_opts_stripe_count(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_result_t                     result;
    int                                 sc;
    int                                 stripe_count;
    GFSGForkFuncName(gfs_l_gfork_opts_stripe_count);

    sc = sscanf(opt[0], "%d", &stripe_count);
    if(sc != 1)
    {
        result = GFSGforkError("stripe count must be an int",
            GFS_GFORK_ERROR_PARAMETER);
        goto error_format;
    }

    g_stripe_count = stripe_count;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
error_format:
    return result;

}

static
globus_result_t
gfs_l_gfork_opts_gsi(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_bool_t                       b = GLOBUS_FALSE;

    if(strcasecmp(opt[0], "t") == 0 ||
        strcasecmp(opt[0], "y") == 0 ||
        strcasecmp(opt[0], "yes") == 0 ||
        strcasecmp(opt[0], "true") == 0)
    {
        b = GLOBUS_TRUE;
    }

    g_use_gsi = b;
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfs_l_gfork_opts_dn_file(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    g_allowed_dn_file = opt[0];
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfs_l_gfork_opts_log(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_result_t                     result;

    if(strcmp(opt[0], "-") == 0)
    {
        g_log_fptr = stderr;
    }
    else
    {
        g_log_fptr = fopen(opt[0], "w");
        if(g_log_fptr == NULL)
        {
            goto error_open;
        }
    }
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
error_open:
    return result;
}

globus_options_entry_t                   gfork_l_opts_table[] =
{
    {"help", "h", NULL, NULL,
        "print the help message",
        0, gfs_l_gfork_opts_help},
    {"port", "p", NULL, "<int>",
        "Port where server listens for connections.",
        1, gfs_l_gfork_opts_port},
    {"stripe-count", "s", NULL, "<int>",
        "The max number of stripes to give to each server."
        "  0 is all avaiable.",
        1, gfs_l_gfork_opts_stripe_count},
    {"logfile", "l", NULL, "<path>",
        "Path to the logfile.",
        1, gfs_l_gfork_opts_log},
    {"gsi", "G", NULL, "<bool>",
        "Enable or disable GSI.  Default is on.",
        1, gfs_l_gfork_opts_gsi},
    {"dn-file", "dn", NULL, "<path>",
        "Path to a file containing the list of acceptable DNs."
        "  Default is system gridmap file",
        1, gfs_l_gfork_opts_dn_file},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};

static
globus_result_t
gfs_l_gfork_master_opts_unknown(
    globus_options_handle_t             opts_handle,
    void *                              unknown_arg,
    int                                 argc,
    char **                             argv)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "gfs_lgfork_master_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        unknown_arg));
}



static
globus_result_t
gfs_gfork_master_options(
    int                                 argc,
    char **                             argv)
{
    globus_options_handle_t             opt_h;
    globus_result_t                     result;

    globus_options_init(
        &opt_h, gfs_l_gfork_master_opts_unknown, NULL);
    globus_options_add_table(opt_h, gfork_l_opts_table, NULL);
    result = globus_options_command_line_process(opt_h, argc, argv);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    return GLOBUS_SUCCESS;
error:
    return result;
}

