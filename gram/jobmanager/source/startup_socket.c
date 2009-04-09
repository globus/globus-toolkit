/*
 * Copyright 1999-2009 University of Chicago
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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file start_socket.c Job Manager Socket Transfer Code
 *
 * CVS Information:
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#include "globus_common.h"
#include "globus_gram_job_manager.h"
#include "globus_xio.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

static
globus_result_t
globus_l_gram_create_handle(
    int                                 sock,
    globus_xio_handle_t *               handle);

static
void
globus_l_gram_startup_socket_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

globus_xio_driver_t                     globus_i_gram_job_manager_file_driver;
globus_xio_stack_t                      globus_i_gram_job_manager_file_stack;
#endif

/**
 * Create socket to handle startup messages from other job managers
 *
 * Creates a UNIX domain socket, binds it to a well-known user-and lrm-specific
 * filename, and then creates and registers an XIO handle for select.
 *
 * @param manager
 *     Manager to create the socket for.
 * @param handle
 *     Pointer to XIO handle to be set to the socket descriptor.
 * @param lock_fd
 *     Pointer to file descriptor pointing to the UNIX domain socket.
 * @param lock_fd
 *     Pointer to file descriptor pointing to the lock file associated with the 
 *     UNIX domain socket.
 */
int
globus_gram_job_manager_startup_socket_init(
    globus_gram_job_manager_t *         manager,
    globus_xio_handle_t *               handle,
    int *                               socket_fd,
    int *                               lock_fd)
{
    static unsigned char                byte[1];
    int                                 sock = -1;
    int                                 rc = 0;
    globus_result_t                     result;
    struct sockaddr_un                  addr;
    int                                 lockfd = -1;
    mode_t                              old_umask;
    int                                 i;
    int                                 rcvbuf;
    int                                 flags;
    enum { GRAM_RETRIES = 100 };

    if (!manager->config->single)
    {
        return GLOBUS_SUCCESS;
    }

    /* Create and lock lockfile */
    for (i = 0, lockfd = -1; lockfd < 0 && i < GRAM_RETRIES; i++)
    {
        lockfd = open(manager->lock_path, O_RDWR|O_CREAT, S_IRWXU);
    }
    if (lockfd < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;
        goto lockfd_open_failed;
    }
    flags = fcntl(lockfd, F_GETFD);
    if (flags < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto fcntl_lockfd_failed;
    }
    flags |= FD_CLOEXEC;
    if (fcntl(lockfd, F_SETFD, flags) < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto fcntl_lockfd_failed;
    }

    rc = globus_gram_job_manager_file_lock(lockfd);
    if (rc != GLOBUS_SUCCESS)
    {
        goto lock_failed;
    }

    /* create and bind socket */
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = PF_LOCAL;
    strncpy(addr.sun_path, manager->socket_path, sizeof(addr.sun_path)-1);

    sock = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;
        goto socket_failed;
    }

    rcvbuf = 10 * GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE;
    rc = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        goto setsockopt_failed;
    }
    old_umask = umask(S_IRWXG|S_IRWXO);

    (void ) remove(addr.sun_path);
    for (rc = -1, i = 0; rc < 0 && i < GRAM_RETRIES; i++)
    {
        rc = bind(sock, (struct sockaddr *) &addr, sizeof(addr));

        if (rc < 0)
        {
            remove(addr.sun_path);
        }
    }
    (void) umask(old_umask);
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;

        goto bind_failed;
    }

    flags = fcntl(sock, F_GETFD);
    if (flags < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto fcntl_failed;
    }
    flags |= FD_CLOEXEC;
    if (fcntl(sock, F_SETFD, flags) < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto fcntl_failed;
    }

    result = globus_l_gram_create_handle(
            sock,
            handle);

    if (result != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_FAILED_ALLOW_ATTACH;
        goto create_handle_failed;
    }

    result = globus_xio_register_read(
            *handle,
            byte,
            0,
            0,
            NULL,
            globus_l_gram_startup_socket_callback,
            manager);
    if (result != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_FAILED_ALLOW_ATTACH;

        goto register_read_failed;
    }

    if (rc != GLOBUS_SUCCESS)
    {
register_read_failed:
        globus_xio_close(*handle, NULL);
        *handle = NULL;
create_handle_failed:
fcntl_failed:
bind_failed:
setsockopt_failed:
        close(sock);
        sock = -1;
socket_failed:
        remove(manager->lock_path);
lock_failed:
fcntl_lockfd_failed:
        close(lockfd);
        lockfd = -1;
lockfd_open_failed:
        ;
    }

    *socket_fd = sock;
    *lock_fd = lockfd;
    return rc;
}
/* globus_gram_job_manager_startup_socket_init() */

int
globus_gram_job_manager_starter_send(
    globus_gram_job_manager_t *         manager,
    int                                 http_body_fd,
    int                                 context_fd,
    int                                 response_fd,
    gss_cred_id_t                       cred)
{
    int                                 sock;
    char                                sockpath[PATH_MAX != -1 ? PATH_MAX: _POSIX_PATH_MAX];
    char                                byte[1];
    int                                 rc = 0;
    struct sockaddr_un                  addr;
    struct msghdr                       message;
    struct iovec                        iov[1];
    struct cmsghdr *                    cmsg;
    int *                               fdptr;
    char                                cmsgbuf[sizeof(struct cmsghdr) + 4 * sizeof(int)];
    gss_buffer_desc                     cred_buffer;
    int                                 acksock[2];
    OM_uint32                           major_status, minor_status;
    int                                 sndbuf;
    enum { GRAM_RETRIES = 100 };

    sprintf(sockpath,
            "%s/.globus/job/%s/%s.sock",
            manager->config->home,
            manager->config->hostname,
            manager->config->jobmanager_type);

    /* create socket */
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = PF_LOCAL;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path)-1);
    sock = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        goto socket_failed;
    }
    sndbuf = GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE;
    rc = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        goto setsockopt_failed;
    }
    rc = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        goto connect_failed;
    }
    /* create acksocks */
    rc = socketpair(PF_LOCAL, SOCK_STREAM, 0, acksock);
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        goto socketpair_failed;
    }

    /* Export credential to be sent to active job manager */
    major_status = gss_export_cred(
            &minor_status,
            cred,
            GSS_C_NO_OID,
            0,
            &cred_buffer);
    if (GSS_ERROR(major_status))
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY;
        goto export_cred_failed;
    }

    if (cred_buffer.length > GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
        goto cred_too_big;
    }

    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    /* Credential we send along with the descriptors */
    iov[0].iov_base = cred_buffer.value;
    iov[0].iov_len = cred_buffer.length;
        
    /* Message metadata */
    message.msg_name = NULL;
    message.msg_namelen = 0;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_flags = 0;
    message.msg_control = cmsgbuf;
    message.msg_controllen = sizeof(cmsgbuf);

    cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = sizeof(cmsgbuf);
    fdptr = (int *)CMSG_DATA(cmsg);
    fdptr[0] = http_body_fd;
    fdptr[1] = context_fd;
    fdptr[2] = response_fd;
    fdptr[3] = acksock[0];

    /* Send message */
    rc = sendmsg(sock, &message, 0);
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
        goto sendmsg_failed;
    }
    close(acksock[0]);
    acksock[0] = -1;
    memset(&message, 0, sizeof(struct msghdr));
    iov[0].iov_base = &byte;
    iov[0].iov_len = 1;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    rc = recvmsg(acksock[1], &message, 0);
    if (rc < 0 || byte[0] != 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    else
    {
        rc = GLOBUS_SUCCESS;
    }
    memset(&message, 0, sizeof(struct msghdr));
    iov[0].iov_base = &byte;
    iov[0].iov_len = 1;
    byte[0]++;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    rc = sendmsg(acksock[1], &message, 0);
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    else
    {
        rc = GLOBUS_SUCCESS;
    }
    
sendmsg_failed:
cred_too_big:
    gss_release_buffer(
            &minor_status,
            &cred_buffer);
export_cred_failed:
    if (acksock[0] != -1)
    {
        close(acksock[0]);
    }
    close(acksock[1]);
socketpair_failed:
connect_failed:
setsockopt_failed:
    close(sock);
socket_failed:

    return rc;
}
/* globus_gram_job_manager_starter_send_fds() */


static
void
globus_l_gram_startup_socket_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_gram_job_manager_t *         manager = user_arg;
    int *                               sent_fds;
    struct msghdr                       message;
    struct iovec                        iov[1];
    gss_buffer_desc                     cred_buffer;
    struct cmsghdr *                    control_message = NULL;
    int                                 http_body_fd = -1;
    int                                 context_fd = -1;
    int                                 response_fd = -1;
    int                                 acksock = -1;
    int                                 rc;
    gss_ctx_id_t                        context;
    char *                              contact;
    int                                 job_state_mask;
    globus_gram_jobmanager_request_t *  request;
    OM_uint32                           major_status, minor_status;
    gss_cred_id_t                       cred;
    char                                byte[1] = {0};
    char                                cmsgbuf[sizeof(struct cmsghdr) + 4 * sizeof(int)];

    cred_buffer.length = GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE;
    cred_buffer.value = malloc(GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE);
    if (cred_buffer.value == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto cred_buffer_malloc_failed;
    }
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    /* Prepare to receive credential from other job manager */
    iov[0].iov_base = cred_buffer.value;
    iov[0].iov_len = cred_buffer.length;
        
    /* Message metadata */
    message.msg_name = NULL;
    message.msg_namelen = 0;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_control = cmsgbuf;
    message.msg_controllen = sizeof(cmsgbuf);
    message.msg_flags = 0;

    /* Attempt to receive file descriptors */
    if (recvmsg(manager->socket_fd, &message, 0) < 0)
    {
        goto failed_receive;
    }

    for (control_message = CMSG_FIRSTHDR(&message);
         control_message != NULL;
         control_message = CMSG_NXTHDR(&message, control_message))
    {
        if (control_message->cmsg_level == SOL_SOCKET &&
            control_message->cmsg_type == SCM_RIGHTS)
        {
            sent_fds = (int *) CMSG_DATA(control_message);
            http_body_fd = sent_fds[0];
            context_fd = sent_fds[1];
            response_fd = sent_fds[2];
            acksock = sent_fds[3];
            break;
        }
    }

    if (http_body_fd < 0 || context_fd < 0 || response_fd < 0 || acksock < 0)
    {
        goto failed_get_data;
    }
    cred_buffer.length = iov[0].iov_len;

    byte[0] = 0;
    iov[0].iov_base = byte;
    iov[0].iov_len = sizeof(byte);
    memset(&message, 0, sizeof(struct msghdr));
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    rc = sendmsg(acksock, &message, 0);
    if (rc < 0)
    {
        goto ackfailed;
    }

    byte[0] = 0;
    iov[0].iov_base = byte;
    iov[0].iov_len = sizeof(byte);
    memset(&message, 0, sizeof(struct msghdr));
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    rc = recvmsg(acksock, &message, 0);
    if (rc < 0 || byte[0] != 1)
    {
        goto ackfailed;
    }

    major_status = gss_import_cred(
            &minor_status,
            &cred,
            GSS_C_NO_OID,
            0,
            &cred_buffer,
            0,
            NULL);

    if (GSS_ERROR(major_status))
    {
        goto failed_import_cred;
    }
    /* 
     * TODO: Replace Job Manager credential with this credential if it lives
     * beyond our current credential.
     */

    /* Load request data */
    rc = globus_gram_job_manager_request_load(
            manager,
            http_body_fd,
            context_fd,
            cred,
            &request,
            &context,
            &contact,
            &job_state_mask);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = globus_gram_job_manager_reply(
                NULL,
                rc,
                NULL,
                response_fd,
                context);

        goto request_load_failed;
    }

    /* Start state machine and send response */
    rc = globus_gram_job_manager_request_start(
            manager,
            request,
            response_fd,
            contact,
            job_state_mask);
    if (rc != GLOBUS_SUCCESS)
    {
        /* start decreases the reference count for the request */
        request = NULL;
    }

    free(contact);

    close(response_fd);
    response_fd = -1;
request_load_failed:
ackfailed:
    gss_release_cred(
            &minor_status,
            &cred);
    cred = GSS_C_NO_CREDENTIAL;
failed_import_cred:
    close(acksock);
    close(http_body_fd);
    close(context_fd);
    if (response_fd != -1)
    {
        close(response_fd);
    }
failed_get_data:
failed_receive:
    free(cred_buffer.value);
cred_buffer_malloc_failed:
    result = globus_xio_register_read(
            handle,
            buffer,
            0,
            0,
            NULL,
            globus_l_gram_startup_socket_callback,
            manager);
}
/* globus_l_gram_startup_socket_callback() */

static
globus_result_t
globus_l_gram_create_handle(
    int                                 sock,
    globus_xio_handle_t *               handle)
{
    globus_xio_attr_t                   attr;
    globus_result_t                     result;


    result = globus_xio_attr_init(&attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto attr_init_failed;
    }
    result = globus_xio_attr_cntl(
            attr,
            globus_i_gram_job_manager_file_driver,
            GLOBUS_XIO_FILE_SET_HANDLE,
            sock);
    if (result != GLOBUS_SUCCESS)
    {
        goto attr_cntl_failed;
    }

    result = globus_xio_handle_create(
            handle,
            globus_i_gram_job_manager_file_stack);
    if (result != GLOBUS_SUCCESS)
    {
        goto handle_create_failed;
    }

    result = globus_xio_open(
            *handle,
            NULL,
            attr);

    if (result != GLOBUS_SUCCESS)
    {
        globus_xio_close(*handle, NULL);
        *handle = NULL;
    }

handle_create_failed:
attr_cntl_failed:
    globus_xio_attr_destroy(attr);
attr_init_failed:
    return result;
}
/* globus_l_gram_create_handle() */

