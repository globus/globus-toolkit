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
    int                                 save_errno;
    FILE *                              fp;
    enum { GRAM_RETRIES = 100 };

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
            "event=gram.startup_socket_init.start level=DEBUG\n");

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.startup_socket_init.lock.start "
            "level=TRACE "
            "path=\"%s\"\n",
            manager->lock_path);
    /* Create and lock lockfile */
    for (i = 0, lockfd = -1; lockfd < 0 && i < GRAM_RETRIES; i++)
    {
        lockfd = open(manager->lock_path, O_RDWR|O_CREAT, S_IRWXU);
    }
    if (lockfd < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup_socket_init.lock.end "
                "level=ERROR "
                "status=%d "
                "path=\"%s\" "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\"\n",
                -rc,
                manager->lock_path,
                "Error opening state lock file",
                errno,
                strerror(errno));
        goto lockfd_open_failed;
    }
    flags = fcntl(lockfd, F_GETFD);
    if (flags < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup_socket_init.lock.end "
                "level=ERROR "
                "status=%d "
                "path=\"%s\" "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\"\n",
                -rc,
                manager->lock_path,
                "Error getting file descriptor flags",
                errno,
                strerror(errno));
        goto fcntl_lockfd_failed;
    }
    flags |= FD_CLOEXEC;
    if (fcntl(lockfd, F_SETFD, flags) < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup_socket_init.lock.end "
                "level=ERROR "
                "status=%d "
                "path=\"%s\" "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                -rc,
                manager->lock_path,
                "Error setting close-on-exec flag for lock file",
                errno,
                strerror(errno));

        goto fcntl_lockfd_failed;
    }

    rc = globus_gram_job_manager_file_lock(lockfd);
    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
                "event=gram.startup_socket_init.lock.end "
                "level=DEBUG "
                "status=%d "
                "path=\"%s\" "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                -rc,
                manager->lock_path,
                "Error locking file",
                errno,
                strerror(errno));
        goto lock_failed;
    }

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.startup_socket_init.lock.end "
            "level=TRACE "
            "path=\"%s\" "
            "status=%d "
            "\n",
            manager->lock_path,
            rc);

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.startup_socket_init.write_pid.start "
            "level=TRACE "
            "path=\"%s\" "
            "\n",
            manager->pid_path);
    fp = fopen(manager->pid_path, "w");
    if (fp == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_STATE_FILE;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup_socket_init.write_pid.end "
                "level=ERROR "
                "path=\"%s\" "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                manager->pid_path,
                -rc,
                "Error opening pid file",
                errno,
                strerror(errno));

        goto open_pid_failed;
    }

    rc = fprintf(fp, "%ld\n", (long) getpid());
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_STATE_FILE;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup_socket_init.write_pid.end "
                "level=ERROR "
                "path=\"%s\" "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                manager->pid_path,
                -rc,
                "Error writing to pid file",
                errno,
                strerror(errno));

        goto write_pid_failed;
    }

    rc = fclose(fp);
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_STATE_FILE;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup_socket_init.write_pid.end "
                "level=ERROR "
                "path=\"%s\" "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                manager->pid_path,
                -rc,
                "Error writing to pid file",
                errno,
                strerror(errno));

        goto close_pid_failed;
    }
    fp = NULL;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.startup_socket_init.write_pid.end "
            "level=TRACE "
            "path=\"%s\" "
            "status=%d "
            "\n",
            manager->pid_path,
            0);

    /* create and bind socket */
    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.startup_socket_init.create_socket.start "
            "level=TRACE "
            "path=\"%s\" "
            "\n",
            manager->socket_path);
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = PF_LOCAL;
    strncpy(addr.sun_path, manager->socket_path, sizeof(addr.sun_path)-1);

    sock = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup_socket_init.create_socket.end "
                "level=ERROR "
                "path=\"%s\" "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                manager->socket_path,
                -rc,
                "Error creating socket",
                errno,
                strerror(errno));

        goto socket_failed;
    }

    rcvbuf = 10 * GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE;
    rc = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup_socket_init.create_socket.end "
                "level=ERROR "
                "path=\"%s\" "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                manager->socket_path,
                -rc,
                "Error setting socket buffer size",
                errno,
                strerror(errno));
        goto setsockopt_failed;
    }
    old_umask = umask(S_IRWXG|S_IRWXO);

    (void ) remove(addr.sun_path);
    for (rc = -1, i = 0; rc < 0 && i < GRAM_RETRIES; i++)
    {
        rc = bind(sock, (struct sockaddr *) &addr, sizeof(addr));

        if (rc < 0)
        {
            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                    "event=gram.startup_socket_init.create_socket "
                    "level=WARN "
                    "path=\"%s\" "
                    "tries=%d "
                    "msg=\"%s\" "
                    "errno=%d "
                    "reason=\"%s\" "
                    "\n",
                    manager->socket_path,
                    i+1,
                    "Error binding socket to filesystem",
                    errno,
                    strerror(errno));
            remove(addr.sun_path);
        }
    }
    save_errno = errno;
    (void) umask(old_umask);
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup.socket.create_socket.end "
                "level=ERROR "
                "status=%d "
                "path=\"%s\" "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\"\n",
                -rc,
                manager->socket_path,
                "Error binding socket to filesystem",
                save_errno,
                strerror(save_errno));

        goto bind_failed;
    }

    flags = fcntl(sock, F_GETFD);
    if (flags < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup.socket.create_socket.end "
                "level=ERROR "
                "status=%d "
                "path=\"%s\" "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\"\n",
                -rc,
                manager->socket_path,
                "Error getting socket flags",
                errno,
                strerror(errno));

        goto fcntl_failed;
    }

    flags |= FD_CLOEXEC;
    if (fcntl(sock, F_SETFD, flags) < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup.socket.create_socket.end "
                "level=ERROR "
                "status=%d "
                "path=\"%s\" "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\"\n",
                -rc,
                manager->socket_path,
                "Error getting socket flags",
                errno,
                strerror(errno));

        goto fcntl_failed;
    }

    result = globus_l_gram_create_handle(
            sock,
            handle);

    if (result != GLOBUS_SUCCESS)
    {
        char * errstr;
        char * errstr_escaped;

        errstr = globus_error_print_friendly(globus_error_peek(result));
        errstr_escaped = globus_gram_prepare_log_string(errstr);

        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_FAILED_ALLOW_ATTACH;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup.socket.create_socket.end "
                "level=ERROR "
                "status=%d "
                "path=\"%s\" "
                "msg=\"%s\" "
                "reason=\"%s\"\n",
                -rc,
                manager->socket_path,
                "Error creating xio handle from socket",
                errstr_escaped ? errstr_escaped : "");

        if (errstr)
        {
            free(errstr);
        }
        if (errstr_escaped)
        {
            free(errstr_escaped);
        }
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
        char *                          errstr;
        char *                          errstr_escaped;

        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JM_FAILED_ALLOW_ATTACH;

        errstr = globus_error_print_friendly(globus_error_peek(result));
        errstr_escaped = globus_gram_prepare_log_string(errstr_escaped);

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                "event=gram.startup.socket.create_socket.end "
                "level=ERROR "
                "status=%d "
                "path=\"%s\" "
                "msg=\"%s\" "
                "reason=\"%s\"\n",
                -rc,
                manager->socket_path,
                "Error registering socket for reading",
                errstr_escaped ? errstr_escaped : errstr_escaped);

        if (errstr)
        {
            free(errstr);
        }
        if (errstr_escaped)
        {
            free(errstr_escaped);
        }

        goto register_read_failed;
    }

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE,
            "event=gram.startup.socket.create_socket.end "
            "level=TRACE "
            "status=%d "
            "path=\"%s\" "
            "\n",
            0,
            manager->socket_path);

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
close_pid_failed:
        fp = NULL;
write_pid_failed:
        if (fp != NULL)
        {
            fclose(fp);
        }
        remove(manager->pid_path);
open_pid_failed:
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

    if (rc == GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
            "event=gram.startup_socket_init.end "
            "level=DEBUG "
            "status=0 "
            "path=\"%s\" "
            "\n",
            manager->socket_path);
    }
    else
    {
        globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
            "event=gram.startup_socket_init.end "
            "level=DEBUG "
            "status=%d "
            "reason=\"%s\" "
            "\n",
            -rc,
            globus_gram_protocol_error_string(rc));
    }

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
    struct linger                       linger;

    globus_gram_job_manager_log(
            manager,
            GLOBUS_GRAM_JOB_MANAGER_LOG_INFO,
            "event=gram.send_job.start "
            "level=INFO "
            "http_body_fd=%d "
            "context_fd=%d "
            "response_fd=%d "
            "\n",
            http_body_fd,
            context_fd,
            response_fd);

    sprintf(sockpath,
            "%s/.globus/job/%s/%s.%s.sock",
            manager->config->home,
            manager->config->hostname,
            manager->config->jobmanager_type,
            manager->config->service_tag);

    /* create socket */
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = PF_LOCAL;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path)-1);
    sock = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.send_job.end "
                "level=WARN "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "errno=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                -rc,
                errno,
                "Error creating datagram socket",
                strerror(errno));
        goto socket_failed;
    }
    sndbuf = GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE;
    rc = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.send_job.end "
                "level=WARN "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "errno=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                -rc,
                errno,
                "Error setting datagram socket buffer",
                strerror(errno));
        goto setsockopt_failed;
    }
    rc = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.send_job.end "
                "level=WARN "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "address=\"%s\" "
                "errno=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                -rc,
                sockpath,
                errno,
                "Error making datagram connecting to Job Manager",
                strerror(errno));
        goto connect_failed;
    }
    /* create acksocks */
    rc = socketpair(PF_LOCAL, SOCK_STREAM, 0, acksock);
    if (rc < 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.send_job.end "
                "level=WARN "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "errno=%d "
                "msg=\"%s\" "
                "reason=\"%s\" "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                -rc,
                errno,
                "Error creating ack socket pair",
                strerror(errno));
        goto socketpair_failed;
    }
    linger.l_onoff = 1;
    linger.l_linger = 5;
    setsockopt(
            acksock[0],
            SOL_SOCKET,
            SO_LINGER,
            &linger,
            sizeof(linger));
    setsockopt(
            acksock[1],
            SOL_SOCKET,
            SO_LINGER,
            &linger,
            sizeof(linger));

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
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.send_job.end "
                "level=WARN "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "reason=\"%s\" "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                -rc,
                "Error exporting proxy");
        goto export_cred_failed;
    }

    if (cred_buffer.length > GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.send_job.end "
                "level=WARN "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "reason=\"%s\" "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                -rc,
                "Proxy larger than protocol allows");
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
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.send_job.end "
                "level=WARN "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                -rc,
                "Error sending datagram",
                errno,
                strerror(errno));
        goto sendmsg_failed;
    }
    memset(&message, 0, sizeof(struct msghdr));
    iov[0].iov_base = &byte;
    iov[0].iov_len = 1;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    close(acksock[0]);
    acksock[0] = -1;
    rc = recvmsg(acksock[1], &message, 0);
    if (rc < 0 || byte[0] != 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;

        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.send_job.end "
                "level=WARN "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                -rc,
                "Error receiving ack",
                errno,
                strerror(errno));
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
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_WARN,
                "event=gram.send_job.end "
                "level=WARN "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "msg=\"%s\" "
                "errno=%d "
                "reason=\"%s\" "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                -rc,
                "Error sending ack",
                errno,
                strerror(errno));
    }
    else
    {
        rc = GLOBUS_SUCCESS;
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_INFO,
                "event=gram.send_job.end "
                "level=INFO "
                "http_body_fd=%d "
                "context_fd=%d "
                "response_fd=%d "
                "status=%d "
                "\n",
                http_body_fd,
                context_fd,
                response_fd,
                0);
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
    const int                           MAX_NEW_PER_SELECT = 2;
    int                                 accepted;
    globus_bool_t                       done = GLOBUS_FALSE;
    int                                 tries;
    char *                              old_job_contact = NULL;
    globus_gram_jobmanager_request_t *  old_job_request = NULL;
    globus_bool_t                       version_only = GLOBUS_FALSE;
    static unsigned char                cred_buffer_value[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    gss_name_t                          name;
    gss_buffer_desc                     output_name;
    struct linger                       linger;

    cred_buffer.value = cred_buffer_value;

    for (accepted = 0; !done && accepted < MAX_NEW_PER_SELECT; accepted++)
    {
        globus_gram_job_manager_log(
                manager,
                GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
                "event=gram.new_request.start "
                "level=DEBUG "
                "fd=%d "
                "\n",
                manager->socket_fd);

        cred_buffer.length = GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE;
        memset(cred_buffer.value, 0, cred_buffer.length);

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
        tries = 10;
        while (tries > 0)
        { 
            rc = recvmsg(manager->socket_fd, &message, 0);
            if (rc <= 0 && errno == EINPROGRESS)
            {
                tries--;
                globus_libc_usleep(1000);
            }
            else
            {
                break;
            }
        }

        if (rc < 0)
        {
            int level;
            char * levelstr;
            done = GLOBUS_TRUE;

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;

            if (manager->done)
            {
                level = GLOBUS_GRAM_JOB_MANAGER_LOG_TRACE;
                levelstr = "TRACE";
            }
            else if (accepted == 0)
            {
                level = GLOBUS_GRAM_JOB_MANAGER_LOG_WARN;
                levelstr = "WARN";
            }
            else
            {
                level = GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG;
                levelstr = "DEBUG";
            }
            globus_gram_job_manager_log(
                    manager,
                    level,
                    "event=gram.new_request.end "
                    "level=%s "
                    "fd=%d "
                    "msg=\"%s\" "
                    "status=%d "
                    "errno=%d "
                    "reason=\"%s\" "
                    "\n",
                    levelstr,
                    manager->socket_fd,
                    "recvmsg failed",
                    -rc,
                    errno,
                    strerror(errno));

            goto failed_receive;
        }
        cred_buffer.length = rc;

        http_body_fd = -1;
        context_fd = -1;
        response_fd = -1;
        acksock = -1;

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

        if (http_body_fd < 0 || context_fd < 0 ||
            response_fd < 0 || acksock < 0)
        {
            done = GLOBUS_TRUE;

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;

            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.new_request.end "
                    "level=ERROR "
                    "fd=%d "
                    "status=%d "
                    "http_body_fd=%d "
                    "context_fd=%d "
                    "response_fd=%d "
                    "acksock=%d "
                    "reason=\"%s\" "
                    "\n",
                    manager->socket_fd,
                    -rc,
                    "Message did not contain required descriptors",
                    http_body_fd,
                    context_fd,
                    response_fd,
                    acksock,
                    globus_gram_protocol_error_string(rc));

            goto failed_get_data;
        }

        linger.l_onoff = 1;
        linger.l_linger = 5;
        setsockopt(
                response_fd,
                SOL_SOCKET,
                SO_LINGER,
                &linger,
                sizeof(linger));

        byte[0] = 0;
        iov[0].iov_base = byte;
        iov[0].iov_len = sizeof(byte);
        memset(&message, 0, sizeof(struct msghdr));
        message.msg_iov = iov;
        message.msg_iovlen = 1;
        errno = 0;
        rc = sendmsg(acksock, &message, 0);
        if (rc < 0)
        {
            done = GLOBUS_TRUE;

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;

            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.new_request.end "
                    "level=ERROR "
                    "fd=%d "
                    "status=%d "
                    "http_body_fd=%d "
                    "context_fd=%d "
                    "response_fd=%d "
                    "acksock=%d "
                    "errno=%d "
                    "reason=\"%s\" "
                    "\n",
                    manager->socket_fd,
                    -rc,
                    "Failed sending ack",
                    http_body_fd,
                    context_fd,
                    response_fd,
                    acksock,
                    errno,
                    strerror(errno));

            goto ackfailed;
        }

        byte[0] = 0;
        iov[0].iov_base = byte;
        iov[0].iov_len = sizeof(byte);
        memset(&message, 0, sizeof(struct msghdr));
        message.msg_iov = iov;
        message.msg_iovlen = 1;
        errno = 0;
        rc = -1;
        tries = 10;
        while (rc < 1 && tries > 0)
        {
            rc = recvmsg(acksock, &message, 0);
            tries--;
        }
        if (rc < 0 || byte[0] != 1)
        {
            done = GLOBUS_TRUE;

            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.new_request.end "
                    "level=ERROR "
                    "fd=%d "
                    "status=%d "
                    "msg=\"%s\" "
                    "http_body_fd=%d "
                    "context_fd=%d "
                    "response_fd=%d "
                    "acksock=%d "
                    "errno=%d "
                    "reason=\"%s\" "
                    "rc=%d "
                    "byte=%d "
                    "\n",
                    manager->socket_fd,
                    -GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED,
                    "Failed receiving ack",
                    http_body_fd,
                    context_fd,
                    response_fd,
                    acksock,
                    errno,
                    strerror(errno),
                    (int) rc,
                    (int) byte[0]);

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;

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
            char *                          errstr;
            char *                          errstr_escaped;

            globus_gss_assist_display_status_str(
                    &errstr,
                    "Import cred failed: ",
                    major_status,
                    minor_status,
                    0);

            errstr_escaped = globus_gram_prepare_log_string(errstr);

            globus_gram_job_manager_log(
                    manager,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_ERROR,
                    "event=gram.new_request.end "
                    "level=ERROR "
                    "fd=%d "
                    "status=%d "
                    "http_body_fd=%d "
                    "context_fd=%d "
                    "response_fd=%d "
                    "acksock=%d "
                    "reason=\"%s\" "
                    "\n",
                    manager->socket_fd,
                    -rc,
                    "Error importing credential",
                    http_body_fd,
                    context_fd,
                    response_fd,
                    acksock,
                    errstr_escaped ? errstr_escaped : "");

            if (errstr)
            {
                free(errstr);
            }

            if (errstr_escaped)
            {
                free(errstr_escaped);
            }
            done = GLOBUS_TRUE;
            goto failed_import_cred;
        }
        /* Load request data */
        rc = globus_gram_job_manager_request_load(
                manager,
                http_body_fd,
                context_fd,
                cred,
                &request,
                &context,
                &contact,
                &job_state_mask,
                &old_job_contact,
                &old_job_request,
                &version_only);
        if (rc != GLOBUS_SUCCESS)
        {
            if (rc == GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE &&
                old_job_request)
            {
                if (old_job_request->status ==
                            GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED )
                {
                    rc = old_job_request->failure_code;
                }
                else if (old_job_request->two_phase_commit != 0) 
                {
                    /*
                     * Condor-G expects waiting for commit message on restarts.
                     */
                    rc = GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT;
                }
                else
                {
                    rc = GLOBUS_SUCCESS;
                }
                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
                        "event=gram.new_request.info "
                        "level=DEBUG "
                        "gramid=%s "
                        "msg=\"%s\" "
                        "response=%d "
                        "job_state=%d "
                        "job_manager_state=%s "
                        "job_manager_restart_state=%s "
                        "\n",
                        old_job_request->job_contact_path,
                        "Restarting already restarted request",
                        rc,
                        old_job_request->status,
                        globus_i_gram_job_manager_state_strings[
                                old_job_request->jobmanager_state],
                        globus_i_gram_job_manager_state_strings[
                                old_job_request->restart_state]);
            }
            else if(rc != GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE)
            {
                assert(old_job_request == NULL);
                globus_i_gram_send_job_failure_stats(manager, rc);
                globus_gram_job_manager_log(
                        manager,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_DEBUG,
                        "event=gram.new_request.info "
                        "level=DEBUG "
                        "gramid=%s "
                        "msg=\"%s\" "
                        "response=%d "
                        "\n",
                        old_job_contact ? old_job_contact : "",
                        globus_gram_protocol_error_string(rc),
                        rc);
            }
            rc = globus_gram_job_manager_reply(
                    NULL,
                    manager,
                    rc,
                    (old_job_contact == NULL && old_job_request)
                        ? old_job_request->job_contact
                        : old_job_contact,
                    response_fd,
                    context);

            done = GLOBUS_TRUE;
            rc = globus_gram_job_manager_gsi_update_credential(
                    manager,
                    NULL,
                    cred);
            cred = GSS_C_NO_CREDENTIAL;

            if (old_job_request)
            {
                /* This occurs when a client tries to restart a job that
                 * we found during the load_all when this process started.
                 *
                 * We'll return information to the client about the job and
                 * make sure the job manager knows about the client
                 * contact/mask.
                 *
                 * If it is in a STOP state or two-phase end state, then we
                 * need to fake the restart by setting the state to just after
                 * two-phase commit and let the restart logic in the state
                 * machine pick it up from there.
                 * 
                 * Additionally, in the STOP state, we need to register the
                 * state machine.
                 */
                globus_gram_job_manager_contact_add(
                        old_job_request,
                        contact,
                        job_state_mask);
                
                if (old_job_request->jobmanager_state ==
                        GLOBUS_GRAM_JOB_MANAGER_STATE_STOP)
                {
                    if (old_job_request->jm_restart)
                    {
                        free(old_job_request->jm_restart);
                    }
                    old_job_request->jm_restart = strdup(
                            old_job_request->job_contact);

                    /* In GLOBUS_GRAM_JOB_MANAGER_STATE_START,
                     * the state machine jumps to the current restart state
                     * based on the value in the state file after receiving
                     * a two-phase commit signal
                     */
                    old_job_request->jobmanager_state =
                        GLOBUS_GRAM_JOB_MANAGER_STATE_START;

                    /* If the job is in another state, we'll assume that it's
                     * already being handled by the state machine
                     */
                    globus_gram_job_manager_state_machine_register(
                            old_job_request->manager,
                            old_job_request,
                            NULL);
                }
                else if (old_job_request->jobmanager_state ==
                                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END ||
                         old_job_request->jobmanager_state ==
                                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE)
                {
                    if (old_job_request->jm_restart)
                    {
                        free(old_job_request->jm_restart);
                    }
                    old_job_request->jm_restart = strdup(old_job_request->job_contact);

                    /* In GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED,
                     * the state machine jumps to the current restart state
                     * based on the value in the state file.
                     */
                    old_job_request->jobmanager_state =
                        GLOBUS_GRAM_JOB_MANAGER_STATE_START;
                }

                globus_gram_job_manager_remove_reference(
                        old_job_request->manager,
                        old_job_request->job_contact_path,
                        "jm_restart");
            }
            goto request_load_failed;
        }

        if (!version_only)
        {
            major_status = gss_inquire_cred(
                    &minor_status,
                    cred,
                    &name,
                    NULL,
                    NULL,
                    NULL);
            /* Don't care too much if this fails, as the user_dn will be
             * set to NULL in that case
             */
            if (major_status == GSS_S_COMPLETE)
            {
                major_status = gss_display_name(
                        &minor_status,
                        name,
                        &output_name,
                        NULL);
                request->job_stats.user_dn = strdup(output_name.value);
                gss_release_name(&minor_status, &name);
                gss_release_buffer(&minor_status, &output_name);
            }
        }

        rc = globus_gram_job_manager_gsi_update_credential(
                manager,
                NULL,
                cred);
        cred = GSS_C_NO_CREDENTIAL;

        /* How much do I care about this error? */
        if (rc != GLOBUS_SUCCESS || version_only)
        {
            globus_gram_job_manager_reply(
                    request,
                    manager,
                    rc,
                    NULL,
                    response_fd,
                    context);

            done = GLOBUS_TRUE;
            goto update_cred_failed;
        }

        if (!version_only)
        {
            globus_sockaddr_t           peer_address;
            socklen_t                   peer_address_len;
            char *                      peer_str = NULL;

            peer_address_len = sizeof(peer_address);

            rc = getpeername(
                    response_fd,
                    (struct sockaddr *) &peer_address,
                    &peer_address_len);
            if (rc == GLOBUS_SUCCESS)
            {
                rc = globus_libc_addr_to_contact_string(
                        &peer_address,
                        GLOBUS_LIBC_ADDR_NUMERIC,
                        &peer_str);
            }

            globus_gram_job_manager_request_log(
                    request,
                    GLOBUS_GRAM_JOB_MANAGER_LOG_INFO,
                    "event=gram.job.start "
                    "level=INFO "
                    "gramid=%s "
                    "peer=%s "
                    "\n",
                    request->job_contact_path,
                    peer_str ? peer_str : "\"\"");

            if (request->job_stats.client_address == NULL)
            {
                request->job_stats.client_address = peer_str;
            }
            else if (peer_str)
            {
                free(peer_str);
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
                globus_gram_job_manager_request_log(
                        request,
                        GLOBUS_GRAM_JOB_MANAGER_LOG_INFO,
                        "event=gram.job.end "
                        "level=INFO "
                        "gramid=%s "
                        "status=%d "
                        "msg=\"%s\" "
                        "reason=\"%s\" "
                        "\n",
                        request->job_contact_path,
                        -rc,
                        "Request start failed",
                        globus_gram_protocol_error_string(rc));
            }
        }

update_cred_failed:
        free(contact);

request_load_failed:
        if (old_job_contact != NULL)
        {
            free(old_job_contact);
        }
        if (cred != GSS_C_NO_CREDENTIAL)
        {
            gss_release_cred(
                    &minor_status,
                    &cred);
            cred = GSS_C_NO_CREDENTIAL;
        }
ackfailed:
failed_import_cred:
failed_get_data:
        if (acksock != -1)
        {
            close(acksock);
            acksock = -1;
        }
        if (http_body_fd != -1)
        {
            close(http_body_fd);
            http_body_fd = -1;
        }
        if (context_fd != -1)
        {
            close(context_fd);
            context_fd = -1;
        }
        if (response_fd != -1)
        {
            close(response_fd);
            response_fd = -1;
        }
failed_receive:
        ;
    }
    if (acksock != -1)
    {
        close(acksock);
        acksock = -1;
    }
    if (http_body_fd != -1)
    {
        close(http_body_fd);
        http_body_fd = -1;
    }
    if (context_fd != -1)
    {
        close(context_fd);
        context_fd = -1;
    }
    if (response_fd != -1)
    {
        close(response_fd);
        response_fd = -1;
    }

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

