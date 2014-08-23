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
 * The goal of this abstraction is to provide a common interface for the
 * asynchronous and IO operations only.
 */
#ifndef GLOBUS_XIO_SYSTEM_INCLUDE
#define GLOBUS_XIO_SYSTEM_INCLUDE

#include "globus_common.h"
#include "globus_xio_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GLOBUS_XIO_SYSTEM_MODULE (&globus_i_xio_system_module)
extern globus_module_descriptor_t       globus_i_xio_system_module;

#ifdef WIN32

#include <windows.h>
#include <winsock2.h>
#define GLOBUS_XIO_SYSTEM_INVALID_FILE INVALID_HANDLE_VALUE
#define GLOBUS_XIO_SYSTEM_INVALID_SOCKET INVALID_SOCKET

typedef struct globus_l_xio_win32_file_s * globus_xio_system_file_handle_t;
typedef struct globus_l_xio_win32_socket_s * globus_xio_system_socket_handle_t;

typedef SOCKET globus_xio_system_socket_t;
typedef HANDLE globus_xio_system_file_t;

#else

#define GLOBUS_XIO_SYSTEM_INVALID_FILE  -1
#define GLOBUS_XIO_SYSTEM_INVALID_SOCKET  -1

/* these are handles to this interface */
typedef struct globus_l_xio_system_s * globus_xio_system_file_handle_t;
typedef struct globus_l_xio_system_s * globus_xio_system_socket_handle_t;

/* these are the native descriptor types */
typedef int globus_xio_system_socket_t;
typedef int globus_xio_system_file_t;

/* deprecated, do not use! */
typedef int globus_xio_system_native_handle_t;
#endif

typedef enum
{
    GLOBUS_XIO_SYSTEM_ERROR_SYSTEM_ERROR = 1024,
    GLOBUS_XIO_SYSTEM_ERROR_TOO_MANY_FDS,
    GLOBUS_XIO_SYSTEM_ERROR_ALREADY_REGISTERED,
    GLOBUS_XIO_SYSTEM_ERROR_OPERATION_CANCELED,
    GLOBUS_XIO_SYSTEM_ERROR_NOT_REGISTERED
} globus_xio_system_error_type_t;

typedef enum
{
    GLOBUS_XIO_SYSTEM_FILE = 1,
    GLOBUS_XIO_SYSTEM_TCP,
    GLOBUS_XIO_SYSTEM_TCP_LISTENER,
    GLOBUS_XIO_SYSTEM_UDP
} globus_xio_system_type_t;

typedef void
(*globus_xio_system_callback_t)(
    globus_result_t                     result,
    void *                              user_arg);

typedef void
(*globus_xio_system_data_callback_t)(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

/**
 * This handle is only used to maintain state for the operations below.
 * As of now, the only modification it makes to the handle is set the
 * non-blocking attribute.
 * 
 * Note that initial file pointer is taken here and cached throughout.
 * do not seek yourself
 */
globus_result_t
globus_xio_system_file_init(
    globus_xio_system_file_handle_t *   handle,
    globus_xio_system_file_t            fd);

/* this does *not* close the native handle.
 *  It should remove the non-blocking setting
 * 
 * do not call this with outstanding operations.  you can call it from with
 * a callback
 */
void
globus_xio_system_file_destroy(
    globus_xio_system_file_handle_t     handle);

globus_result_t
globus_xio_system_file_register_read(
    globus_xio_operation_t              op,
    globus_xio_system_file_handle_t     handle,
    globus_off_t                        offset,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_file_register_write(
    globus_xio_operation_t              op,
    globus_xio_system_file_handle_t     handle,
    globus_off_t                        offset,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

/* pass 0 for waitforbytes to not block */
globus_result_t
globus_xio_system_file_read(
    globus_xio_system_file_handle_t     handle,
    globus_off_t                        offset,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes);

globus_result_t
globus_xio_system_file_write(
    globus_xio_system_file_handle_t     handle,
    globus_off_t                        offset,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes);

/* syscall abstractions */
globus_off_t
globus_xio_system_file_get_position(
    globus_xio_system_file_t            fd);
    
globus_off_t
globus_xio_system_file_get_size(
    globus_xio_system_file_t            fd);

globus_xio_system_file_t
globus_xio_system_convert_stdio(
    const char *                        stdio);

globus_result_t
globus_xio_system_file_truncate(
    globus_xio_system_file_t            fd,
    globus_off_t                        size);

globus_result_t
globus_xio_system_file_open(
    globus_xio_system_file_t *          fd,
    const char *                        filename,
    int                                 flags,
    unsigned long                       mode);

globus_result_t
globus_xio_system_file_close(
    globus_xio_system_file_t            fd);
    
/**
 * This handle is only used to maintain state for the operations below.
 * As of now, the only modification it makes to the handle is set the
 * non-blocking attribute.
 */
globus_result_t
globus_xio_system_socket_init(
    globus_xio_system_socket_handle_t * handle,
    globus_xio_system_socket_t          socket,
    globus_xio_system_type_t            type);

/* this does *not* close the native handle.
 *  It should remove the non-blocking setting
 * 
 * do not call this with outstanding operations.  you can call it from with
 * a callback
 */
void
globus_xio_system_socket_destroy(
    globus_xio_system_socket_handle_t   handle);
    
globus_result_t
globus_xio_system_socket_register_connect(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   handle,
    globus_sockaddr_t *                 addr,
    globus_xio_system_callback_t        callback,
    void *                              user_arg);

globus_result_t
globus_xio_system_socket_register_accept(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   listener_handle,
    globus_xio_system_socket_t *        out_handle,
    globus_xio_system_callback_t        callback,
    void *                              user_arg);

/* if using from, probably want waitforbytes to be 1 */
/* if waitforbytes == 0 and iov[0].iov_len == 0
 * behave like select()... ie notify when data ready
 */
globus_result_t
globus_xio_system_socket_register_read(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 out_from,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

/* if waitforbytes == 0 and iov[0].iov_len == 0
 * behave like select()... ie notify when data ready
 */
globus_result_t
globus_xio_system_socket_register_write(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 to,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg);

/* if waitforbytes == 0, do a non-blocking read */
globus_result_t
globus_xio_system_socket_read(
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 from,
    globus_size_t *                     nbytes);

/* if waitforbytes == 0, do a non-blocking write */
globus_result_t
globus_xio_system_socket_write(
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 to,
    globus_size_t *                     nbytes);

/* syscall abstractions */
globus_result_t
globus_xio_system_socket_create(
    globus_xio_system_socket_t *        socket,
    int                                 domain,
    int                                 type,
    int                                 protocol);

globus_result_t
globus_xio_system_socket_setsockopt(
    globus_xio_system_socket_t          socket,
    int                                 level,
    int                                 optname,
    const void *                        optval,
    globus_socklen_t                    optlen);

globus_result_t
globus_xio_system_socket_getsockopt(
    globus_xio_system_socket_t          socket,
    int                                 level,
    int                                 optname,
    void *                              optval,
    globus_socklen_t *                  optlen);
    
globus_result_t
globus_xio_system_socket_getsockname(
    globus_xio_system_socket_t          socket,
    struct sockaddr *                   name,
    globus_socklen_t *                  namelen);

globus_result_t
globus_xio_system_socket_getpeername(
    globus_xio_system_socket_t          socket,
    struct sockaddr *                   name,
    globus_socklen_t *                  namelen);

globus_result_t
globus_xio_system_socket_bind(
    globus_xio_system_socket_t          socket,
    struct sockaddr *                   addr,
    globus_socklen_t                    addrlen);

globus_result_t
globus_xio_system_socket_listen(
    globus_xio_system_socket_t          socket,
    int                                 backlog);
    
globus_result_t
globus_xio_system_socket_connect(
    globus_xio_system_socket_t          socket,
    const struct sockaddr *             addr,
    globus_socklen_t                    addrlen);
    
globus_result_t
globus_xio_system_socket_close(
    globus_xio_system_socket_t          socket);

#ifdef WIN32

/**
 * XXX
 * readonly on windows means something different than on unix.  don't support
 * it for now
 */
 
#undef S_IRWXU
#define S_IRWXU 0
#undef S_IRUSR
#define S_IRUSR 0
#undef S_IWUSR
#define S_IWUSR 0
#undef S_IXUSR
#define S_IXUSR 0
#undef S_IRWXO
#define S_IRWXO 0
#undef S_IROTH
#define S_IROTH 0
#undef S_IWOTH
#define S_IWOTH 0
#undef S_IXOTH
#define S_IXOTH 0
#undef S_IRWXG
#define S_IRWXG 0
#undef S_IRGRP
#define S_IRGRP 0
#undef S_IWGRP
#define S_IWGRP 0
#undef S_IXGRP
#define S_IXGRP 0

#endif

#ifdef __cplusplus
}
#endif

#endif
