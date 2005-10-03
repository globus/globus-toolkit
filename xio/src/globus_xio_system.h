/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

/**
 * The goal of this abstraction is to provide a common interface for the
 * asynchronous and IO operations only.
 */
#ifndef GLOBUS_XIO_SYSTEM_INCLUDE
#define GLOBUS_XIO_SYSTEM_INCLUDE

#include "globus_common.h"
#include "globus_xio_types.h"

EXTERN_C_BEGIN

#define GLOBUS_XIO_SYSTEM_MODULE (&globus_i_xio_system_module)
extern globus_module_descriptor_t       globus_i_xio_system_module;

#ifndef WIN32

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

#else

#include <Windows.h>
#include <Winsock2.h>
#define GLOBUS_XIO_SYSTEM_INVALID_FILE INVALID_HANDLE_VALUE
#define GLOBUS_XIO_SYSTEM_INVALID_SOCKET INVALID_SOCKET

typedef struct globus_l_xio_win32_file_s * globus_xio_system_file_handle_t;
typedef struct globus_l_xio_win32_socket_s * globus_xio_system_socket_handle_t;

typedef SOCKET globus_xio_system_socket_t;
typedef HANDLE globus_xio_system_file_t;

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

globus_result_t
globus_xio_system_socket_read(
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 from,
    globus_size_t *                     nbytes);

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
    socklen_t                           optlen);

globus_result_t
globus_xio_system_socket_getsockopt(
    globus_xio_system_socket_t          socket,
    int                                 level,
    int                                 optname,
    void *                              optval,
    socklen_t *                         optlen);
    
globus_result_t
globus_xio_system_socket_getsockname(
    globus_xio_system_socket_t          socket,
    struct sockaddr *                   name,
    socklen_t *                         namelen);

globus_result_t
globus_xio_system_socket_getpeername(
    globus_xio_system_socket_t          socket,
    struct sockaddr *                   name,
    socklen_t *                         namelen);

globus_result_t
globus_xio_system_socket_bind(
    globus_xio_system_socket_t          socket,
    struct sockaddr *                   addr,
    socklen_t                           addrlen);

globus_result_t
globus_xio_system_socket_listen(
    globus_xio_system_socket_t          socket,
    int                                 backlog);
    
globus_result_t
globus_xio_system_socket_connect(
    globus_xio_system_socket_t          socket,
    const struct sockaddr *             addr,
    socklen_t                           addrlen);
    
globus_result_t
globus_xio_system_socket_close(
    globus_xio_system_socket_t          socket);

/* only read-only vs read-write file perms available */
#ifdef WIN32

#define GLOBUS_XIO_SYSTEM_FILE_READABLE 0
#define GLOBUS_XIO_SYSTEM_FILE_WRITABLE 1

/* use 1 for writable */
#undef S_IRWXU
#define S_IRWXU GLOBUS_XIO_SYSTEM_FILE_WRITABLE
#undef S_IRUSR
#define S_IRUSR GLOBUS_XIO_SYSTEM_FILE_READABLE
#undef S_IWUSR
#define S_IWUSR GLOBUS_XIO_SYSTEM_FILE_WRITABLE
#undef S_IXUSR
#define S_IXUSR GLOBUS_XIO_SYSTEM_FILE_READABLE
#undef S_IRWXO
#define S_IRWXO GLOBUS_XIO_SYSTEM_FILE_WRITABLE
#undef S_IROTH
#define S_IROTH GLOBUS_XIO_SYSTEM_FILE_READABLE
#undef S_IWOTH
#define S_IWOTH GLOBUS_XIO_SYSTEM_FILE_WRITABLE
#undef S_IXOTH
#define S_IXOTH GLOBUS_XIO_SYSTEM_FILE_READABLE
#undef S_IRWXG
#define S_IRWXG GLOBUS_XIO_SYSTEM_FILE_WRITABLE
#undef S_IRGRP
#define S_IRGRP GLOBUS_XIO_SYSTEM_FILE_READABLE
#undef S_IWGRP
#define S_IWGRP GLOBUS_XIO_SYSTEM_FILE_WRITABLE
#undef S_IXGRP
#define S_IXGRP GLOBUS_XIO_SYSTEM_FILE_READABLE

#endif

EXTERN_C_END

#endif
