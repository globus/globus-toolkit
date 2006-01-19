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

#ifndef GLOBUS_INCLUDE_GLOBUS_IO_H
#define GLOBUS_INCLUDE_GLOBUS_IO_H

#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_file_driver.h"
#include "globus_xio_gsi.h"

#define GLOBUS_IO_OVER_XIO 1

EXTERN_C_BEGIN

#define GLOBUS_IO_MODULE (&globus_l_io_module)

extern globus_module_descriptor_t       globus_l_io_module;

#define _IOSL(s) globus_common_i18n_get_string( \
			GLOBUS_IO_MODULE, \
			s)

typedef struct globus_l_io_handle_s *   globus_io_handle_t;
typedef struct globus_l_io_attr_s *     globus_io_attr_t;
/*** XXXX ***/
typedef struct blah_s *                 globus_netlogger_handle_t;

typedef void
(*globus_io_callback_t)(
    void *                              callback_arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result);

typedef void
(*globus_io_read_callback_t)(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes);

typedef void
(*globus_io_write_callback_t)(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes);

typedef void
(*globus_io_writev_callback_t)(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    struct iovec *                      iov,
    globus_size_t                       iovcnt,
    globus_size_t                       nbytes);

typedef enum
{
    GLOBUS_IO_HANDLE_TYPE_TCP_LISTENER,
    GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED,
    GLOBUS_IO_HANDLE_TYPE_UDSS_LISTENER,
    GLOBUS_IO_HANDLE_TYPE_UDSS_CONNECTED,
    GLOBUS_IO_HANDLE_TYPE_FILE,
    GLOBUS_IO_HANDLE_TYPE_UDP_UNCONNECTED,
    GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED,
    GLOBUS_IO_HANDLE_TYPE_UDDS_UNCONNECTED,
    GLOBUS_IO_HANDLE_TYPE_UDDS_CONNECTED,
    GLOBUS_IO_HANDLE_TYPE_INTERNAL
} globus_io_handle_type_t;

typedef enum
{
    GLOBUS_IO_FILE_CREAT        = GLOBUS_XIO_FILE_CREAT,
    GLOBUS_IO_FILE_EXCL         = GLOBUS_XIO_FILE_EXCL,
    GLOBUS_IO_FILE_RDONLY       = GLOBUS_XIO_FILE_RDONLY,
    GLOBUS_IO_FILE_WRONLY       = GLOBUS_XIO_FILE_WRONLY,
    GLOBUS_IO_FILE_RDWR         = GLOBUS_XIO_FILE_RDWR,
    GLOBUS_IO_FILE_TRUNC        = GLOBUS_XIO_FILE_TRUNC,
    GLOBUS_IO_FILE_APPEND       = GLOBUS_XIO_FILE_APPEND
} globus_io_file_flag_t;

typedef enum
{
    GLOBUS_IO_FILE_IRWXU        = GLOBUS_XIO_FILE_IRWXU,
    GLOBUS_IO_FILE_IRUSR        = GLOBUS_XIO_FILE_IRUSR,
    GLOBUS_IO_FILE_IWUSR        = GLOBUS_XIO_FILE_IWUSR,
    GLOBUS_IO_FILE_IXUSR        = GLOBUS_XIO_FILE_IXUSR,
    GLOBUS_IO_FILE_IRWXO        = GLOBUS_XIO_FILE_IRWXO,
    GLOBUS_IO_FILE_IROTH        = GLOBUS_XIO_FILE_IROTH,
    GLOBUS_IO_FILE_IWOTH        = GLOBUS_XIO_FILE_IWOTH,
    GLOBUS_IO_FILE_IXOTH        = GLOBUS_XIO_FILE_IXOTH,
    GLOBUS_IO_FILE_IRWXG        = GLOBUS_XIO_FILE_IRWXG,
    GLOBUS_IO_FILE_IRGRP        = GLOBUS_XIO_FILE_IRGRP,
    GLOBUS_IO_FILE_IWGRP        = GLOBUS_XIO_FILE_IWGRP,
    GLOBUS_IO_FILE_IXGRP        = GLOBUS_XIO_FILE_IXGRP
} globus_io_file_create_mode_t;

typedef enum
{
    GLOBUS_IO_SEEK_SET = GLOBUS_XIO_FILE_SEEK_SET,
    GLOBUS_IO_SEEK_CUR = GLOBUS_XIO_FILE_SEEK_CUR,
    GLOBUS_IO_SEEK_END = GLOBUS_XIO_FILE_SEEK_END
} globus_io_whence_t;

typedef enum
{
    GLOBUS_IO_FILE_TYPE_TEXT = GLOBUS_XIO_FILE_TEXT,
    GLOBUS_IO_FILE_TYPE_BINARY = GLOBUS_XIO_FILE_BINARY
} globus_io_file_type_t;

typedef enum
{
    GLOBUS_IO_SEND_MSG_OOB = GLOBUS_XIO_TCP_SEND_OOB
} globus_io_send_flags_t;

globus_result_t
globus_io_register_cancel(
    globus_io_handle_t *                handle,
    globus_bool_t                       perform_callbacks,
    globus_io_callback_t                cancel_callback,
    void *                              cancel_arg);

globus_result_t
globus_io_cancel(
    globus_io_handle_t *                handle,
    globus_bool_t                       perform_callbacks);

globus_result_t
globus_io_register_close(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback,
    void *                              callback_arg);

globus_result_t
globus_io_close(
    globus_io_handle_t *                handle);

globus_io_handle_type_t
globus_io_get_handle_type(
    globus_io_handle_t *                handle);

globus_result_t
globus_io_handle_get_user_pointer(
    globus_io_handle_t *                handle,
    void **                             user_pointer);

globus_result_t
globus_io_handle_set_user_pointer(
    globus_io_handle_t *                handle,
    void *                              user_pointer);

globus_result_t
globus_io_register_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t                       wait_for_nbytes,
    globus_io_read_callback_t           callback,
    void *                              callback_arg);

globus_result_t
globus_io_try_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t *                     nbytes_read);

globus_result_t
globus_io_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t                       wait_for_nbytes,
    globus_size_t *                     nbytes_read);

globus_result_t
globus_io_register_write(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    globus_io_write_callback_t          write_callback,
    void *                              callback_arg);

globus_result_t
globus_io_register_send(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_io_write_callback_t          write_callback,
    void *                              callback_arg);

globus_result_t
globus_io_register_writev(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    globus_size_t                       iovcnt,
    globus_io_writev_callback_t         writev_callback,
    void *                              callback_arg);

globus_result_t
globus_io_try_write(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t *                     nbytes_written);

globus_result_t
globus_io_try_send(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_size_t *                     nbytes_sent);

globus_result_t
globus_io_write(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    globus_size_t *                     nbytes_written);

globus_result_t
globus_io_send(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_size_t *                     nbytes_sent);

globus_result_t
globus_io_writev(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    globus_size_t                       iovcnt,
    globus_size_t *                     bytes_written);

globus_result_t
globus_io_tcp_register_connect(
    const char *                        host,
    unsigned short                      port,
    globus_io_attr_t *                  attr,
    globus_io_callback_t                callback,
    void *                              callback_arg,
    globus_io_handle_t *                handle);

globus_result_t
globus_io_tcp_connect(
    const char *                        host,
    unsigned short                      port,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle);

globus_result_t
globus_io_tcp_create_listener(
    unsigned short *                    port,
    int                                 backlog,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle);

#define globus_io_register_listen globus_io_tcp_register_listen
#define globus_io_listen globus_io_tcp_listen

globus_result_t
globus_io_tcp_register_listen(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback,
    void *                              callback_arg);

globus_result_t
globus_io_tcp_listen(
    globus_io_handle_t *                handle);

globus_result_t
globus_io_tcp_register_accept(
    globus_io_handle_t *                listener_handle,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                new_handle,
    globus_io_callback_t                callback,
    void *                              callback_arg);

globus_result_t
globus_io_tcp_accept(
    globus_io_handle_t *                listener_handle,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle);

globus_result_t
globus_io_register_select(
    globus_io_handle_t *                handle,
    globus_io_callback_t                read_callback_func,
    void *                              read_callback_arg,
    globus_io_callback_t                write_callback_func,
    void *                              write_callback_arg,
    globus_io_callback_t                except_callback_func,
    void *                              except_callback_arg);
    
/* host must have room for 4 ints. will fail if ip is ipv6 */
globus_result_t
globus_io_tcp_get_local_address(
    globus_io_handle_t *                handle,
    int *                               host,
    unsigned short *                    port);

globus_result_t
globus_io_tcp_get_remote_address(
    globus_io_handle_t *                handle,
    int *                               host,
    unsigned short *                    port);

/* host must have room for 16 ints,
 * count will be passed back: 4 for ipv4, 16 for ipv6
 */
globus_result_t
globus_io_tcp_get_local_address_ex(
    globus_io_handle_t *                handle,
    int *                               host,
    int *                               count,
    unsigned short *                    port);

globus_result_t
globus_io_tcp_get_remote_address_ex(
    globus_io_handle_t *                handle,
    int *                               host,
    int *                               count,
    unsigned short *                    port);

globus_result_t
globus_io_tcp_posix_convert(
    int                                 socket,
    globus_io_attr_t *                  attributes,
    globus_io_handle_t *                handle);

globus_result_t
globus_io_tcp_posix_convert_listener(
    int                                 socket,
    globus_io_attr_t *                  attributes,
    globus_io_handle_t *                handle);

globus_result_t
globus_io_fileattr_init(
    globus_io_attr_t *                  attr);

globus_result_t
globus_io_fileattr_destroy(
    globus_io_attr_t *                  attr);

globus_result_t
globus_io_attr_set_file_type(
    globus_io_attr_t *                  attr,
    globus_io_file_type_t               file_type);

globus_result_t
globus_io_attr_get_file_type(
    globus_io_attr_t *                  attr,
    globus_io_file_type_t *             file_type);

globus_result_t
globus_io_file_open(
    const char *                        path,
    int                                 flags,
    int                                 mode,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle);

globus_result_t
globus_io_file_seek(
    globus_io_handle_t *                handle,
    globus_off_t                        offset,
    globus_io_whence_t                  whence);

globus_result_t
globus_io_file_posix_convert(
    int                                 fd,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle);

globus_result_t
globus_io_tcpattr_init(
    globus_io_attr_t *                  attr);

globus_result_t
globus_io_tcpattr_destroy(
    globus_io_attr_t *                  attr);

globus_result_t
globus_io_tcp_get_attr(
    globus_io_handle_t *                handle,
    globus_io_attr_t *                  attr);

globus_result_t
globus_io_attr_set_tcp_restrict_port(
    globus_io_attr_t *                  attr,
    globus_bool_t                       restrict_port);

globus_result_t
globus_io_attr_get_tcp_restrict_port(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     restrict_port);

globus_result_t
globus_io_attr_set_socket_reuseaddr(
    globus_io_attr_t *                  attr,
    globus_bool_t                       reuseaddr);

globus_result_t
globus_io_attr_get_socket_reuseaddr(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     reuseaddr);

globus_result_t
globus_io_attr_set_socket_keepalive(
    globus_io_attr_t *                  attr,
    globus_bool_t                       keepalive);

globus_result_t
globus_io_attr_get_socket_keepalive(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     keepalive);

globus_result_t
globus_io_attr_set_socket_linger(
    globus_io_attr_t *                  attr,
    globus_bool_t                       linger,
    int                                 linger_time);

globus_result_t
globus_io_attr_get_socket_linger(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     linger,
    int *                               linger_time);

globus_result_t
globus_io_attr_set_socket_oobinline(
    globus_io_attr_t *                  attr,
    globus_bool_t                       oobinline);

globus_result_t
globus_io_attr_get_socket_oobinline(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     oobinline);

globus_result_t
globus_io_attr_set_socket_sndbuf(
    globus_io_attr_t *                  attr,
    int                                 sndbuf);

globus_result_t
globus_io_attr_get_socket_sndbuf(
    globus_io_attr_t *                  attr,
    int *                               sndbuf);

globus_result_t
globus_io_attr_set_socket_rcvbuf(
    globus_io_attr_t *                  attr,
    int                                 rcvbuf);

globus_result_t
globus_io_attr_get_socket_rcvbuf(
    globus_io_attr_t *                  attr,
    int *                               rcvbuf);

globus_result_t
globus_io_attr_set_tcp_nodelay(
    globus_io_attr_t *                  attr,
    globus_bool_t                       nodelay);

globus_result_t
globus_io_attr_get_tcp_nodelay(
    globus_io_attr_t *                  attr,
    globus_bool_t *                     nodelay);

globus_result_t
globus_io_attr_set_tcp_interface(
    globus_io_attr_t *                  attr,
    const char *                        interface_addr);

globus_result_t
globus_io_attr_get_tcp_interface(
    globus_io_attr_t *                  attr,
    char **                             interface_addr);

globus_result_t
globus_io_attr_set_tcp_allow_ipv6(
    globus_io_attr_t *                  attr,
    globus_bool_t                       allow);

globus_bool_t
globus_io_eof(
    globus_object_t *                   eof);

globus_result_t
globus_io_attr_set_callback_space(
    globus_io_attr_t *                  attr,
    globus_callback_space_t             space);

globus_result_t
globus_io_attr_get_callback_space(
    globus_io_attr_t *                  attr,
    globus_callback_space_t *           space);

#include "globus_gss_assist.h"

#ifndef _HAVE_GSI_EXTENDED_GSSAPI
#include "globus_gss_ext_compat.h"
#endif

typedef struct globus_l_io_secure_authorization_data_s * globus_io_secure_authorization_data_t;

typedef globus_bool_t
(*globus_io_secure_authorization_callback_t)(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    char *                              identity,
    gss_ctx_id_t                        context_handle);

typedef void
(* globus_io_delegation_callback_t)(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    gss_cred_id_t                       delegated_cred,
    OM_uint32                           time_rec);

typedef enum
{
    GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE,
    GLOBUS_IO_SECURE_AUTHENTICATION_MODE_GSSAPI,
    GLOBUS_IO_SECURE_AUTHENTICATION_MODE_MUTUAL,
    GLOBUS_IO_SECURE_AUTHENTICATION_MODE_ANONYMOUS
} globus_io_secure_authentication_mode_t;

typedef enum
{
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE =
    GLOBUS_XIO_GSI_NO_AUTHORIZATION,
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF =
    GLOBUS_XIO_GSI_SELF_AUTHORIZATION,
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY =
    GLOBUS_XIO_GSI_IDENTITY_AUTHORIZATION,
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST =
    GLOBUS_XIO_GSI_HOST_AUTHORIZATION,
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK
} globus_io_secure_authorization_mode_t;

typedef enum
{
    GLOBUS_IO_SECURE_PROTECTION_MODE_NONE =
    GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE,
    GLOBUS_IO_SECURE_PROTECTION_MODE_SAFE =
    GLOBUS_XIO_GSI_PROTECTION_LEVEL_INTEGRITY,
    GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE =
    GLOBUS_XIO_GSI_PROTECTION_LEVEL_PRIVACY
} globus_io_secure_protection_mode_t;

typedef enum
{
    GLOBUS_IO_SECURE_DELEGATION_MODE_NONE =
    GLOBUS_XIO_GSI_DELEGATION_MODE_NONE,
    GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY =
    GLOBUS_XIO_GSI_DELEGATION_MODE_LIMITED,
    GLOBUS_IO_SECURE_DELEGATION_MODE_FULL_PROXY =
    GLOBUS_XIO_GSI_DELEGATION_MODE_FULL
} globus_io_secure_delegation_mode_t;

typedef enum
{
    GLOBUS_IO_SECURE_PROXY_MODE_NONE =
    GLOBUS_XIO_GSI_PROXY_MODE_LIMITED,
    GLOBUS_IO_SECURE_PROXY_MODE_LIMITED =
    GLOBUS_XIO_GSI_PROXY_MODE_FULL,
    GLOBUS_IO_SECURE_PROXY_MODE_MANY =
    GLOBUS_XIO_GSI_PROXY_MODE_MANY
} globus_io_secure_proxy_mode_t;

typedef enum
{
    GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR = 0,
    GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP,
    GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP
} globus_io_secure_channel_mode_t;

globus_result_t
globus_io_tcp_get_security_context(
    globus_io_handle_t *                handle,
    gss_ctx_id_t *                      context);

globus_result_t
globus_io_tcp_get_delegated_credential(
    globus_io_handle_t *                handle,
    gss_cred_id_t *                     cred);

/* new api just for gram_protocol_io */
globus_result_t
globus_io_tcp_set_credential(
    globus_io_handle_t *                handle,
    gss_cred_id_t                       credential);

globus_result_t
globus_io_tcp_get_credential(
    globus_io_handle_t *                handle,
    gss_cred_id_t *                     credential);

globus_result_t
globus_io_register_init_delegation(
    globus_io_handle_t *                handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    globus_io_delegation_callback_t     callback,
    void *                              callback_arg);

globus_result_t
globus_io_init_delegation(
    globus_io_handle_t *                handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req);

globus_result_t
globus_io_register_accept_delegation(
    globus_io_handle_t *                handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    globus_io_delegation_callback_t     callback,
    void *                              callback_arg);

globus_result_t
globus_io_accept_delegation(
    globus_io_handle_t *                handle,
    gss_cred_id_t *                     delegated_cred,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec);


globus_result_t
globus_io_attr_set_secure_authentication_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_authentication_mode_t
                                        mode,
    gss_cred_id_t                       credential);

globus_result_t
globus_io_attr_get_secure_authentication_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_authentication_mode_t *
                                        mode,
    gss_cred_id_t *                     credential);

globus_result_t
globus_io_attr_set_secure_authorization_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_authorization_mode_t
                                        mode,
    globus_io_secure_authorization_data_t *
                                        data);

globus_result_t
globus_io_attr_get_secure_authorization_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_authorization_mode_t *
                                        mode,
    globus_io_secure_authorization_data_t *
                                        data);
globus_result_t
globus_io_attr_set_secure_extension_oids(
    globus_io_attr_t *                  attr,
    gss_OID_set                         extension_oids);

globus_result_t
globus_io_attr_get_secure_extension_oids(
    globus_io_attr_t *                  attr,
    gss_OID_set *                       extension_oids);

globus_result_t
globus_io_secure_authorization_data_initialize(
    globus_io_secure_authorization_data_t *
                                        data);
globus_result_t
globus_io_secure_authorization_data_destroy(
    globus_io_secure_authorization_data_t *
                                        data);
globus_result_t
globus_io_secure_authorization_data_set_identity(
    globus_io_secure_authorization_data_t *
                                        data,
    char *                              identity);

globus_result_t
globus_io_secure_authorization_data_get_identity(
    globus_io_secure_authorization_data_t *
                                        data,
    char **                             identity);

globus_result_t
globus_io_secure_authorization_data_set_callback(
    globus_io_secure_authorization_data_t *
                                        data,
    globus_io_secure_authorization_callback_t
                                        callback,
    void *                              callback_arg);

globus_result_t
globus_io_secure_authorization_data_get_callback(
    globus_io_secure_authorization_data_t *
                                        data,
    globus_io_secure_authorization_callback_t *
                                        callback,
    void **                             callback_arg);

globus_result_t
globus_io_attr_set_secure_channel_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_channel_mode_t     mode);

globus_result_t
globus_io_attr_get_secure_channel_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_channel_mode_t *   mode);

globus_result_t
globus_io_attr_set_secure_protection_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_protection_mode_t  mode);

globus_result_t
globus_io_attr_get_secure_protection_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_protection_mode_t *mode);

globus_result_t
globus_io_attr_set_secure_delegation_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_delegation_mode_t  mode);

globus_result_t
globus_io_attr_get_secure_delegation_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_delegation_mode_t *
                                        mode);
globus_result_t
globus_io_attr_set_secure_proxy_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_proxy_mode_t       mode);

globus_result_t
globus_io_attr_get_secure_proxy_mode(
    globus_io_attr_t *                  attr,
    globus_io_secure_proxy_mode_t *     mode);


/* netlogger */

globus_result_t
globus_io_attr_netlogger_set_handle(
    globus_io_attr_t *                  attr,
    globus_netlogger_handle_t *         nl_handle);

globus_result_t
globus_io_attr_netlogger_copy_handle(
    globus_netlogger_handle_t *              src,
    globus_netlogger_handle_t *              dst);

globus_result_t
globus_netlogger_write(
    globus_netlogger_handle_t *       nl_handle,
    const char *                      event,
    const char *                      id,
    const char *                      level,
    const char *                      tag);

globus_result_t
globus_netlogger_handle_init(
    globus_netlogger_handle_t *       gnl_handle,
    const char *                      hostname,
    const char *                      progname,
    const char *                      pid);

globus_result_t
globus_netlogger_handle_destroy(
    globus_netlogger_handle_t *       nl_handle);

globus_result_t
globus_netlogger_get_nlhandle(
    globus_netlogger_handle_t *       nl_handle,
    void **                           handle);

globus_result_t
globus_netlogger_set_desc(
    globus_netlogger_handle_t *       nl_handle,
    char *                            desc);

globus_result_t
globus_io_handle_get_socket_buf(
    globus_io_handle_t *                handle,
    int *                               rcvbuf,
    int *                               sndbuf);


EXTERN_C_END

#include "globus_io_error_hierarchy.h"

#endif
