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
 * @mainpage Globus I/O API
 *
 * The globus_io library is motivated by the desire to provide a
 * uniform I/O interface to stream and datagram style
 * communications. The goals in doing this are to
 * 
 * - Provide a robust way to describe, apply, and query connection
 *   properties. These include the standard socket options (socket
 *   buffer sizes, etc), as well as additional attributes.
 *   These include security attributes and, eventually, QoS attributes.
 * - Provide a service to support nonblocking I/O and handle
 *   asynchronous file and network events.
 * - Provide a simple and portable way to implement communication
 *   protocols. Globus components such as GASS and GRAM can use this to
 *   redefine their control message protocol in terms of TCP messages,
 *   instead of nexus RSRs.
 *
 * Any program that uses Globus I/O functions must include "globus_io.h".
 *
 * @htmlonly
 * <a href="main.html" target="_top">View documentation without frames</a><br>
 * <a href="index.html" target="_top">View documentation with frames</a><br>
 * @endhtmlonly
 */

#ifndef GLOBUS_INCLUDE_GLOBUS_IO_H
#define GLOBUS_INCLUDE_GLOBUS_IO_H

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
#include "globus_common.h"
#include "globus_gss_assist.h"
#endif

#ifndef _HAVE_GSI_EXTENDED_GSSAPI
#include "globus_gss_ext_compat.h"
#endif

#ifdef TARGET_ARCH_WIN32
#include "globus_io_win_io_operation.h"
#endif

struct globus_netlogger_handle_s;
typedef struct globus_netlogger_handle_s *  globus_netlogger_handle_t;

/**
 * @defgroup globus_io_activation Activation
 *
 * Globus I/O uses standard Globus module activation and deactivation.
 * Before any Globus I/O functions are called, the following function
 * must be called:
 *
 * @code
 *      globus_module_activate(GLOBUS_IO_MODULE)
 * @endcode
 *
 *
 * This function returns GLOBUS_SUCCESS if Globus I/O was successfully
 * initialized, and you are therefore allowed to subsequently call
 * Globus I/O functions.  Otherwise, an error code is returned, and
 * Globus I/O functions should not be subsequently called. This
 * function may be called multiple times.
 *
 * To deactivate Globus I/O, the following function must be called:
 *
 * @code
 *    globus_module_deactivate(GLOBUS_IO_MODULE)
 * @endcode
 *
 * This function should be called once for each time Globus I/O was activated.
 *
 * Before I/O is activated for the first time in a process, certain
 * environment variables can be set to modify some of the behavior of 
 * Globus I/O
 *
 *
 * @b GLOBUS_TCP_PORT_RANGE  @e min,max
 *
 * @b GLOBUS_UDP_PORT_RANGE @e min,max
 *
 * The variables min and max should both be unsigned shorts. They
 * specify the port range to be used for anonymous TCP and UDP port
 * bindings.
 *
 * @b GLOBUS_IO_POLL_FREQUENCY @e frequency
 *
 * The variable frequency indicates the amount of time between polling
 * file descriptors. This was known as the "nexus skip poll" in
 * previous Globus releases.
 *
 * @b GLOBUS_IO_DEBUG_LEVEL @e level
 *
 * The variable level indicates the amount of debugging output to be
 * generated.The value should be in the range 0..9. Larger values
 * indicate that more debugging output will be displayed.
 */
/** Module descriptor
 * @ingroup activation
 */
#define GLOBUS_IO_MODULE (&globus_i_io_module)

extern
globus_module_descriptor_t		globus_i_io_module;

/** Globus I/O Handle Types
 * @ingroup common
 */
typedef enum 
{
    /** TCP Server Handle */
    GLOBUS_IO_HANDLE_TYPE_TCP_LISTENER,
    /** TCP Connection Handle */
    GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED,
    /** Unix Domain Socket Server Handle -- unimplemented */
    GLOBUS_IO_HANDLE_TYPE_UDSS_LISTENER,
    /** Unix Domain Socket Connection Handle -- unimplemented */
    GLOBUS_IO_HANDLE_TYPE_UDSS_CONNECTED,
    /** Local File Handle */
    GLOBUS_IO_HANDLE_TYPE_FILE,
    /** UDP Datagram Socket */
    GLOBUS_IO_HANDLE_TYPE_UDP_UNCONNECTED,
    /** UDP Connected Datagram Socket */
    GLOBUS_IO_HANDLE_TYPE_UDP_CONNECTED,
    /** Unix Domain Datagram Socket */
    GLOBUS_IO_HANDLE_TYPE_UDDS_UNCONNECTED,
    /** Unix Domain Connected Datagram Socket */
    GLOBUS_IO_HANDLE_TYPE_UDDS_CONNECTED,
    /** For internal use only  */
    GLOBUS_IO_HANDLE_TYPE_INTERNAL
} globus_io_handle_type_t;


/**
 * Globus I/O extensible attribute structure.
 *
 * This structure implements the various attribute structure types
 * used in the Globus I/O API.
 * 
 * The attribute structure can be initialized by a call to
 * globus_io_tcpattr_init(), globus_io_udpattr_init(), or
 * globus_io_fileattr_init().
 * @ingroup attr
 */
typedef struct
{
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
    globus_object_t *			attr;

    /*
     * NETLOGGER
     */
    globus_netlogger_handle_t *         nl_handle;
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
} globus_io_attr_t;

typedef struct globus_io_handle_s globus_io_handle_t;

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
#include "globus_io_error_hierarchy.h"
#endif

/* Callback Types */
typedef void (*globus_io_callback_t)(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

/**
 * Signature of a callback to globus_io_register_read()
 * @ingroup read
 */
typedef void (*globus_io_read_callback_t)(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes);

/**
 * Signature of a callback to globus_io_register_recv()
 * @ingroup read
 */
typedef void (*globus_io_recv_callback_t)(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					flags);

/**
 * Signature of a callback to globus_io_register_write() and
 * globus_io_register_send().
 *
 * @param arg
 * The callback argument passed to the registration
 * function
 * @param handle
 * The handle that the I/O operation was done to.
 * @param result
 * The status of the asynchronous write. If the write
 * completed successfully, then this will be GLOBUS_SUCCESS,
 * otherwise it will be one of the error types described under
 * the globus_io_write() or globus_io_register_write().
 * @param buf
 * The buffer passed into the registration function.
 * @param nbytes
 * The amount of data sent before the I/O completed.
 * In the case where no errors occurred, this should equal
 * the value of nbytes passed to the registration function; otherwise
 * it will contain the amount of data sent before the error pointed
 * to by @b result occurred.
 *
 * @return void
 * @ingroup write
 */
typedef void (*globus_io_write_callback_t)(
    void *				arg, 
    globus_io_handle_t *		handle, 
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes);


/**
 * Signature of a callback to globus_io_register_writev()
 * @ingroup write
 */
typedef void (*globus_io_writev_callback_t)(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    struct iovec *			iov,
    globus_size_t			iovcnt,
    globus_size_t			nbytes);

/**
 * Signature of a Globus I/O authorization callback.
 *
 * This callback function is invoked once authentication is completed, 
 * to allow the user to implement arbitrary authorization operations,
 * based on the identity of the connection peer, and/or the state of the
 * context handle.
 *
 * The parameters to this function are
 *
 * @param arg
 * The callback argument set in the authorization attribute.
 * @param handle
 * The handle which the authorization check pertains to.
 * @param result
 * The result of the authentication operation.
 * @param identity
 * The identity of the handle's peer.
 * @param context_handle
 * The security context which has been established on this handle.
 *
 * @return
 * This function returns a boolean value indicating
 * whether the authorization processes succeeded or not.
 *
 * @retval GLOBUS_TRUE
 * The connection establishment is considered complete and a successful
 * result is returned to the connect or accept operation.
 * @retval GLOBUS_FALSE
 * The connection establishment is considered failed. The connection
 * is closed, and an authorization error is returned to the connect
 * or accept operation.
 *
 * @see globus_io_secure_authorization_data_set_callback()
 * @see globus_io_secure_authorization_data_get_callback()
 * @see globus_io_attr_set_secure_authorization_mode()
 *
 * @ingroup security
 */
typedef globus_bool_t (*globus_io_secure_authorization_callback_t)(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    char *				identity,
    gss_ctx_id_t 			context_handle);


/**
 * Signature of a Globus I/O delegation callback.
 *
 * This callback function is invoked once delegation is completed. 
 *
 * The parameters to this function are
 *
 * @param arg
 * The callback argument passed to the delegation function.
 * @param handle
 * The handle used in the delegation process.
 * @param result
 * The result of the authentication operation.
 * @param delegated_cred
 * The credential involved in the delegation.
 * @param time_rec
 * Parameter returning the actual time in seconds the received
 * credential is valid for. This parameter will be 0 if this callback
 * is a result of a call to init delegation.
 *
 * @return
 * This function returns GLOBUS_SUCCESS on success, or a
 * globus_result_t indicating the error that occured.
 *
 * @ingroup security
 */

typedef void (* globus_io_delegation_callback_t)(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    gss_cred_id_t                       delegated_cred,
    OM_uint32                           time_rec);


typedef void (*globus_io_udp_sendto_callback_t)(
    void *				arg, 
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes);

typedef void 
(*globus_io_udp_sendvto_callback_t)(
    void *                                  arg, 
    globus_io_handle_t *                    handle,
    globus_result_t			                result,
    struct iovec *                          iov,
    int                                     iovc);

typedef void (*globus_io_udp_recvfrom_callback_t)(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes_recvd,
    const char *				host,
    unsigned short			port);

typedef void
(*globus_io_udp_recvfromv_callback_t)(
    void *                                  arg,
    globus_io_handle_t *                    handle,
    globus_result_t			                result,
    struct iovec *                          iov,
    int                                     iovc,
    globus_size_t                           nbytes_recvd,
    const char *                            host,
    unsigned short                          port);

/* attribute support */
/** 
 * Authentication mode for sockets
 *
 * The authentication mode parameter is used to determine whether to
 * use the GSSAPI to authenticate the socket connection.
 * @see globus_io_attr_set_secure_authentication_mode()
 * @see globus_io_attr_get_secure_authentication_mode()
 *
 * @ingroup security
 */
typedef enum
{
    /** Don't do authentication */
    GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE = 0,
    /** Authenticate with the GSSAPI library using mutual
     *  authenitcation.
     */
    GLOBUS_IO_SECURE_AUTHENTICATION_MODE_GSSAPI = 1,
    GLOBUS_IO_SECURE_AUTHENTICATION_MODE_MUTUAL = 1,
    /** Authenticate without a client cert */
    GLOBUS_IO_SECURE_AUTHENTICATION_MODE_ANONYMOUS = 2
} globus_io_secure_authentication_mode_t;

/** 
 * Authorization mode for TCP sockets
 *
 * Authorization is the process by which Globus I/O determines whether 
 * to allow an authenticated entity to communicate over a secure
 * Globus I/O handle.
 * @ingroup security
 */
typedef enum
{
    /** No authorization (Only valid for non-authenticated sockets) */
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE = 0,
    /** 
     * Authorize any connection with the same credentials as the local
     * credentials used when creating this handle.
     */
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF,
    /**
     * Authorize any connection with the credentials matching the 
     * specified identity.
     *
     * The identity string should generated in a way which is
     * compatible with the GSSAPI that Globus I/O is linked with.
     */
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY,
    /**
     * Authorize any connect with credentials matching the 
     * host the connection is made with.
     *
     * The identity of the connection peer is expected to be a "host
     * credential". When using the GSI implementation, this is of the
     * form "/CN=host/fully.qualified.hostname". The actual name is
     * automatically generated based on the TCP address of the peer
     * and the GSSAPI implementation.
     */
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST,
    /**
     * Allow the user to make authorization decisions on a per-connection
     * basis.
     *
     * The decision function is of type
     * globus_io_secure_authorization_callback_t, and is set by the
     * globus_io_secure_authorization_data_set_callback() function.
     */
    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK
} globus_io_secure_authorization_mode_t;

/**
 * Authorization-mode specific data.
 *
 * This data structure is passed as an argument to
 * globus_io_attr_get_secure_authorization_mode()
 * and
 * globus_io_attr_set_secure_authorization_mode().
 *
 * This data structure should only be accessed through
 * these functions:
 * globus_io_secure_authorization_data_initialize(),
 * globus_io_secure_authorization_data_destroy(),
 * globus_io_secure_authorization_data_get_callback(),
 * globus_io_secure_authorization_data_set_callback(),
 * globus_io_secure_authorization_data_get_identity(),
 * globus_io_secure_authorization_data_set_identity()
 * @ingroup security
 */
typedef struct
{
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
    char *				identity;
    globus_io_secure_authorization_callback_t
					callback;
    void *				callback_arg;
#endif
} globus_io_secure_authorization_data_t;

/**
 *
 * Data channel mode.
 * @ingroup security
 *
 * This type defines the different data channel modes provided by
 * Globus I/O. Data protection can be applied to a Globus I/O handle
 * by setting the channel mode attribute to
 * #GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP
 * or #GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, and setting the data
 * protection mode.
 */
typedef enum
{
    /** 
     * No data protection can be applied to the connection.
     *
     * Once the connection is established, authenticated, and
     * authorized, no data protection is applied to data sent on the
     * connection by Globus I/O.
     */
    GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR = 0,
    /** 
     * Data protection is provided, with support for GSI features,
     * such as delegation.
     *
     * This channel mode uses the GSSAPI encoding of the data sent on
     * the socket. Additionally, the delegation_mode attribute is
     * honored, even when doing so would violate the SSL protocol.
     */
    GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP,
    /** 
     * Data protection is provided using strict SSL if applicable.
     *
     * If the GSSAPI implementation is capabable of writing SSL tokens,
     * then no extra message header will be sent on the channel. This implies
     * that delegation can not be done, since the SSL protocol does not
     * yet support it.
     *
     * This channel mode uses the GSSAPI encoding of the data sent on
     * the socket. However, when using then GSI implementation of the
     * GSSAPI, the delegation negotion is eliminated. This means that
     * sockets connected with this attribute will ignore the
     * delegation attribute, with the result that they will have no
     * extra messages inserted into the data stream.
     *
     * When any GSSAPI other than GSI is used with Globus I/O, this
     * channel mode is identical to
     * GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP. It is provided to
     * support interoperability between Globus I/O and other SSL
     * applications.
     */
    GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP
} globus_io_secure_channel_mode_t;

/**
 *
 * Data protection mode.
 * @ingroup security
 *
 * This type defines the different data protection modes provided by
 * Globus I/O. If a Globus I/O handle's channel mode attribute is set
 * to #GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP
 * or #GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP, then data protection
 * can be applied to the channel.
 */
typedef enum
{
    /** 
     * No data protection is applied to the connection.
     *
     * This is only valid if the channel mode is set to
     * #GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR
     */
    GLOBUS_IO_SECURE_PROTECTION_MODE_NONE = 0,
    /** 
     * Integrity-checked messages.
     *
     * When a handle's protection is set to this value, all data sent
     * or received on it will have a message integrity code associated
     * with it. This code will be checked when the message is received
     * to ensure that the message has not been tampered with.
     *
     * This is the default for wrapped channels.
     */
    GLOBUS_IO_SECURE_PROTECTION_MODE_SAFE,
    /** 
     * Encrypted messages.
     *
     * When a handle's protection is set to this value, all data sent
     * or received on it will have a message integrity code associated
     * with it and will also be encrypted. This message integrity code
     * will be checked when the message is received to ensure that the
     * message has not been tampered with.
     */
    GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE
} globus_io_secure_protection_mode_t;


/**
 * Security Delegation mode
 *
 * Delegation is the process by which Globus I/O transfers the
 * applications security credentials to a remote process.
 * Delegation can be enabled on a Globus I/O handle
 * by setting the delegation attribute to the appropriate
 * value. This is done by calling
 * globus_io_attr_set_secure_delegation_mode() function.
 *
 * @bug The GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP channel mode will
 * override the delegation mode attribute for the GSI implementation
 * of the GSSAPI.
 *
 * @ingroup security
 */
typedef enum
{
    /** 
     * Do not do delegation
     */
    GLOBUS_IO_SECURE_DELEGATION_MODE_NONE = 0,
    /** 
     * Delegate a limited proxy, suitable only for user-to-user 
     * authentication
     */
    GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY,
    /**
     * Delegate full credentials to the server. The server may do any 
     * security operation that the client can do, including delegate
     * to other servers
     */
    GLOBUS_IO_SECURE_DELEGATION_MODE_FULL_PROXY
} globus_io_secure_delegation_mode_t;


/**
 * Security Proxy mode
 *
 * The setting of this mode determines if and what kind of proxy
 * certificates will be accepted for authentication. The mode may be
 * changed by calling the globus_io_attr_set_secure_proxy_mode()
 * function. 
 *
 * @ingroup security
 */
typedef enum
{
    /** 
     * Accept a full or level 1 limited proxy, but not a level >=2
     * limited proxy.
     */
    GLOBUS_IO_SECURE_PROXY_MODE_NONE = 0,
    /** 
     * Do not accept any form of limited proxy. This would be used by
     * the gatekeeper and sshd. This behavior is unchanged from today.
     */
    GLOBUS_IO_SECURE_PROXY_MODE_LIMITED,
    /**
     * Accept any proxy, limited or otherwise, as valid authentication.
     */
    GLOBUS_IO_SECURE_PROXY_MODE_MANY
} globus_io_secure_proxy_mode_t;



/*
   Globus I/O Attribute Objects 
   GLOBUS_IO_OBJECT_TYPE_BASE
   - GLOBUS_IO_OBJECT_TYPE_BASE_ATTR
   - - GLOBUS_IO_OBJECT_TYPE_SOCKETATTR
   - - - GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR
   - - - - GLOBUS_IO_OBJECT_TYPE_TCPATTR
   - - - - GLOBUS_IO_OBJECT_TYPE_UDPATTR
   - - GLOBUS_IO_OBJECT_TYPE_FILEATTR
*/
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
extern const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_BASE_ATTR_DEFINITION;
#define GLOBUS_IO_OBJECT_TYPE_BASE_ATTR \
    (&GLOBUS_IO_OBJECT_TYPE_BASE_ATTR_DEFINITION)
    
extern const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_SOCKETATTR_DEFINITION;
#define GLOBUS_IO_OBJECT_TYPE_SOCKETATTR \
    (&GLOBUS_IO_OBJECT_TYPE_SOCKETATTR_DEFINITION)
    
extern const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR_DEFINITION;
#define GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR \
    (&GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR_DEFINITION)
    
extern const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_TCPATTR_DEFINITION;
#define GLOBUS_IO_OBJECT_TYPE_TCPATTR \
    (&GLOBUS_IO_OBJECT_TYPE_TCPATTR_DEFINITION)

extern const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_UDPATTR_DEFINITION;
#define GLOBUS_IO_OBJECT_TYPE_UDPATTR \
    (&GLOBUS_IO_OBJECT_TYPE_UDPATTR_DEFINITION)

extern const globus_object_type_t
GLOBUS_IO_OBJECT_TYPE_FILEATTR_DEFINITION;
#define GLOBUS_IO_OBJECT_TYPE_FILEATTR \
    (&GLOBUS_IO_OBJECT_TYPE_FILEATTR_DEFINITION)
#endif
    
/* Globus I/O Attributes Instance Data */
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
typedef struct
{
    globus_bool_t				reuseaddr;
    globus_bool_t				keepalive;
    globus_bool_t				linger;
    int						linger_time;
    globus_bool_t				oobinline;
    int						sndbuf;
    int						rcvbuf;
    
    globus_callback_space_t                     space;
    
} globus_i_io_socketattr_instance_t;
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
typedef struct
{
    globus_io_secure_authentication_mode_t	authentication_mode;
    globus_io_secure_authorization_mode_t	authorization_mode;
    globus_io_secure_channel_mode_t		channel_mode;
    globus_io_secure_protection_mode_t		protection_mode;
    globus_io_secure_delegation_mode_t		delegation_mode;
    globus_io_secure_proxy_mode_t		proxy_mode;
    gss_cred_id_t				credential;
    globus_bool_t				internal_credential;
    char *					authorized_identity;
    globus_io_secure_authorization_callback_t   auth_callback;
    void *					auth_callback_arg;
    gss_OID_set                                 extension_oids;
} globus_i_io_securesocketattr_instance_t;
#endif

/* File related typedefs */

/**
 * Flags to pass to the globus_io_file_open() call.
 * @ingroup file
 */
typedef enum
{
    /** Open file with create  */
    GLOBUS_IO_FILE_CREAT	= O_CREAT,
    /** Exclusive open */
    GLOBUS_IO_FILE_EXCL		= O_EXCL,
    /** Read-only open */
    GLOBUS_IO_FILE_RDONLY	= O_RDONLY,
    /** Write-only open */
    GLOBUS_IO_FILE_WRONLY	= O_WRONLY,
    /** Read-write open */
    GLOBUS_IO_FILE_RDWR		= O_RDWR,
    /** Open and truncate */
    GLOBUS_IO_FILE_TRUNC	= O_TRUNC,
    /** Open for append */
    GLOBUS_IO_FILE_APPEND	= O_APPEND
} globus_io_file_flag_t;

/** 
 * Open mode to pass to the globus_io_file_open() call.
 * The group permission settings are not available under Windows NT.
 *
 * @ingroup file
 */
typedef enum
{
#ifndef TARGET_ARCH_WIN32
    /** Read, write, execute: owner */
    GLOBUS_IO_FILE_IRWXU	= S_IRWXU,
    /** Read permission: owner */
    GLOBUS_IO_FILE_IRUSR	= S_IRUSR,
    /** Write permission: owner */
    GLOBUS_IO_FILE_IWUSR	= S_IWUSR,
    /** Execute permission: owner */
    GLOBUS_IO_FILE_IXUSR	= S_IXUSR,
    /** Read, write, execute: other users */
    GLOBUS_IO_FILE_IRWXO	= S_IRWXO,
    /** Read permission: other users */
    GLOBUS_IO_FILE_IROTH	= S_IROTH,
    /** Write permission: other users */
    GLOBUS_IO_FILE_IWOTH	= S_IWOTH,
    /** Execute permission: other users */
    GLOBUS_IO_FILE_IXOTH	= S_IXOTH,

#if !defined(TARGET_ARCH_CYGWIN)
    /** Read, write, execute: group members */
    GLOBUS_IO_FILE_IRWXG	= S_IRWXG,
    /** Read permission: group members */
    GLOBUS_IO_FILE_IRGRP	= S_IRGRP,
    /** Write permission: group members */
    GLOBUS_IO_FILE_IWGRP	= S_IWGRP,
    /** Execute permission: group members */
    GLOBUS_IO_FILE_IXGRP	= S_IXGRP
#endif /* TARGET_ARCH_CYGWIN */
#endif /* TARGET_ARCH_WIN32 */
} globus_io_file_create_mode_t;

/**
 * Type for the "whence" parameter of globus_io_file_seek().
 * This value is used to interpret the "offset" parameter of 
 * globus_io_file_seek().
 * @ingroup file
 */
typedef enum
{
    /**
     * Set the offset of the file handle relative to the beginning
     * of the file.
     */
    GLOBUS_IO_SEEK_SET = SEEK_SET,
    /**
     * Set the offset of the file handle relative to the current offset.
     */
    GLOBUS_IO_SEEK_CUR = SEEK_CUR,
    /**
     * Set the offset of the file handle relative to the end of
     * the file.
     */
    GLOBUS_IO_SEEK_END = SEEK_END
} globus_io_whence_t;

/**
 * Values for the Globus I/O file_type file attribute.
 * @ingroup file
 */
typedef enum
{
    /** Open the file as a text file. */
    GLOBUS_IO_FILE_TYPE_TEXT,
    /** Open the file as a binary file. */
    GLOBUS_IO_FILE_TYPE_BINARY
}
globus_io_file_type_t;

/**
 * Type of the offset to be used as a parameter to globus_io_file_seek().
 * @ingroup file
 */
typedef globus_off_t globus_io_off_t;

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
typedef struct
{
    globus_io_file_type_t			file_type;
}
globus_i_io_fileattr_instance_t;
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
typedef struct
{
    globus_bool_t				nodelay;
    globus_bool_t				restrict_port;
    unsigned char				interface_addr[16];
} globus_i_io_tcpattr_instance_t;
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
typedef struct
{
    globus_bool_t                               connected;
    globus_bool_t                               reuse;
    char                                        mc_loop;
    char                                        mc_ttl;
    globus_bool_t                               mc_enabled;
    char *                                      address;
    char *                                      interface_addr;
    globus_bool_t				restrict_port;
} globus_i_io_udpattr_instance_t;
#endif

typedef enum
{
    GLOBUS_IO_HANDLE_STATE_INVALID,
    GLOBUS_IO_HANDLE_STATE_CONNECTING,
    GLOBUS_IO_HANDLE_STATE_ACCEPTING,
    GLOBUS_IO_HANDLE_STATE_AUTHENTICATING,
    GLOBUS_IO_HANDLE_STATE_CONNECTED,
    GLOBUS_IO_HANDLE_STATE_LISTENING,
    GLOBUS_IO_HANDLE_STATE_CLOSING,
    GLOBUS_IO_HANDLE_STATE_UDP_BIND
} globus_io_handle_state_t;

/**
 * @struct globus_io_handle_t
 * A file or socket handle.
 *
 * Globus I/O uses the abstraction of a handle to act as a common data
 * type for multiple I/O media. Currently, Globus I/O provides
 * interfaces to the BSD socket library and the POSIX file I/O library
 * using handles instead of file descriptors or win32 file or HANDLE
 * objects.
 *
 * A handle is created by calling one of the following functions:
 * globus_io_file_open(), globus_io_tcp_create_listener(),
 * globus_io_tcp_accept(), globus_io_tcp_register_accept(),
 * globus_io_tcp_connect(), or globus_io_udp_bind().
 *
 * @link attr Attributes @endlink may be bound to a handle at creation
 * time. These provide an interface to socket options, file access
 * options, and security.
 */
struct globus_io_handle_s
{
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
    int						fd;
#ifdef TARGET_ARCH_WIN32
	HANDLE io_handle; /* to be used for both sockets and files */
	WinIoOperation winIoOperation_read;
	WinIoOperation winIoOperation_write;
	WinIoOperation winIoOperation_structure; // set up and tear down
#endif
    gss_ctx_id_t				context;
    gss_cred_id_t				delegated_credential;
    globus_size_t				max_wrap_length;

    /* attribute instance data for this handle */
    globus_i_io_socketattr_instance_t		socket_attr;
    globus_i_io_securesocketattr_instance_t	securesocket_attr;
    globus_i_io_tcpattr_instance_t		tcp_attr;
    globus_i_io_udpattr_instance_t		udp_attr;
    globus_i_io_fileattr_instance_t		file_attr;
    
    /* buffer for reading GSSAPI wrapped data */
    globus_fifo_t 				wrapped_buffers;
    globus_fifo_t 				unwrapped_buffers;
    
    globus_io_handle_type_t			type;

    /* some handle state information */
    globus_io_handle_state_t		        state;
    void *					user_pointer;
    
    /* blocking call indicators, necessary to deliver callbacks to correct
     * space durring blocking calls
     */
    globus_bool_t                               blocking_read;
    globus_bool_t                               blocking_write;
    globus_bool_t                               blocking_except;
    globus_bool_t                               blocking_cancel;
    
    struct globus_io_operation_info_s *         read_operation;
    struct globus_io_operation_info_s *         write_operation;
    struct globus_io_operation_info_s *         except_operation;
    
    /* 
     *  NETLOGGER
     */
    char *                                      nl_event_id;
    globus_netlogger_handle_t *                 nl_handle;
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
};

/* Core API Functions */
#ifndef DOXYGEN
globus_result_t
globus_io_register_cancel(
    globus_io_handle_t *		handle,
    globus_bool_t			perform_callbacks,
    globus_io_callback_t		cancel_callback,
    void *				cancel_arg);

globus_result_t
globus_io_cancel(
    globus_io_handle_t *		handle,
    globus_bool_t			perform_callbacks);

#ifndef TARGET_ARCH_WIN32
globus_result_t 
globus_io_register_select( 
    globus_io_handle_t *		handle, 
    globus_io_callback_t		read_callback_func, 
    void *				read_callback_arg,
    globus_io_callback_t		write_callback_func, 
    void *				write_callback_arg,
    globus_io_callback_t		except_callback_func, 
    void *				except_callback_arg);
#endif /* TARGET_ARCH_WIN32 */
#endif

/**
 * @defgroup common I/O Operations
 *
 * The API functions in this section deal with operations which are
 * independent of the type of handle being used. These operations
 * include handle close, asynchronous operation cancellation, and
 * handle state queries.
 */

#ifndef DOXYGEN
globus_result_t
globus_io_register_close(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback,
    void *				callback_arg);

globus_result_t
globus_io_close(
    globus_io_handle_t *		handle);

globus_io_handle_type_t
globus_io_get_handle_type(
    globus_io_handle_t *		handle);

globus_result_t
globus_io_handle_get_user_pointer(
    globus_io_handle_t *		handle,
    void **				user_pointer);

globus_result_t
globus_io_handle_set_user_pointer(
    globus_io_handle_t *		handle,
    void *				user_pointer);
/* Read API functions */
globus_result_t 
globus_io_register_read( 
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes, 
    globus_size_t			wait_for_nbytes, 
    globus_io_read_callback_t		callback,
    void *				callback_arg);

globus_result_t
globus_io_try_read(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t 			max_nbytes,
    globus_size_t *			nbytes_read);

globus_result_t
globus_io_read(
    globus_io_handle_t *		handle, 
    globus_byte_t *			buf, 
    globus_size_t			max_nbytes,
    globus_size_t			wait_for_nbytes,
    globus_size_t *			nbytes_read);

/* Write/Send API functions */
globus_result_t
globus_io_register_write(
    globus_io_handle_t *		handle, 
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    globus_io_write_callback_t		write_callback, 
    void *				callback_arg);

globus_result_t
globus_io_register_send(
    globus_io_handle_t *		handle, 
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					flags,
    globus_io_write_callback_t		write_callback, 
    void *				callback_arg);

globus_result_t
globus_io_register_writev(
    globus_io_handle_t *		handle, 
    struct iovec *			iov,
    globus_size_t			iovcnt,
    globus_io_writev_callback_t		writev_callback, 
    void *				callback_arg);

globus_result_t
globus_io_try_write(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    globus_size_t *			nbytes_written);

globus_result_t
globus_io_try_send(
    globus_io_handle_t *		handle, 
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					flags,
    globus_size_t *			nbytes_sent);

globus_result_t
globus_io_write(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    globus_size_t *			nbytes_written);

globus_result_t
globus_io_send(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			nbytes,
    int					flags,
    globus_size_t *			nbytes_sent);

globus_result_t
globus_io_writev(
    globus_io_handle_t *		handle,
    struct iovec *			iov,
    globus_size_t			iovcnt,
    globus_size_t *			bytes_written);

/* TCP API Functions */
globus_result_t
globus_io_tcp_register_connect(
    char *				host,
    unsigned short			port,
    globus_io_attr_t *			attr,
    globus_io_callback_t		callback,
    void *				callback_arg,
    globus_io_handle_t *		handle);

globus_result_t
globus_io_tcp_connect(
    char *				host,
    unsigned short			port,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle);

globus_result_t
globus_io_tcp_create_listener(
    unsigned short *			port,
    int					backlog,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle);


globus_result_t
globus_io_tcp_register_listen(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback,
    void *				callback_arg);

globus_result_t
globus_io_tcp_listen(
    globus_io_handle_t *		handle);

globus_result_t
globus_io_tcp_register_accept(
    globus_io_handle_t *		listener_handle,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		new_handle,
    globus_io_callback_t		callback,
    void *				callback_arg);

globus_result_t
globus_io_tcp_accept(
    globus_io_handle_t *		listener_handle,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle);

globus_result_t
globus_io_tcp_get_local_address(
    globus_io_handle_t *		handle,
    int *				host,
    unsigned short *			port);
    
globus_result_t
globus_io_tcp_get_remote_address(
    globus_io_handle_t *		handle,
    int *				host,
    unsigned short *			port);

globus_result_t
globus_io_tcp_get_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr);

globus_result_t
globus_io_tcp_set_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr);

globus_result_t
globus_io_tcp_get_security_context(
    globus_io_handle_t *		handle,
    gss_ctx_id_t *			context);

globus_result_t
globus_io_tcp_get_delegated_credential(
    globus_io_handle_t *		handle,
    gss_cred_id_t *			cred);

#ifndef TARGET_ARCH_WIN32
globus_result_t
globus_io_tcp_posix_convert(
    int					socket,
    globus_io_attr_t *			attributes,
    globus_io_handle_t *		handle);

globus_result_t
globus_io_tcp_posix_convert_listener(
    int					socket,
    globus_io_attr_t *			attributes,
    globus_io_handle_t *		handle);
#else
globus_result_t globus_io_tcp_windows_convert(
    SOCKET						socket,
    globus_io_attr_t *			attributes,
    globus_io_handle_t *		handle);
globus_result_t globus_io_tcp_windows_convert_listener(
    SOCKET						socket,
    globus_io_attr_t *			attributes,
    globus_io_handle_t *		handle);
#endif

/* attribute methods */
globus_result_t
globus_io_fileattr_init(
    globus_io_attr_t *			attr);

globus_result_t
globus_io_fileattr_destroy(
    globus_io_attr_t *			attr);

globus_result_t
globus_io_attr_set_file_type(
    globus_io_attr_t *			attr,
    globus_io_file_type_t		file_type);

globus_result_t
globus_io_attr_get_file_type(
    globus_io_attr_t *			attr,
    globus_io_file_type_t *		file_type);

globus_result_t
globus_io_attr_get_udp_restrict_port(
    globus_io_attr_t *                       attr,
    globus_bool_t *                          restrict_port);

globus_result_t
globus_io_attr_set_udp_restrict_port(
    globus_io_attr_t *                       attr,
    globus_bool_t                            restrict_port);


/* UDP API Functions */
globus_result_t
globus_io_udp_bind(
    unsigned short *                    port,
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle);

globus_result_t
globus_io_udp_connect(
    globus_io_handle_t *                handle,
    char *                              host,
    unsigned short                      port);

globus_result_t 
globus_io_udp_sendto(
     globus_io_handle_t *                handle,
     globus_byte_t *                     buf,
     int                                 flags,
     globus_size_t                       nbytes,
     char *                              host,
     unsigned short                      port,
     globus_size_t *                     bytes_sent);

globus_result_t
globus_io_udp_sendvto(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    int                                 iovc,
    int                                 flags,
    char *                              host,
    unsigned short                      port,
    globus_size_t *                     bytes_sent);

globus_result_t 
globus_io_udp_register_recvfrom(
     globus_io_handle_t *                handle,
     globus_byte_t *                     buf,
     globus_size_t                       nbytes,
     int                                 flags,
     globus_io_udp_recvfrom_callback_t   recvfrom_callback,
     void *                              callback_arg);

globus_result_t 
globus_io_udp_recvfrom(
     globus_io_handle_t *                handle,
     globus_byte_t *                     buf,
     int                                 flags,
     globus_size_t                       nbytes,
     char **                             host,
     unsigned short *                    port,
     globus_size_t *                     nbytes_received);

globus_result_t
globus_io_udp_register_sendto(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    int                                 flags,
    globus_size_t                       nbytes,
    char *                              host,
    unsigned short                      port,
    globus_io_udp_sendto_callback_t     send_cb,
    void *                              user_arg);

globus_result_t
globus_io_udp_register_sendvto(
    globus_io_handle_t *                handle,
    struct iovec *                      iov,
    int                                 iovc,
    int                                 flags,
    char *                              host,
    unsigned short                      port,
    globus_io_udp_sendvto_callback_t    sendv_cb,
    void *                              user_arg);

#define GLOBUSIO_UDP_WRITEV_ENABLED 1

globus_result_t
globus_io_udp_register_recvfromv(
    globus_io_handle_t *                handle,
    struct iovec *                      iovec,
    int                                 iovec_count,
    int                                 flags,
    globus_io_udp_recvfromv_callback_t  recvfromv_callback,
    void *                              callback_arg);

globus_result_t 
globus_io_udp_recvfromv(
    globus_io_handle_t *                handle,
    struct iovec *                      iovec,
    int                                 iovec_count,
    int                                 flags,
    char **                             host,
    unsigned short *                    port,
    globus_size_t *                     nbytes_received);

globus_result_t
globus_io_udpattr_init(
     globus_io_attr_t *                  attr);

globus_result_t
globus_io_udpattr_destroy(
    globus_io_attr_t *			attr);

globus_result_t
globus_io_attr_set_udp_multicast_loop(
    globus_io_attr_t * attr,
    globus_bool_t enable_loopback);

globus_result_t
globus_io_attr_get_udp_multicast_loop(
    globus_io_attr_t *  attr,
    globus_bool_t *     enable_loopback);

globus_result_t
globus_io_attr_set_udp_multicast_membership(
    globus_io_attr_t * attr,
    char * address,
    char * interface_addr);

globus_result_t
globus_io_attr_get_udp_multicast_membership(
    globus_io_attr_t * attr,
    char ** address,
    char ** interface_addr);

globus_result_t
globus_io_attr_set_udp_multicast_ttl(
    globus_io_attr_t * attr,
    globus_byte_t ttl);

globus_result_t
globus_io_attr_get_udp_multicast_ttl(
    globus_io_attr_t * attr,
    globus_byte_t * ttl);

globus_result_t
globus_io_attr_set_udp_multicast_interface(
    globus_io_attr_t * attr,
    char * interface_addr);

globus_result_t
globus_io_attr_get_udp_multicast_interface(
    globus_io_attr_t * attr,
    char ** interface_addr);

/* delegation functions */

globus_result_t
globus_io_register_init_delegation(
    globus_io_handle_t *                handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    globus_io_delegation_callback_t	callback,
    void *				callback_arg);

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
    globus_io_delegation_callback_t	callback,
    void *				callback_arg);

globus_result_t
globus_io_accept_delegation(
    globus_io_handle_t *                handle,
    gss_cred_id_t *                     delegated_cred,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec);


#endif


/**
 * @defgroup file Files
 *
 * The API functions in this section deal with the opening of
 * File handles, and the use of file handle attributes.
 */
#ifndef DOXYGEN
globus_result_t
globus_io_file_open(
    char *				path,
    int					flags,
    int					mode,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle);

globus_result_t
globus_io_file_seek(
    globus_io_handle_t *		handle,
    globus_io_off_t			offset,
    globus_io_whence_t			whence);

#ifndef TARGET_ARCH_WIN32
globus_result_t
globus_io_file_posix_convert(
    int fd,
    globus_io_attr_t * attr,
    globus_io_handle_t * handle);
#else
globus_result_t 
globus_io_file_windows_convert(
	HANDLE file_handle,
    globus_io_attr_t * attr,
    globus_io_handle_t * handle );
#endif /* TARGET_ARCH_WIN32 */
#endif

/**
 * @defgroup attr Attributes
 *
 * The API functions in this section deal with the setting and
 * querying of attribute values.
 */

globus_result_t 
globus_io_attr_set_callback_space( 
    globus_io_attr_t *                  attr, 
    globus_callback_space_t             space);

globus_result_t 
globus_io_attr_get_callback_space( 
    globus_io_attr_t *                  attr, 
    globus_callback_space_t *           space);

/*
 *  NETLOGGER STUFF
 */
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

/* NETLOGGER handle */

#ifndef DOXYGEN
globus_result_t
globus_io_tcpattr_init(
    globus_io_attr_t *			attr);

globus_result_t
globus_io_tcpattr_destroy(
    globus_io_attr_t *			attr);

globus_result_t
globus_io_attr_set_tcp_restrict_port(
    globus_io_attr_t *			attr,
    globus_bool_t			restrict_port);

globus_result_t
globus_io_attr_get_tcp_restrict_port(
    globus_io_attr_t *			attr,
    globus_bool_t *			restrict_port);

globus_result_t
globus_io_attr_set_socket_reuseaddr(
    globus_io_attr_t *			attr,
    globus_bool_t			reuseaddr);

globus_result_t
globus_io_attr_get_socket_reuseaddr(
    globus_io_attr_t *			attr,
    globus_bool_t *			reuseaddr);

globus_result_t
globus_io_attr_set_socket_keepalive(
    globus_io_attr_t *			attr,
    globus_bool_t			keepalive);

globus_result_t
globus_io_attr_get_socket_keepalive(
    globus_io_attr_t *			attr,
    globus_bool_t *			keepalive);

globus_result_t
globus_io_attr_set_socket_linger(
    globus_io_attr_t *			attr,
    globus_bool_t			linger,
    int					linger_time);

globus_result_t
globus_io_attr_get_socket_linger(
    globus_io_attr_t *			attr,
    globus_bool_t *			linger,
    int *				linger_time);

globus_result_t
globus_io_attr_set_socket_oobinline(
    globus_io_attr_t *			attr,
    globus_bool_t			oobinline);

globus_result_t
globus_io_attr_get_socket_oobinline(
    globus_io_attr_t *			attr,
    globus_bool_t *			oobinline);

globus_result_t
globus_io_attr_set_socket_sndbuf(
    globus_io_attr_t *			attr,
    int					sndbuf);


globus_result_t
globus_io_attr_get_socket_sndbuf(
    globus_io_attr_t *			attr,
    int *				sndbuf);

globus_result_t
globus_io_attr_set_socket_rcvbuf(
    globus_io_attr_t *			attr,
    int					rcvbuf);

globus_result_t
globus_io_attr_get_socket_rcvbuf(
    globus_io_attr_t *			attr,
    int *				rcvbuf);

globus_result_t
globus_io_attr_set_tcp_nodelay(
    globus_io_attr_t *			attr,
    globus_bool_t			nodelay);


globus_result_t
globus_io_attr_get_tcp_nodelay(
    globus_io_attr_t *			attr,
    globus_bool_t *			nodelay);

globus_result_t
globus_io_attr_set_tcp_interface(
    globus_io_attr_t * attr,
    const char * interface_addr);

globus_result_t
globus_io_attr_get_tcp_interface(
    globus_io_attr_t * attr,
    char ** interface_addr);

globus_result_t
globus_io_attr_set_secure_authentication_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_authentication_mode_t
					mode,
    gss_cred_id_t			credential);

globus_result_t
globus_io_attr_get_secure_authentication_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_authentication_mode_t *
					mode,
    gss_cred_id_t *			credential);

globus_result_t
globus_io_attr_set_secure_authorization_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_authorization_mode_t
					mode,
    globus_io_secure_authorization_data_t *
					data);

globus_result_t
globus_io_attr_get_secure_authorization_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_authorization_mode_t *
					mode,
    globus_io_secure_authorization_data_t *
					data);
globus_result_t
globus_io_attr_set_secure_extension_oids(
    globus_io_attr_t *			attr,
    gss_OID_set                         extension_oids);

globus_result_t
globus_io_attr_get_secure_extension_oids(
    globus_io_attr_t *			attr,
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
    char *				identity);

globus_result_t
globus_io_secure_authorization_data_get_identity(
    globus_io_secure_authorization_data_t *
					data,
    char **				identity);

globus_result_t
globus_io_secure_authorization_data_set_callback(
    globus_io_secure_authorization_data_t *
					data,
    globus_io_secure_authorization_callback_t
					callback,
    void *				callback_arg);

globus_result_t
globus_io_secure_authorization_data_get_callback(
    globus_io_secure_authorization_data_t *
					data,
    globus_io_secure_authorization_callback_t *
					callback,
    void **				callback_arg);

globus_result_t
globus_io_attr_set_secure_channel_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_channel_mode_t	mode);

globus_result_t
globus_io_attr_get_secure_channel_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_channel_mode_t *	mode);

globus_result_t
globus_io_attr_set_secure_protection_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_protection_mode_t	mode);

globus_result_t
globus_io_attr_get_secure_protection_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_protection_mode_t *mode);


globus_result_t
globus_io_attr_set_secure_delegation_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_delegation_mode_t	mode);

globus_result_t
globus_io_attr_get_secure_delegation_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_delegation_mode_t *
					mode);
globus_result_t
globus_io_attr_set_secure_proxy_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_proxy_mode_t	mode);

globus_result_t
globus_io_attr_get_secure_proxy_mode(
    globus_io_attr_t *			attr,
    globus_io_secure_proxy_mode_t *     mode);

globus_bool_t
globus_io_eof(
    globus_object_t *			eof);

#ifndef TARGET_ARCH_WIN32
globus_result_t
globus_io_set_close_on_exec(
    globus_io_handle_t *                handle,
    globus_bool_t                       value);
#endif

#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Deprecated function.
 *
 * @see globus_io_tcp_listen()
 * @ingroup tcp
 */
globus_result_t
globus_io_listen(
    globus_io_handle_t *		handle);

/**
 * Deprecated function.
 *
 * @see globus_io_tcp_register_listen()
 * @ingroup tcp
 */
globus_result_t
globus_io_register_listen(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback,
    void *				callback_arg);
#endif

/* new api just for gram_protocol_io */
globus_result_t
globus_io_tcp_set_credential(
    globus_io_handle_t *                handle,
    gss_cred_id_t                       credential);

globus_result_t
globus_io_tcp_get_credential(
    globus_io_handle_t *                handle,
    gss_cred_id_t *                     credential);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_IO_H */
