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

/*
 * globus_l_io.h
 *
 * Description:
 * 
 * Globus I/O toolset internal definitions
 *
 * CVS Information:
 *
 * $Source$
 * $Date$
 * $Revision$
 * $State$
 * $Author$
 */


/*
 *		          Include header files
 */

#include "globus_common.h"
#ifndef TARGET_ARCH_WIN32
#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(HAVE_NETINET_TCP_H)
#   include <netinet/tcp.h>
#endif

#include <netdb.h>
#endif /* TARGET_ARCH_WIN32 */

#include <stdlib.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#if defined(HAVE_DCE_CMA_UX_H) && !defined(BUILD_LITE) && defined(HAVE_THREAD_SAFE_SELECT) && defined(TARGET_ARCH_AIX)
#include <dce/cma_ux.h>
#endif

#include "globus_io.h"

#ifdef TARGET_ARCH_WIN32
#define ssize_t long
#include "globus_i_io_windows.h"
#include "globus_i_io_winsock.h"
#endif /* TARGET_ARCH_WIN32 */

/*
 *  NETLOGGER
 */
/*
 *  If this is a Netlogger aware build, include the logging headers
 */
#if defined(GLOBUS_BUILD_WITH_NETLOGGER)
#include "NetLogger.h"
#else
typedef void NLhandle;
#endif

/*
 * Tru64 defines except when including pthreads with _OSF_SOURCE defined.
 * Nasty namespace pollution...
 */

#ifdef _OSF_SOURCE
#    undef except
#endif

#define GLOBUS_IO_NL_EVENT_START_READ     "GIO_READ_START"
#define GLOBUS_IO_NL_EVENT_END_READ       "GIO_READ_END"
#define GLOBUS_IO_NL_EVENT_START_WRITE    "GIO_WRITE_START"
#define GLOBUS_IO_NL_EVENT_END_WRITE      "GIO_WRITE_END"

struct globus_netlogger_handle_s
{   
    NLhandle *                            nl_handle;
    char *                                hostname;
    char *                                progname;
    char *                                gsid;
    char *                                pid;
    char *                                desc;

    char *                                main_str;
};

/*
 * provides a mechanism to turn netlogger on and off in a netlogger 
 * aware build.
 */
extern globus_bool_t                      g_globus_i_io_use_netlogger;

/*
 *			  Module specific prototypes
 */
#ifdef BUILD_LITE
#   ifndef HAVE_THREAD_SAFE_SELECT
#       define HAVE_THREAD_SAFE_SELECT
#   endif
#endif /* BUILD_LITE */

/* because of the warning messages */
#if  !defined(GLOBUS_SOCK_SIZE_T)
#    if  defined(TARGET_ARCH_AIX) 
#        define   GLOBUS_SOCK_SIZE_T  globus_size_t
#    else
#        define   GLOBUS_SOCK_SIZE_T  int
#    endif
#endif

#ifndef NEXUS_FD_SET_CAST
#ifdef TARGET_ARCH_HPUX
#define NEXUS_FD_SET_CAST (int *)
#else
#define NEXUS_FD_SET_CAST (fd_set *)
#endif
#endif

typedef enum
{
    GLOBUS_I_IO_READ_OPERATION = 1,
    GLOBUS_I_IO_WRITE_OPERATION = 2,
    GLOBUS_I_IO_EXCEPT_OPERATION = 4
} globus_i_io_operation_type_t;

extern globus_mutex_t			globus_i_io_mutex;
extern globus_cond_t			globus_l_io_cond;
extern int			        globus_i_io_mutex_cnt;
extern int			        globus_l_io_cond_cnt;

extern globus_bool_t *                  globus_i_io_tcp_used_port_table;
extern unsigned short                   globus_i_io_tcp_used_port_min;
extern unsigned short                   globus_i_io_tcp_used_port_max;
extern globus_bool_t *                  globus_i_io_udp_used_port_table;
extern unsigned short                   globus_i_io_udp_used_port_min;
extern unsigned short                   globus_i_io_udp_used_port_max;

extern int                              globus_i_io_skip_poll_frequency;

#   define globus_l_io_mutex_acquired() ((globus_i_io_mutex_cnt > 0)	\
				       ? GLOBUS_TRUE			\
				       : GLOBUS_FALSE)

#   define globus_i_io_mutex_lock()			\
    {							\
        globus_mutex_lock(&globus_i_io_mutex);		\
        globus_i_io_mutex_cnt++;			\
        globus_assert(globus_i_io_mutex_cnt==1);        \
    }


#   define globus_i_io_mutex_unlock()			\
    {							\
        globus_i_io_mutex_cnt--;			\
        globus_assert(globus_i_io_mutex_cnt==0);        \
        globus_mutex_unlock(&globus_i_io_mutex);	\
    }

#   define globus_l_io_cond_signal()			\
    {							\
	if (globus_i_io_cond_cnt > 0)			\
	{						\
	    globus_cond_signal(&globus_i_io_cond);	\
	}						\
    }

#   define globus_l_io_cond_broadcast()			\
    {							\
	if (globus_i_io_cond_cnt > 0)			\
	{						\
	    globus_cond_broadcast(&globus_i_io_cond);	\
	}						\
    }

#   define globus_l_io_cond_wait()				\
    {								\
        globus_i_io_mutex_cnt--;				\
        globus_i_io_cond_cnt++;					\
	globus_cond_wait(&globus_i_io_cond, &globus_i_io_mutex);	\
        globus_i_io_cond_cnt--;					\
        globus_i_io_mutex_cnt++;				\
    }

extern int globus_i_io_debug_level;

#ifdef BUILD_DEBUG
#define globus_i_io_debug(Level) (globus_i_io_debug_level >= (Level))
#endif

#ifdef BUILD_DEBUG
#define globus_i_io_debug_printf(level, message) \
do { \
    if (globus_i_io_debug(level)) \
    { \
	globus_libc_fprintf message; \
    } \
} while (0)
#else
#define globus_i_io_debug_printf(level, message)
#endif

typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_object_t *			err;
    globus_bool_t			use_err;
    globus_bool_t		        done;
    globus_size_t			nbytes;
    void *                              data;
} globus_i_io_monitor_t;

typedef void (*globus_io_destructor_t)(void *arg);

globus_bool_t
globus_i_common_get_env_pair(
    char * env_name,
    int * min,
    int * max);

globus_result_t
globus_i_io_copy_fileattr_to_handle(
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle);

void
globus_i_io_securesocket_copy_attr(
    globus_i_io_securesocketattr_instance_t *
					dst,
    globus_i_io_securesocketattr_instance_t *
					src);

void
globus_i_io_socket_copy_attr(
    globus_i_io_socketattr_instance_t *	dst,
    globus_i_io_socketattr_instance_t *	src);

void
globus_i_io_tcp_copy_attr(
    globus_i_io_tcpattr_instance_t *	dst,
    globus_i_io_tcpattr_instance_t *	src);

void
globus_i_io_udp_copy_attr(
    globus_i_io_udpattr_instance_t *	dst,
    globus_i_io_udpattr_instance_t *	src);

globus_result_t
globus_i_io_copy_udpattr_to_handle(
    globus_io_attr_t *                  attr,
    globus_io_handle_t *                handle);

/* internal functions defined in globus_io_core.c */
globus_result_t
globus_i_io_close(
    globus_io_handle_t *		handle);

globus_result_t
globus_i_io_setup_nonblocking(
    globus_io_handle_t *		handle);

globus_result_t
globus_i_io_start_operation(
    globus_io_handle_t *                handle,
    globus_i_io_operation_type_t        ops);

void
globus_i_io_end_operation(
    globus_io_handle_t *                handle,
    globus_i_io_operation_type_t        op);

globus_result_t
globus_i_io_register_operation(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback_func,
    void *                              callback_arg,
    globus_io_destructor_t              arg_destructor,
    globus_bool_t                       needs_select,
    globus_i_io_operation_type_t        op);

globus_result_t
globus_i_io_unregister_operation(
    globus_io_handle_t *                handle,
    globus_bool_t                       call_destructor,
    globus_i_io_operation_type_t        op);

globus_result_t
globus_i_io_register_quick_operation(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback_func,
    void *                              callback_arg,
    globus_io_destructor_t              arg_destructor,
    globus_bool_t                       needs_select,
    globus_i_io_operation_type_t        op);

/* internal functions defined in globus_io_read.c */
globus_result_t
globus_i_io_register_read(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    globus_size_t			wait_for_nbytes,
    globus_io_read_callback_t		callback,
    void *				callback_arg);

/* internal functions defined in globus_io_common.c */
void
globus_i_io_monitor_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

void
globus_i_io_securesocket_register_connect_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

globus_result_t
globus_i_io_securesocket_register_accept(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback_func,
    void *				callback_arg);

globus_result_t
globus_i_io_setup_securesocket(
    globus_io_handle_t *		handle);

globus_result_t
globus_i_io_setup_socket(
    globus_io_handle_t *		handle);

globus_result_t
globus_i_io_copy_securesocketattr_to_handle(
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle);

globus_result_t
globus_i_io_copy_socketattr_to_handle(
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle);

globus_result_t
globus_i_io_copy_tcpattr_to_handle(
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle);

globus_result_t
globus_i_io_securesocket_get_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr);

globus_result_t
globus_i_io_socket_get_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr);
    
globus_result_t
globus_i_io_securesocket_set_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr);

globus_result_t
globus_i_io_socket_set_attr(
    globus_io_handle_t *		handle,
    globus_io_attr_t *			attr);

void
globus_i_io_get_callback_space(
    globus_io_handle_t *		handle,
    globus_callback_space_t *           space);

void
globus_i_io_set_callback_space(
    globus_io_handle_t *		handle,
    globus_callback_space_t             space);

typedef struct
{
    globus_io_handle_t *		handle;
    globus_io_callback_t		callback;
    void *				callback_arg;
    globus_object_t *			err;
} globus_i_io_callback_info_t;

void
globus_i_io_attr_activate(void);

void
globus_i_io_handle_destroy(
    globus_io_handle_t *		handle);

globus_result_t
globus_i_io_try_write(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t *                     nbytes_written);

globus_result_t
globus_i_io_try_read(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			max_nbytes,
    globus_size_t *			nbytes_read);

/* Attribute constructors and initializers */
globus_object_t *
globus_i_io_fileattr_construct(void);

globus_result_t
globus_i_io_fileattr_initialize(
    globus_object_t *				obj);

globus_object_t *
globus_i_io_tcpattr_construct(void);

globus_object_t *
globus_i_io_udpattr_construct(void);

globus_result_t
globus_i_io_tcpattr_initialize(
    globus_object_t *				obj);

globus_result_t
globus_i_io_udpattr_initialize(
    globus_object_t *				obj);

globus_result_t
globus_i_io_securesocketattr_initialize(
    globus_object_t *				obj);

globus_result_t
globus_i_io_socketattr_initialize(
    globus_object_t *				obj);

globus_result_t
globus_i_io_attr_initialize(
    globus_object_t *				obj);

globus_result_t
globus_i_io_securesocket_wrap_buffer(
    globus_io_handle_t *		handle,
    globus_byte_t *			buf,
    globus_size_t			buf_size,
    struct iovec **			iov,
    globus_size_t *			iovcnt);

globus_result_t
globus_i_io_securesocket_wrap_iov(
    globus_io_handle_t *		handle,
    struct iovec *			iov,
    globus_size_t			iovcnt,
    struct iovec **			new_iov,
    globus_size_t *			new_iovcnt);

globus_result_t
globus_i_io_securesocket_register_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t                       wait_for_nbytes,
    globus_io_read_callback_t           callback,
    void *                              callback_arg);

void
globus_i_io_default_destructor(
    void *				arg);

void
globus_i_io_connect_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

void
globus_i_io_accept_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

void
globus_i_io_register_cancel(
    globus_io_handle_t *                handle,
    globus_bool_t                       perform_callbacks,
    globus_io_callback_t                cancel_callback,
    void *                              cancel_arg,
    globus_io_destructor_t 		cancel_destructor);

char *
globus_i_io_error_string_func ( globus_object_t * error );

globus_result_t
globus_i_io_initialize_handle(
    globus_io_handle_t *                handle,
    globus_io_handle_type_t		type);
