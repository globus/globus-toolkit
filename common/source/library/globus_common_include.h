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

/** @file globus_common_include.h Include System Headers */
/**
 *  Defines the macros and typedefs common to all globus_common
 *  components.
 */
#if !defined(GLOBUS_COMMON_INCLUDE_H)
#define GLOBUS_COMMON_INCLUDE_H 1

#include "globus_config.h"

#if defined(_WIN32) && !defined(__CYGWIN__)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef __GNUC__
#define GlobusFuncName(func) static const char * _globus_func_name \
    __attribute__((__unused__)) = #func
#else
#define GlobusFuncName(func) static const char * _globus_func_name = #func
#endif

extern const char * _globus_func_name;

#define _GCSL(s) globus_common_i18n_get_string(GLOBUS_COMMON_MODULE,\
		               s)

/** GET IPv6 compatible types (at least with GNU) **/
#ifndef __USE_POSIX
#define __USE_POSIX
#endif

/*
 * Include system files if we have them
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/param.h>
#include <fcntl.h>

#if defined(_WIN32)
#   include <windows.h>
#   include <winsock2.h>
#   include <process.h>
#   include <io.h>
#   include <sys/timeb.h>
#   include <signal.h>
#   include <malloc.h>
#define setenv(var,val,ovw) (((ovw)||!getenv(var))?(putenv(globus_common_create_string("%s=%s",(var),(val)))):0
#define unsetenv(var) (putenv(globus_common_create_string("%s=",(var))))
#else
#   include <pwd.h>
#   include <netdb.h>
#   include <netinet/in.h>
#   include <sys/socket.h>
#   include <sys/uio.h>
#endif


#include <sys/time.h>
#include <time.h>

#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#include <dirent.h>
#include <fcntl.h>

#ifdef _WIN32
extern int inet_pton(int af, const char *src, void *dst);
#endif /* _WIN32 */

/******************************************************************************
				 Define macros
******************************************************************************/

/*
 * Various macro definitions for assertion checking
 */
#if 0
	void globus_dump_stack();
	#define GLOBUS_DUMP_STACK() globus_dump_stack() 
#else
	#define GLOBUS_DUMP_STACK()
#endif

#if defined(BUILD_DEBUG)
#   define globus_assert(assertion)					    \
    do {							            	    \
        if (!(assertion))						        \
        {								                \
            fprintf(stderr, "Assertion " #assertion 	\
		    " failed in file %s at line %d\n",			\
		    __FILE__, __LINE__);				        \
	    GLOBUS_DUMP_STACK();						    \
	    abort();                                        \
         }								                \
    } while(0)

#   define globus_assert_string(assertion, string)      \
    do {								                \
    	if (!(assertion))					      	    \
    	{								                \
    	    fprintf(stderr, "Assertion " #assertion		\
		    " failed in file %s at line %d: %s",    	\
		    __FILE__, __LINE__, string);			    \
	    GLOBUS_DUMP_STACK();						    \
	    abort();                                        \
    	}								                \
    } while(0)
#else /* BUILD_DEBUG */
#   define globus_assert(assertion)
#   define globus_assert_string(assertion, string)
#endif /* BUILD_DEBUG */

#define GLOBUS_MAX(V1,V2) (((V1) > (V2)) ? (V1) : (V2))
#define GLOBUS_MIN(V1,V2) (((V1) < (V2)) ? (V1) : (V2))

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

typedef size_t                                      globus_size_t;
typedef ssize_t                                     globus_ssize_t;

typedef socklen_t                                   globus_socklen_t;

#if defined(_WIN32)
/* The ordering of the fields must match those in WSABUF */
struct  iovec  
{
    unsigned long      iov_len;  /* Length in bytes.  */
    char *             iov_base;  /* Starting address.  */
};
#endif 

/* POSIX error code remapping */
#ifdef _WIN32
	#define EWOULDBLOCK EAGAIN
	#define ETIMEDOUT WSAETIMEDOUT
	#define EINPROGRESS WSAEINPROGRESS
#endif

#include <inttypes.h>

#if defined(_WIN32)
#    define vsnprintf _vsnprintf
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

typedef unsigned char	                                globus_byte_t;
/**
 * @brief Boolean type
 * @ingroup globus_common
 * @details
 * Set values to either the constant GLOBUS_TRUE and GLOBUS_FALSE
 */
typedef int		                                globus_bool_t;
/**
 * @ingroup globus_common
 * Weak pointer to a Globus Error object, or the special value GLOBUS_SUCCESS
 */
typedef uint32_t                                        globus_result_t;
typedef int64_t                                         globus_off_t;
#define GLOBUS_OFF_T_FORMAT                             PRId64

/**
 * @brief True value for globus_bool_t
 * @ingroup globus_common
 */
#define GLOBUS_TRUE    1
/**
 * @brief False value for globus_bool_t
 * @ingroup globus_common
 */
#define GLOBUS_FALSE   0
#define GLOBUS_NULL    0
#define GLOBUS_SUCCESS 0
#define GLOBUS_FAILURE  -1

#endif  /* GLOBUS_COMMON_INCLUDE_H */

