/**
 *  Defines the macros and typedefs common to all globus_common
 *  components.
 */
#if !defined(GLOBUS_COMMON_INCLUDE_H)
#define GLOBUS_COMMON_INCLUDE_H 1

#include "globus_config.h"

/*
 * configure macros
 */

/*
 * include system files if we have them
 */
#ifdef HAVE_SYS_STAT_H
#   include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#   include <sys/types.h>
#endif
#ifdef HAVE_IO_H
#   include <io.h>
#endif
#ifdef HAVE_SYS_SIGNAL_H
#   include <sys/signal.h>
#endif
#ifdef HAVE_UNISTD_H
#   include <unistd.h>
#endif
#ifdef HAVE_PWD_H
#   include <pwd.h>
#endif
#ifdef HAVE_NETDB_H
#   include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#   include <netinet/in.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#   include <sys/param.h>
#endif
#if HAVE_FCNTL_H
#   include <fcntl.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
#if HAVE_CTYPE_H
#   include <ctype.h>
#endif


#ifdef HAVE_SYS_SOCKET_H
#   include <sys/socket.h>
#endif

#if defined(TARGET_ARCH_WIN32)
#   include <Winsock2.h>
#   include <process.h>
#   include <io.h>
#endif

/*
 *  *  all windows specific includes
*   */
#ifdef TARGET_ARCH_WIN32
#   include <sys/timeb.h>
#   include <signal.h>
#endif

#include <stdarg.h>

#if defined(TIME_WITH_SYS_TIME)
#   include <sys/time.h>
#   include <time.h>
#else
#   if HAVE_SYS_TIME_H
#       include <sys/time.h>
#   else
#       include <time.h>
#   endif
#endif

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef HAVE_FCNTL_H
#   include <fcntl.h>
#endif

#if defined(HAVE_DIRENT_H)
#   include <dirent.h>
#   define NAMLEN(dirent) strlen((dirent)->d_name)
#else
#   define dirent direct
#   define NAMLEN(dirent) (dirent)->d_namlen
#   define HAVE_DIRENT_NAMELEN 1
#   if defined(HAVE_SYS_NDIR_H)
#       include <sys/ndir.h>
#   endif
#   if defined(HAVE_SYS_DIR_H)
#       include <sys/dir.h>
#   endif
#   if defined(HAVE_NDIR_H)
#       include <ndir.h>
#   endif
#endif

#if defined(HAVE_SYS_UIO_H)
#   include <sys/uio.h>
#endif

#include <limits.h>
#include <assert.h>

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif


/*
 *  common macros
 */
#define GLOBUS_TRUE	    1
#define GLOBUS_FALSE	0
#define GLOBUS_NULL  	0
#define GLOBUS_FAILURE  1
#define GLOBUS_SUCCESS  0

/******************************************************************************
				 Define macros
******************************************************************************/

/*
 * Various macro definitions for assertion checking
 */
#if defined(BUILD_DEBUG)
#   define globus_assert(assertion)					\
    do {								\
        if (!(assertion))						\
        {								\
            fprintf(stderr, "Assertion " #assertion			\
		    " failed in file %s at line %d\n",			\
		    __FILE__, __LINE__);				\
	    abort();							\
         }								\
    } while(0)

#   define globus_assert_string(assertion, string)			\
    do {								\
    	if (!(assertion))						\
    	{								\
    	    fprintf(stderr, "Assertion " #assertion			\
		    " failed in file %s at line %d: %s",		\
		    __FILE__, __LINE__, string);			\
	    abort();							\
    	}								\
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

#ifdef GLOBUS_USE_PTHREADS
#   define GLOBUS_THREAD_INCLUDE "globus_thread_pthreads.h"
#endif

#ifdef GLOBUS_USE_SOLARIS_THREADS
#   define GLOBUS_THREAD_INCLUDE "globus_thread_solaristhreads.h"
#endif

#ifdef GLOBUS_USE_EXTERNAL_THREADS
#   define GLOBUS_THREAD_INCLUDE "globus_thread_external.h"
#endif

#ifdef GLOBUS_USE_SPROC
#   define GLOBUS_THREAD_INCLUDE "globus_thread_sproc.h"
#endif

#ifdef GLOBUS_USE_NO_THREADS
#   define GLOBUS_THREAD_INCLUDE "globus_thread_none.h"
#endif

typedef unsigned char	                           globus_byte_t;
typedef int		                                   globus_bool_t;
typedef void *                                     globus_result_t;
typedef GLOBUS_OFF_T                               globus_off_t;

#if !defined(TARGET_ARCH_WIN32)
typedef size_t                                     globus_size_t;
#else
typedef long                                       globus_size_t;
#endif


#if !defined(HAVE_STRUCT_IOVEC)

struct  iovec  
{
   void *             iov_base;  /* Starting address.  */
   size_t             iov_len;  /* Length in bytes.  */
};

#endif 

#endif  /* GLOBUS_COMMON_INCLUDE_H */

