/**
 *  Globus Common Internal
 */
#if !defined(GLOBUS_COMMON_INTERNAL_H)

#include "config.h"
#include "globus_common_types.h"

/*
 *  include system files if we have them
 */
#ifdef HAVE_SYS_STAT_H
#   include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#   include <sys/types.h>
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
#ifdef HAVE_SYSY_PARAM_H
#   include <sys/param.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#   include <sys/socket.h>
#else
#   if defined(TARGET_ARCH_WIN32)
#       include <Winsock2.h>
#   endif
#endif

/*
 *  all windows specific includes
 */
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
 
EXTERN_C_BEGIN
EXTERN_C_END

#endif