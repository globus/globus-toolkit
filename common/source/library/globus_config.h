/*
 * Copyright 1999-2013 University of Chicago
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

/** @file globus_config.h */
#include <stdint.h>
#include <limits.h>

#if !defined(GLOBUS_CONFIG_H)
#define GLOBUS_CONFIG_H 1
#define BUILD_DEBUG 1

#ifdef __STDC__
#ifndef HAVE_STDARG_H
#define HAVE_STDARG_H
#endif
#endif

#ifdef _WIN32
#define TARGET_ARCH_WIN32 1
#define WINVER 0x0502
#endif

#ifdef __MINGW32__
#ifndef HAVE_IN6_IS_ADDR_UNSPECIFIED 
#define HAVE_IN6_IS_ADDR_UNSPECIFIED 1
#endif
#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif
#ifndef _POSIX
#define _POSIX 1
#endif
#define TARGET_ARCH_MINGW32
#endif

#ifdef __HOS_AIX__
#define TARGET_ARCH_AIX 1
#endif

#ifdef __FreeBSD__
#define TARGET_ARCH_FREEBSD 1
#define TARGET_ARCH_BSD 1
#endif

#ifdef __CYGWIN__
#define TARGET_ARCH_CYGWIN
#endif

#ifdef __APPLE__
#define TARGET_ARCH_DARWIN 1
#define TARGET_ARCH_BSD 1
#endif

#ifdef sun
#define TARGET_ARCH_SOLARIS 1
#ifdef __i386
#define TARGET_ARCH_X86 1
#endif
#ifdef __x86_64
#define TARGET_ARCH_X86_64 1
#endif
#endif

#ifdef __hpux
#define TARGET_ARCH_HPUX a
#ifdef __ia64
#define TARGET_ARCH_IA64 1
#endif
#endif

#ifdef __GNUC__
#define GLOBUS_FLAVOR_PREFIX "gcc"
#else
#define GLOBUS_FLAVOR_PREFIX "cc"
#endif

#if LONG_MAX >= INT64_MAX
#define GLOBUS_FLAVOR_SUFFIX "64"
#else
#define GLOBUS_FLAVOR_SUFFIX "32"
#endif

#define GLOBUS_FLAVOR_NAME GLOBUS_FLAVOR_PREFIX GLOBUS_FLAVOR_SUFFIX

#endif /* GLOBUS_CONFIG_H */
