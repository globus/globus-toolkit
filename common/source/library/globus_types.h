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
 * @file globus_types.h
 * @brief Common Primitive Types
 *
 * Defines the macros and typedefs common to all globus_common components.
 */

#if !defined(GLOBUS_TYPES_H)
#define GLOBUS_TYPES_H 1

#include "globus_config.h"

#include <stdlib.h>
#include <stdint.h>

#if (!defined(_WIN32)) || (defined(__CYGWIN__) || defined(__MINGW32__))
#include <sys/types.h>
#endif

#if defined(_WIN32) && !defined(__CYGWIN__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

/** @brief Standard size of memory object
 * @ingroup globus_common
 * The globus_size_t is the size of a memory object. It is identical to
 * size_t in all cases and doesn't need to be used ever.
 */
typedef size_t                                      globus_size_t;

#if defined(_WIN32) && !defined(__CYGWIN__) && !defined(__MINGW32__)
/** @brief Type large enough to hold SIZE_MAX and -1.
 * @ingroup globus_common
 * The ssize_t type is a POSIX extension not in the C standard, so we define
 * it here
 */
typedef long                                        globus_ssize_t;
#else
typedef ssize_t                                     globus_ssize_t;
#endif

/** @brief Size of a socket length parameter
 * @ingroup globus_common
 * @details
 * The globus_socklen_t type is part of the POSIX socket interface and is also
 * available in winsock2.h. In older UNIX implementations, this was variously
 * a size_t or an int.
 */
typedef socklen_t                                   globus_socklen_t;

#if defined(_WIN32)
/* The ordering of the fields must match those in WSABUF */
struct  iovec  
{
    unsigned long      iov_len;  /* Length in bytes.  */
    char *             iov_base;  /* Starting address.  */
};
#endif 

/**
 * @brief Unsigned byte datatype
 * @ingroup globus_common
 * This is used for byte-addressable arrays of arbitrary data which is not
 * subject to sign extension.
 */
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
/**
 * @brief NULL value
 * @details
 * From back long ago before NULL was standardized? No reason to use this
 * on any modern system.
 */
#define GLOBUS_NULL    NULL
/**
 * @brief Generic success result
 * @ingroup globus_common
 * Most Globus API functions return this value to indicate success, or some
 * error constant or globus_result_t to indicate an error.
 */
#define GLOBUS_SUCCESS 0
/**
 * @brief Generic failure result
 * @ingroup globus_common
 * Some Globus API functions without good error handling return this value to
 * indicate some undetermined error occurred.
 */
#define GLOBUS_FAILURE  -1

#endif  /* GLOBUS_TYPES_H */
