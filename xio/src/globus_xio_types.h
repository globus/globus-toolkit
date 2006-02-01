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

#if !defined(GLOBUS_XIO_TYPES_H)
#define GLOBUS_XIO_TYPES_H 1

#include "globus_common.h"

EXTERN_C_BEGIN

#define GLOBUS_XIO_QUERY ((globus_xio_driver_t) 0x01)

/*************************************************************************
 *    define types
 ************************************************************************/
typedef struct globus_i_xio_handle_s *          globus_xio_handle_t;
typedef struct globus_i_xio_context_entry_s *   globus_xio_driver_handle_t;
typedef struct globus_i_xio_op_s *              globus_xio_operation_t;
typedef struct globus_i_xio_driver_s *          globus_xio_driver_t;
typedef struct globus_i_xio_attr_s *            globus_xio_attr_t;
typedef struct globus_i_xio_stack_s *           globus_xio_stack_t;
typedef struct globus_i_xio_server_s *          globus_xio_server_t;
typedef struct globus_i_xio_server_s *          globus_xio_driver_server_t;
typedef struct globus_i_xio_op_s *              globus_xio_data_descriptor_t;

#ifdef WIN32
/* The ordering of the fields must match those in WSABUF */
typedef struct
{
    unsigned long                       iov_len;
    char *                              iov_base;
} globus_xio_iovec_t;
#else
typedef struct iovec                            globus_xio_iovec_t;
#endif

/**
 *  @ingroup GLOBUS_XIO_API
 *  Operation types
 *
 *  An enumeration of operation types.  Used in the timeout callback
 *  to indicate what operation typed timedout.
 */
typedef enum globus_i_xio_op_type_e
{
    GLOBUS_XIO_OPERATION_TYPE_NONE,
    GLOBUS_XIO_OPERATION_TYPE_FINISHED,
    GLOBUS_XIO_OPERATION_TYPE_OPEN,
    GLOBUS_XIO_OPERATION_TYPE_CLOSE,
    GLOBUS_XIO_OPERATION_TYPE_READ,
    GLOBUS_XIO_OPERATION_TYPE_WRITE,
    GLOBUS_XIO_OPERATION_TYPE_ACCEPT,
    GLOBUS_XIO_OPERATION_TYPE_DRIVER,
    GLOBUS_XIO_OPERATION_TYPE_DD,
    GLOBUS_XIO_OPERATION_TYPE_SERVER_INIT
} globus_xio_operation_type_t;

typedef enum globus_i_xio_signal_type_e
{
    GLOBUS_XIO_SIGNAL_TYPE_NONE
} globus_xio_signal_type_t;

typedef enum
{
    GLOBUS_XIO_ERROR_CANCELED,
    GLOBUS_XIO_ERROR_EOF,
    GLOBUS_XIO_ERROR_COMMAND,
    GLOBUS_XIO_ERROR_CONTACT_STRING,
    GLOBUS_XIO_ERROR_PARAMETER,
    GLOBUS_XIO_ERROR_MEMORY,
    GLOBUS_XIO_ERROR_SYSTEM_ERROR,
    GLOBUS_XIO_ERROR_SYSTEM_RESOURCE,
    GLOBUS_XIO_ERROR_STACK,
    GLOBUS_XIO_ERROR_DRIVER,
    GLOBUS_XIO_ERROR_PASS,
    GLOBUS_XIO_ERROR_ALREADY_REGISTERED,
    GLOBUS_XIO_ERROR_STATE,
    GLOBUS_XIO_ERROR_WRAPPED,
    GLOBUS_XIO_ERROR_NOT_REGISTERED,
    GLOBUS_XIO_ERROR_NOT_ACTIVATED,
    GLOBUS_XIO_ERROR_UNLOADED,
    GLOBUS_XIO_ERROR_TIMEOUT
} globus_xio_error_type_t;


/* ALL is all but ACCEPT */
typedef enum
{
    GLOBUS_XIO_ATTR_SET_TIMEOUT_ALL,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_OPEN,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_CLOSE,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_READ,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_WRITE,
    GLOBUS_XIO_ATTR_SET_TIMEOUT_ACCEPT,
    GLOBUS_XIO_ATTR_SET_SPACE,
    GLOBUS_XIO_ATTR_CLOSE_NO_CANCEL
} globus_xio_attr_cmd_t;

/** doxygen varargs filter stuff
 * GlobusVarArgDefine(
 *      handle, globus_result_t, globus_xio_handle_cntl, handle, driver)
 */

/**
 * Common driver handle cntls.
 * @ingroup GLOBUS_XIO_API
 * 
 */
typedef enum
{
    /* Make sure this enum starts at a high number */
    
    /**GlobusVarArgEnum(handle)
     * Get local connection info.
     * @ingroup GLOBUS_XIO_API
     * 
     * @param contact_string_out
     *      A pointer to a contact string for the local end of a connected
     *      handle.  Where possible, it will be in symbolic form (FQDN).
     * 
     *      The user must free the returned string.
     * 
     * @see globus_xio_server_get_contact_string()
     */
    /* char **                          contact_string_out */
    GLOBUS_XIO_GET_LOCAL_CONTACT = 12345,
    
    /**GlobusVarArgEnum(handle)
     * Get local connection info.
     * @ingroup GLOBUS_XIO_API
     * 
     * @param contact_string_out
     *      A pointer to a contact string for the local end of a connected
     *      handle.  Where possible, it will be in numeric form. (IP)
     * 
     *      The user must free the returned string.
     */
    /* char **                          contact_string_out */
    GLOBUS_XIO_GET_LOCAL_NUMERIC_CONTACT,
    
    /**GlobusVarArgEnum(handle)
     * Get remote connection info.
     * @ingroup GLOBUS_XIO_API
     * 
     * @param contact_string_out
     *      A pointer to a contact string for the remote end of a connected
     *      handle.  Where possible, it will be in symbolic form (FQDN).
     * 
     *      The user must free the returned string.
     */
    /* char **                          contact_string_out */
    GLOBUS_XIO_GET_REMOTE_CONTACT,
    
    /**GlobusVarArgEnum(handle)
     * Get remote connection info.
     * @ingroup GLOBUS_XIO_API
     * 
     * @param contact_string_out
     *      A pointer to a contact string for the remote end of a connected
     *      handle.  Where possible, it will be in numeric form. (IP)
     * 
     *      The user must free the returned string.
     */
    /* char **                          contact_string_out */
    GLOBUS_XIO_GET_REMOTE_NUMERIC_CONTACT,
    
    /** GlobusVarArgEnum(handle)
     * Reposition read/write offset.
     * @ingroup GLOBUS_XIO_API
     * 
     * @param offset
     *      Specify the desired offset.
     */
    /* globus_off_t                     offset */
    GLOBUS_XIO_SEEK
    
} globus_xio_handle_cmd_t;

typedef enum
{
    GLOBUS_XIO_DD_SET_OFFSET,
    GLOBUS_XIO_DD_GET_OFFSET
} globus_xio_dd_cmd_t;

typedef enum
{
    GLOBUS_XIO_CANCEL_OPEN = 0x01,
    GLOBUS_XIO_CANCEL_CLOSE = 0x02,
    GLOBUS_XIO_CANCEL_READ = 0x04,
    GLOBUS_XIO_CANCEL_WRITE = 0x08
} globus_xio_cancel_t;

typedef enum
{
    GLOBUS_XIO_DEBUG_ERROR = 1,
    GLOBUS_XIO_DEBUG_WARNING = 2,
    GLOBUS_XIO_DEBUG_TRACE = 4,
    GLOBUS_XIO_DEBUG_INTERNAL_TRACE = 8,
    GLOBUS_XIO_DEBUG_INFO = 16,
    GLOBUS_XIO_DEBUG_STATE = 32,
    GLOBUS_XIO_DEBUG_INFO_VERBOSE = 64
} globus_xio_debug_levels_t;

typedef struct
{
    char *                              unparsed;
    char *                              resource;
    char *                              host;
    char *                              port;
    char *                              scheme;
    char *                              user;
    char *                              pass;
    char *                              subject;
} globus_xio_contact_t;

EXTERN_C_END

#endif

