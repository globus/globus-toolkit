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

#if !defined GLOBUS_XIO_DRIVER_BIDI_H
#define GLOBUS_XIO_DRIVER_BIDI_H 1


/**
 * @file
 * Header file for XIO Bidirectional Driver
 */

#include "globus_xio_system.h"
#include "globus_common.h"

/**
 * @defgroup bidi_driver Globus XIO Bidirectional Driver
 */

/**
 * @defgroup bidi_driver_instance Opening/Closing
 * @ingroup bidi_driver
 *
 * An XIO handle with the bidi driver can be created with either
 * @ref globus_xio_handle_create() or @ref globus_xio_server_register_accept().
 *
 * If the handle is created with @ref globus_xio_handle_create(), the contact
 * string passed to ref globus_xio_register_open() call must contain
 * a host name and service/port. The number of streams required can be 
 * specified on the attr using @ref GLOBUS_XIO_BIDI_SET_NUM_STREAMS (default
 * is one stream). The stack of drivers to be used on the streams can be
 * specified on the attr using @ref GLOBUS_XIO_BIDI_SET_STACK (default is
 * a stack containing TCP driver). 
 *
 * When the XIO handle is closed, the bidi driver will destroy its internal
 * resources and close the stream(s).
 */

/**
 * @defgroup bidi_driver_io Reading/Writing
 * @ingroup bidi_driver
 * Mode E is unidirectional. Clients can only write and the server can only 
 * read.
 * The @ref globus_xio_register_read() enforce that the waitforbytes parameter
 * should be one. When multiple transport streams are used between the client 
 * and the server, data might not be delivered in order.
 * @ref globus_xio_data_descriptor_cntl() can be used to get the offset of the
 * data.
 *
 * @ref globus_xio_register_write() does not enforce any restriction on the
 * waitforbytes parameter.
 *
 * In any case, when an error or EOF occurs before the waitforbytes request
 * has been met, the outgoing nbytes is set to the amount of data actually
 * read/written before the error or EOF occurred.
 */

/**
 * @defgroup bidi_driver_server Server
 * @ingroup bidi_driver
 *
 * @ref globus_xio_server_create() causes a bidi listener to be created
 * and listened upon.  @ref globus_xio_server_register_accept() performs an
 * asynchronous accept(). @ref globus_xio_server_register_close() cleans up
 * the internal resources associated with the bidi server.
 *
 * All accepted handles inherit all bidi specific attributes set in the attr 
 * to @ref globus_xio_server_create()
 */

/**
 * @defgroup bidi_driver_envs Env Variables
 * @ingroup bidi_driver
 *
 * - GLOBUS_XIO_BIDI_DEBUG Available if using a debug build.  See 
 * globus_debug.h for format.  
 */

/**
 * @defgroup bidi_driver_cntls Attributes and Cntls
 * @ingroup bidi_driver
 *
 * Mode_e driver specific attrs and cntls.
 *
 * @see globus_xio_attr_cntl()
 * @see globus_xio_handle_cntl()
 * @see globus_xio_server_cntl()
 * @see globus_xio_data_descriptor_cntl()
 */
/**
 * @defgroup bidi_driver_types Types
 * @ingroup bidi_driver
 */
/**
 * @defgroup bidi_driver_errors Error Types
 * @ingroup bidi_driver
 *
 * The errors reported by BIDI driver include
 * GLOBUS_XIO_ERROR_COMMAND, GLOBUS_XIO_ERROR_MEMORY, GLOBUS_XIO_ERROR_STATE, 
 * GLOBUS_XIO_ERROR_PARAMETER, GLOBUS_XIO_ERROR_EOF, 
 * GLOBUS_XIO_ERROR_CANCELED, @ref GLOBUS_XIO_BIDI_HEADER_ERROR
 * 
 * @see globus_xio_driver_error_match()
 * @see globus_error_errno_match()
 */

/**
 * BIDI driver specific error types
 * @ingroup bidi_driver_errors
 */
typedef enum
{   
    /**
     * Indicates that the bidi header is erroneous
     */
    GLOBUS_XIO_BIDI_HEADER_ERROR
    
} globus_xio_bidi_error_type_t;


/** doxygen varargs filter stuff
 * GlobusVarArgDefine(
 *      attr, globus_result_t, globus_xio_attr_cntl, attr, driver)
 * GlobusVarArgDefine(
 *      handle, globus_result_t, globus_xio_handle_cntl, handle, driver)
 * GlobusVarArgDefine(
 *      dd, globus_result_t, globus_xio_data_descriptor_cntl, dd, driver)
 */

/**
 * BIDI driver specific cntls
 * @ingroup bidi_driver_cntls
 */

typedef enum
{
    /** GlobusVarArgEnum(attr)
     * Set the port to be used for the default bootstrap connection.
     * @ingroup bidi_driver_cntls
     *
     * @param port number
     *     Specifies the port number to use for the server-side bootstrap
     *     (control) connection.  Does not influence the read or write stacks.
     *     If you have substituted a non-default bootstrap stack, you will 
     *     have to use GLOBUS_XIO_BIDI_APPLT_ATTR_CNTLS on an appropriate
     *     xio_attr for that stack to set the port instead of using this
     *     attr cntl.
     */
    GLOBUS_XIO_BIDI_SET_PORT,

    /** GlobusVarArgEnum(attr)
     * Set the stack (of xio drivers) to be used for the read/write/bootstrap
     * connection(s).
     * @ingroup bidi_driver_cntls
     * Do not create a new ftp client handle, use this handle instead.
     * 
     * @param stack
     *      Specifies the stack to use for the connection(s).
     *      Note: this stack will not be destroyed.
     */
    GLOBUS_XIO_BIDI_SET_READ_STACK,
    GLOBUS_XIO_BIDI_SET_WRITE_STACK,
    GLOBUS_XIO_BIDI_SET_BOOTSTRAP_STACK,
    /** GlobusVarArgEnum(attr)
     * Get the stack on the attr.
     * @ingroup bidi_driver_cntls
     * 
     * @param stack_out
     *      The stack will be stored here. If none is set, GLOBUS_NULL will be 
     *      set.
     */
    GLOBUS_XIO_BIDI_GET_READ_STACK,
    GLOBUS_XIO_BIDI_GET_WRITE_STACK,
    GLOBUS_XIO_BIDI_GET_BOOTSTRAP_STACK,

    /** GlobusVarArgEnum(attr)
     * Get the attr to be used for the read/write/bootstrap connection(s).
     * @ingroup bidi_driver_cntls
     * 
     * @param attr_out 
     *      The attr specified will be stored here.  Will be GLOBUS_NULL if 
     *      none is set.
     */
    GLOBUS_XIO_BIDI_GET_READ_ATTR,
    GLOBUS_XIO_BIDI_GET_WRITE_ATTR,
    GLOBUS_XIO_BIDI_GET_BOOTSTRAP_ATTR,

    /** GlobusVarArgEnum(attr)
     * Set the attr to be used for the read/write/bootstrap connection(s).
     * @ingroup bidi_driver_cntls
     * 
     * @param attr 
     *      Specifies the attr to use for the appropriate connection.
     *      If setting attrs for a non-default bootstrap connection, 
     *      GLOBUS_XIO_SET_PORT will not have an effect.
     *
     */
    GLOBUS_XIO_BIDI_SET_READ_ATTR,
    GLOBUS_XIO_BIDI_SET_WRITE_ATTR,
    GLOBUS_XIO_BIDI_SET_BOOTSTRAP_ATTR,
    /** GlobusVarArgEnum(attr)
     * Set the attr cntl function that should be called before creating a new
     * connection with the stack specified. If any driver specific cntls is 
     * needed on the stack, this function should take care of applying all 
     * those cntls on the xio_attr passed to it.
     * @see globus_xio_bidi_attr_cntl_callback_t
     * @ingroup bidi_driver_cntls
     *
     * @param attr_cntl_cb
     *      Specifies the function pointer.
     */
    GLOBUS_XIO_BIDI_APPLY_READ_ATTR_CNTLS,
    GLOBUS_XIO_BIDI_APPLY_WRITE_ATTR_CNTLS,
    GLOBUS_XIO_BIDI_APPLY_BOOTSTRAP_ATTR_CNTLS,

    
    /** GlobusVarArgEnum(attr)
     * Set the maximum number of outbound streams to be used for the write
     * handle.  (By definition of the mode E protocol, the read handle must
     * accept any number of connections made to it).  
     * @ingroup bidi_driver_cntls
     *
     * @param number of streams 
     *     Sets the maximum number of write streams.
     *     If you have substituted a non-default write stack, behavior of 
     *     this attr cntl should be a no-op.
     */
    GLOBUS_XIO_BIDI_SET_MAX_WRITE_STREAMS,

    /** GlobusVarArgEnum(attr)
     * Set the tcp buffer size for the read or write stack.
     * @ingroup bidi_driver_cntls
     *
     * @param buffer size
     *     Sets the tcp buffer size for the read or write stack.
     *     If you have substituted a non-default read write stack that 
     *     does not include the mode_e driver, behavior of 
     *     this attr cntl should be a no-op.
     */
    GLOBUS_XIO_BIDI_SET_SNDBUF,
    GLOBUS_XIO_BIDI_SET_RCVBUF,

    
    /** GlobusVarArgEnum(attr)
     * Set the behavior of the bidirectional driver with regard to 
     * parallel writes.  By default, or if this attr is set with a value of 
     * GLOBUS_TRUE, the bidirectional driver will split all writes across
     * available parallel streams.  This ensures parallelism on writes while
     * being a drop-in replacement for the xio tcp driver, but may not 
     * achieve optimal performance in certain situations.  Setting this attr
     * with a value of GLOBUS_FALSE will turn of this "pulsing" write, which
     * then requires the application using the driver to be modified to 
     * post multiple simultaneous writes in order to achieve parallelism.  The
     * advantage of this approach is that the application can then be tweaked 
     * for write performance.
     * @ingroup bidi_driver_cntls
     *
     * @param true or false
     *     Sets behavior of driver with regard to parallel writes.  By default
     *     or when set to GLOBUS_TRUE, the driver will accept a single 
     *     outstanding registered write at a time, and will split that data 
     *     across available parallel streams.  When set to GLOBUS_FALSE, the 
     *     driver will adopt the default mode_e driver behavior, where 
     *     parallelism is achieved only by registering multiple outstanding 
     *     writes.
     */
    GLOBUS_XIO_BIDI_SET_PULSING

} globus_xio_bidi_cmd_t;	

#endif

/**
 * BIDI driver specific types
 * @ingroup bidi_driver_types
 * @hideinitializer
 */
typedef globus_result_t
(*globus_xio_bidi_attr_cntl_callback_t)(
    globus_xio_attr_t                   attr);
