#ifndef GLOBUS_XIO_MODE_E_DRIVER_INCLUDE
#define GLOBUS_XIO_MODE_E_DRIVER_INCLUDE

/**
 * @file
 * Header file for XIO MODE_E Driver
 */

#include "globus_xio_system.h"
#include "globus_common.h"

/**
 * @defgroup mode_e_driver Globus XIO MODE_E Driver
 */

/**
 * @defgroup mode_e_driver_instance Opening/Closing
 * @ingroup mode_e_driver
 *
 * An XIO handle with the mode_e driver can be created with either
 * @ref globus_xio_handle_create() or @ref globus_xio_server_register_accept().
 *
 * If the handle is created with @ref globus_xio_handle_create(), the contact
 * string passed to ref globus_xio_register_open() call must contain
 * a host name and service/port. The number of streams required can be 
 * specified on the attr using @ref GLOBUS_XIO_MODE_E_SET_NUM_STREAMS (default
 * is one stream). The stack of drivers to be used on the streams can be
 * specified on the attr using @ref GLOBUS_XIO_MODE_E_SET_STACK (default is
 * a stack containing TCP driver). 
 *
 * When the XIO handle is closed, the mode_e driver will destroy its internal
 * resources and close the stream(s).
 */

/**
 * @defgroup mode_e_driver_io Reading/Writing
 * @ingroup mode_e_driver
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
 * @defgroup mode_e_driver_server Server
 * @ingroup mode_e_driver
 *
 * @ref globus_xio_server_create() causes a mode_e listener to be created
 * and listened upon.  @ref globus_xio_server_register_accept() performs an
 * asynchronous accept(). @ref globus_xio_server_register_close() cleans up
 * the internal resources associated with the mode_e server.
 *
 * All accepted handles inherit all mode_e specific attributes set in the attr 
 * to @ref globus_xio_server_create()
 */

/**
 * @defgroup mode_e_driver_envs Env Variables
 * @ingroup mode_e_driver
 *
 * - GLOBUS_XIO_MODE_E_DEBUG Available if using a debug build.  See 
 * globus_debug.h for format.  
 */

/**
 * @defgroup mode_e_driver_cntls Attributes and Cntls
 * @ingroup mode_e_driver
 *
 * Mode_e driver specific attrs and cntls.
 *
 * @see globus_xio_attr_cntl()
 * @see globus_xio_handle_cntl()
 * @see globus_xio_server_cntl()
 * @see globus_xio_data_descriptor_cntl()
 */
/**
 * @defgroup mode_e_driver_types Types
 * @ingroup mode_e_driver
 */
/**
 * @defgroup mode_e_driver_errors Error Types
 * @ingroup mode_e_driver
 *
 * The errors reported by MODE_E driver include
 * are GLOBUS_XIO_ERROR_EOF, @ref GLOBUS_XIO_MODE_E_OPEN_ERROR, 
 * @ref GLOBUS_XIO_MODE_E_READ_ERROR, @ref GLOBUS_XIO_MODE_E_WRITE_ERROR
 * 
 * @see globus_xio_driver_error_match()
 * @see globus_error_errno_match()
 */

/**
 * MODE_E driver specific error types
 * @ingroup mode_e_driver_errors
 */
typedef enum
{   
    /**
     * Indicates that an error occured while opening the handle
     */
    GLOBUS_XIO_MODE_E_OPEN_ERROR,       
    /**
     * Indicates that an error occured while reading data
     */
    GLOBUS_XIO_MODE_E_READ_ERROR,       
    /**
     * Indicates that an error occured while writing data
     */
    GLOBUS_XIO_MODE_E_WRITE_ERROR,      
    
} globus_xio_mode_e_error_type_t;


/** doxygen varargs filter stuff
 * GlobusVarArgDefine(
 *      attr, globus_result_t, globus_xio_attr_cntl, attr, driver)
 */

/**
 * MODE_E driver specific cntls
 * @ingroup mode_e_driver_cntls
 */

typedef enum
{
    /** GlobusVarArgEnum(attr)
     * Set the stack (of xio drivers) to be used for the connection(s).
     * @ingroup mode_e_driver_cntls
     * Do not create a new ftp client handle, use this handle instead.
     * 
     * @param stack
     *      Specifies the stack to use for the connection(s).
     *      Note: this stack will not be destroyed.
     */
    GLOBUS_XIO_MODE_E_SET_STACK,

    /** GlobusVarArgEnum(attr)
     * Get the stack on the attr.
     * @ingroup mode_e_driver_cntls
     * 
     * @param stack_out
     *      The stack will be stored here. If none is set, GLOBUS_NULL will be 
     *      set.
     */
    GLOBUS_XIO_MODE_E_GET_STACK,

    /** GlobusVarArgEnum(attr)
     * Set the number of streams to be used between the client and the
     * server.
     * @ingroup mode_e_driver_cntls
     *
     * @param num_streams
     *      Specifies the number of streams to use.
     */
    GLOBUS_XIO_MODE_E_SET_NUM_STREAMS,

    /** GlobusVarArgEnum(attr)
     * Get the number of streams on the attr.
     * @ingroup mode_e_driver_cntls
     *
     * @param num_streams_out
     *      The stream count will be stored here.
     */
    GLOBUS_XIO_MODE_E_GET_NUM_STREAMS,

    /** GlobusVarArgEnum(attr)
     * Set the attr cntl function that should be called before creating a new
     * connection with the stack specified. If any driver specific cntls is 
     * needed on the stack, this function should take care of applying all 
     * those cntls on the xio_attr passed to it.
     * @see globus_xio_mode_e_attr_cntl_callback_t
     * @ingroup mode_e_driver_cntls
     *
     * @param attr_cntl_cb
     *      Specifies the function pointer.
     */
    GLOBUS_XIO_MODE_E_APPLY_ATTR_CNTLS,
    GLOBUS_XIO_MODE_E_SET_OFFSET_READS,
    GLOBUS_XIO_MODE_E_GET_OFFSET_READS,

    /** ??? change this explanation ??? GlobusVarArgEnum(attr)
     * Set EOF on the stripe. If there are multiple stripes, only of them 
     * should send EOF (EOD count). 
     * @ingroup mode_e_driver_cntls
     *
     * @param eof
     *      GLOBUS_TRUE to send EOF (default), GLOBUS_FALSE to not send EOF.
     * @param eod_count
     *      Specifies the number of EODs that must be received by the server.
     */
    GLOBUS_XIO_MODE_E_SET_MANUAL_EODC,

    /** ??? change this explanation ??? GlobusVarArgEnum(attr)
     * Get the EOF flag on the attr.
     * @ingroup mode_e_driver_cntls
     *
     * @param eof_out
     *      The EOF flag will be stored here.
     */
    GLOBUS_XIO_MODE_E_GET_MANUAL_EODC,
    GLOBUS_XIO_MODE_E_SEND_EOD,
    GLOBUS_XIO_MODE_E_SET_EODC,
    GLOBUS_XIO_MODE_E_DD_GET_OFFSET

} globus_xio_mode_e_cmd_t;	

#endif

/**
 * MODE_E driver specific types
 * @ingroup mode_e_driver_types
 * @hideinitializer
 */
typedef globus_result_t
(*globus_xio_mode_e_attr_cntl_callback_t)(
    globus_xio_attr_t                   attr);
