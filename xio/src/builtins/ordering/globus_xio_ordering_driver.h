/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_XIO_ORDERING_DRIVER_INCLUDE
#define GLOBUS_XIO_ORDERING_DRIVER_INCLUDE

/**
 * @file
 * Header file for XIO ORDERING Driver
 */

#include "globus_common.h"

/**
 * @defgroup ordering_driver Globus XIO ORDERING Driver
 */

/**
 * @defgroup ordering_driver_instance Opening/Closing
 * @ingroup ordering_driver
 * Ordering driver is a transform driver and thus has to be used on top of a 
 * transport driver. An XIO handle with the ordering driver can be created with 
 * either @ref globus_xio_handle_create() or 
 * @ref globus_xio_server_register_accept().
 *
 * When the XIO handle is closed, the ordering driver will destroy its internal
 * resources.
 */

/**
 * @defgroup ordering_driver_io Reading/Writing
 * @ingroup ordering_driver
 * Ordering driver does not allow multiple @ref globus_xio_register_read() 
 * to be outstanding. This limitation is there to enforce that the users get 
 * the read callback in order. There is a known issue in enforcing the order
 * in which read callbacks are delivered with multiple outstanding reads. This
 * limitation does not restrict the use of parallel reads feature provided by
 * the underlying transport driver. @ref GLOBUS_XIO_ORDERING_SET_MAX_READ_COUNT 
 * on the attr can be used to specify the number of parallel reads. Ordering
 * will have a maximum of this many number of reads outstanding to the driver
 * below it on the stack. It buffers the data read and delivers it to the user
 * in order.
 *
 * @ref globus_xio_register_write() does not enforce any restriction.
 *
 */

/**
 * @defgroup ordering_driver_envs Env Variables
 * @ingroup ordering_driver
 *
 * - GLOBUS_XIO_ORDERING_DEBUG Available if using a debug build.  See
 * globus_debug.h for format.
 */

/**
 * @defgroup ordering_driver_cntls Attributes and Cntls
 * @ingroup ordering_driver
 *
 * Ordering driver specific attrs and cntls.
 *
 * @see globus_xio_attr_cntl()
 * @see globus_xio_handle_cntl()
 */
/**
 * @defgroup ordering_driver_types Types
 * @ingroup ordering_driver
 */
/**
 * @defgroup ordering_driver_errors Error Types
 * @ingroup ordering_driver
 *
 * The errors reported by ORDERING driver include
 * GLOBUS_XIO_ERROR_COMMAND, GLOBUS_XIO_ERROR_MEMORY, GLOBUS_XIO_ERROR_STATE,
 * GLOBUS_XIO_ERROR_CANCELED
 *
 * @see globus_xio_driver_error_match()
 * @see globus_error_errno_match()
 */

/** doxygen varargs filter stuff
 * GlobusVarArgDefine(
 *      attr, globus_result_t, globus_xio_attr_cntl, attr, driver)
 * GlobusVarArgDefine(
 *      handle, globus_result_t, globus_xio_handle_cntl, handle, driver)
 */

/**
 * ORDERING driver specific cntls
 * @ingroup ordering_driver_cntls
 */
typedef enum
{
    /** GlobusVarArgEnum(handle)
     * Set offset for the next IO operation. This is not allowed when there is
     * an outstanding IO operation. This operation clears all the buffered data.
     * @ingroup ordering_driver_cntls
     *
     * @param offset
     *      Specifies the offset to use in the next IO operation.
     */
    /* globus_off_t			offset */
    GLOBUS_XIO_ORDERING_SET_OFFSET,

    /** GlobusVarArgEnum(attr)
     * Set the maximum number of reads that ordering driver can have outstanding
     * on driver(s) below.
     * @ingroup ordering_driver_cntls
     *
     * @param max_read_count
     *      Specifies the maximum number of parallel reads (default is 1).
     */
    /* int				max_read_count */
    GLOBUS_XIO_ORDERING_SET_MAX_READ_COUNT,

    /** GlobusVarArgEnum(attr)
     * Get the maximum number of parallel reads set on the attr.
     * @ingroup ordering_driver_cntls
     *
     * @param max_read_count_out
     *      The maximum number of parallel reads allowed will be stored here.
     */
    /* int *				max_read_count_out */
    GLOBUS_XIO_ORDERING_GET_MAX_READ_COUNT,

    /** GlobusVarArgEnum(attr)
     * This driver can be used in 2 modes; ordering (care about offsets of the 
     * data read - underlying transport driver may deliver data out of order -
     * this driver will rearrange data based on the offset and deliver inorder
     * to user) and buffering (do not care about offsets - just buffer the data
     * read abd deliver it when requested). This attribute control can be used
     * to enable buffering.
     * @ingroup ordering_driver_cntls
     *
     * @param buffering
     *	    GLOBUS_TRUE to enable buffering, GLOBUS_FALSE (default) to disable 
     * buffering.
     */
    /* globus_bool_t			buffering */
    GLOBUS_XIO_ORDERING_SET_BUFFERING,

    /** GlobusVarArgEnum(attr)
     * Get the buffering flag on the attr.
     * @ingroup ordering_driver_cntls
     *
     * @param buffering_out
     *      Buffering flag will be stored in here.
     */
    /* globus_bool_t *			buffering_out */
    GLOBUS_XIO_ORDERING_GET_BUFFERING,

    /** GlobusVarArgEnum(attr)
     * Set the size of the buffer that ordering driver creates to use for 
     * reading data from the driver below it.
     * @ingroup ordering_driver_cntls
     *
     * @param buf_size
     *      Specifies the buffer size for internal reads (default is 100 KB).
     */
    /* int				buf_size */
    GLOBUS_XIO_ORDERING_SET_BUF_SIZE,

    /** GlobusVarArgEnum(attr)
     * Get the size of the buffer used for the internal reads.
     * @ingroup ordering_driver_cntls
     *
     * @param buf_size_out
     *      The buffer size will be stored in here.
     */ 
    /* int *				buf_size_out */
    GLOBUS_XIO_ORDERING_GET_BUF_SIZE,

    /** GlobusVarArgEnum(attr)
     * Set the maximum number of buffers that this driver can create for
     * reading data from the driver below it.
     * @ingroup ordering_driver_cntls
     *
     * @param max_buf_count
     *      Specifies the max buffer count for internal reads (default is 100).
     */
    /* int				max_buf_count */
    GLOBUS_XIO_ORDERING_SET_MAX_BUF_COUNT,

    /** GlobusVarArgEnum(attr)
     * Get the maximum buffer count set on the attr.
     * @ingroup ordering_driver_cntls
     *
     * @param max_buf_count_out
     *      The maximun buffer count will be stored in here.
     */
    /* int *				max_buf_count_out */
    GLOBUS_XIO_ORDERING_GET_MAX_BUF_COUNT

} globus_xio_ordering_cmd_t;	


#endif
