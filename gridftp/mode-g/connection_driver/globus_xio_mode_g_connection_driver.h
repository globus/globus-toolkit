/*
 * Copyright 1999-2015 University of Chicago
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
 * @file gridftp/mode-g/connection_driver/globus_xio_mode_g_connection_driver.h
 */
#ifndef GLOBUS_XIO_MODE_G_CONNECTION_DRIVER_H
#define GLOBUS_XIO_MODE_G_CONNECTION_DRIVER_H 1

#include <stdint.h>

#include "globus_xio.h"

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */

/**
 * @defgroup globus_xio_mode_g_connection_driver XIO Mode G Connection Driver
 * @brief Mode G Connection Driver
 * @details
 * This driver is a connection-oriented transfer driver that formats and parses
 * Mode G message header meta-data and maintains the state of the transfers
 * that are being processed on the data connection. 
 *
 * This driver is designed to implement the MODE G block framing protocol. This
 * protocol is a bidirectional multiplexed data transfer protocol, where
 * multiple transfers may be happening concurrently on a data connection. By
 * necessity this driver uses data descriptors to differentiate the different
 * data transfers happening on the single data connection. However, explicitly
 * creating these descriptors (except to indicate end of transfer) can be made
 * optional if no parallel transfers are attempted. This driver enforces the
 * flow control behavior defined in the MODE G spec, so callers may only send
 * data when a transfer is ACTIVE or (if it is the only outbound transfer)  in
 * one of the STARTING or STARTING_ENDING states. This driver does not
 * multiplex data across multiple data connections; it implements a single data
 * connection per XIO handle. 
 */

/**
 * @brief Data Flow States
 * @ingroup globus_xio_mode_g_connection_driver
 * @details
 * Enumeration of the connection states that a Mode G data flow may have.
 */
typedef enum
{
    /** The data source has sent a message with the DATA_START bit set but it
     * is not yet acknowledged
     */
    GLOBUS_XIO_MODE_G_STARTING,
    /** The data sink has responded to the message with the DATA_START bit set
     * with a message with the DATA_YES bit set.
     */
    GLOBUS_XIO_MODE_G_ACTIVE,
    /** The data sink has responded to the message with the DATA_START bit set
     * with a message with the DATA_NO bit set, or the data sink has sent a
     * message with the TRANSFER_ABORT bit set while a data flow for that
     * Transfer ID is in the ACTIVE state. 
     */
    GLOBUS_XIO_MODE_G_REFUSED,
    /** The data source has sent a message with the DATA_END bit set but it is
     * not yet acknowledged.
     */
    GLOBUS_XIO_MODE_G_ENDING,
    /** The data source has sent a message (or messages) with both the
     * DATA_START and DATA_END bits set, but the data sink has not yet
     * responded with either DATA_YES and DATA_NO.
     */
    GLOBUS_XIO_MODE_G_STARTING_ENDING
}
globus_xio_mode_g_flow_state_t;

/**
 * @brief Connection States
 * @ingroup globus_xio_mode_g_connection_driver
 * @details
 * Enumeration of the connection states that a Mode G data connection may have
 * for each transfer it is processing.
 */
typedef enum
{
    /** The data connection close protocol has not yet begun */
    GLOBUS_XIO_MODE_G_CONNECTION_START,
    /** The CONNECTION_CLOSE_REQ message has been sent */
    GLOBUS_XIO_MODE_G_CONNECTION_OUTGOING_CLOSING,
    /** The CONNECTION_CLOSE_REQ message has been received */
    GLOBUS_XIO_MODE_G_CONNECTION_INCOMING_CLOSING,
    /** The CONNECTION_CLOSE_REQ message has been sent and received */
    GLOBUS_XIO_MODE_G_CONNECTION_BOTH_CLOSING,
    /** The CONNECTION_CLOSE message has been sent */
    GLOBUS_XIO_MODE_G_CONNECTION_OUTGOING_CLOSED,
    /** The CONNECTION_CLOSE message has been received */
    GLOBUS_XIO_MODE_G_CONNECTION_INCOMING_CLOSED,
    /** The CONNECTION_CLOSE message has been sent and received */
    GLOBUS_XIO_MODE_G_CONNECTION_CLOSED
}
globus_xio_mode_g_connection_state_t;

/**
 * @brief Data Message Descriptors
 * @ingroup globus_xio_mode_g_connection_driver
 * @details
 * These bits may be sent in the message header's descriptor field to indicate
 * how to process the transfer.
 */
typedef enum
{
    /** Request to start a data flow. */
    GLOBUS_XIO_MODE_G_DATA_START            = 1,
    /** Accept the DATA_START request */
    GLOBUS_XIO_MODE_G_DATA_YES              = 2,
    /** Refuse the DATA_START request */
    GLOBUS_XIO_MODE_G_DATA_NO               = 4,
    /** End a data flow  */
    GLOBUS_XIO_MODE_G_DATA_END              = 8,
    /** Abort a transfer */
    GLOBUS_XIO_MODE_G_TRANSFER_ABORT        = 16,
    /** All data for the transfer has been sent on ACTIVE data flows. */
    GLOBUS_XIO_MODE_G_TRANSFER_COMPLETE     = 32,
    /** Request closing the data connection.  */
    GLOBUS_XIO_MODE_G_CONNECTION_CLOSE_REQ  = 64,
    /** Close a data connection. */
    GLOBUS_XIO_MODE_G_CONNECTION_CLOSE      = 128
}
globus_xio_mode_g_connection_descriptor_t;

/**
 * @brief Mode G Extension
 * @ingroup globus_xio_mode_g_connection_driver
 * @details
 * This structure defines extensions in the Mode G data protocol.
 * Extension data blocks may be added either before or after the data payload
 * in a Mode G message.
 */
typedef struct
{
    /** Unique identifier for this extension */
    uint16_t                                id;
    /** Data for this extension */
    globus_xio_iovec_t                     *data;
    /** Number of elements in the data array */
    int                                     data_count;
}
globus_xio_mode_g_extension_t;

/* Miscellaneous constants */
enum
{
    /**
     * This value is used as the transfer_id in a Mode G message header
     * when the message does not contain information about a data transfer
     * but relates to the connection.
     */
    GLOBUS_XIO_MODE_G_TRANSFER_ID_NONE = 0,
    /**
     * This value is used  as the data_size or data_offset value in
     * a data descriptor to mark them as unspecified. 
     * If used for the data_size, its value value in the message header will
     * be the same as the size of the buffer being written. If used for the
     * data_offset, its value in the message header will be on
     * the end offset of the previous write if any there was one, otherwise 
     * it will be 0.
     */
    GLOBUS_XIO_MODE_G_UNSPECIFIED = -1
};

/**
 * @brief Mode G Message Header
 * @ingroup globus_xio_mode_g_connection_driver
 * @details
 * This structure defines message headers in the Mode G data protocol. Each
 * message sent and received by this driver will include a message header
 * like this, which can be inspected and manipulated via the data descriptor
 * interface. All of the data in this structure is in host byte order, which
 * will be converted to network byte order when transmitted as required by
 * the protocol.
 *
 * This driver creates message headers automatically when reading
 * data. The message_state field is used to indicate to the caller whether a
 * read is able to return an entire message.
 *
 */
typedef struct globus_xio_mode_g_header_s
{
    /**
     * The descriptor is a bitwise-or of values from the
     * #globus_xio_mode_g_connection_descriptor_t enumeration. This may be
     * zero if this is a data only block.
     */
    uint16_t                            descriptor;
    /**
     * The transfer id this message is being sent for. This value may be
     * #GLOBUS_XIO_MODE_G_TRANSFER_ID_NONE if message pertains to the connection
     * and not to a particular transfer.
     */
    uint32_t                            transfer_id;
    /**
     * The number of extensions present in the extension_headers
     * array
     */
    size_t                              num_headers;
    /**
     * The number of extensions present in the extension_footers
     * array
     */
    size_t                              num_footers;
    /**
     * An array of extension values to be sent in the header section of this
     * message.
     */
    globus_xio_mode_g_extension_t      *extension_headers;
    /**
     * An array of extension values to be sent in the footer section of this
     * message. 
     */
    globus_xio_mode_g_extension_t      *extension_footers;
    /**
     * The length in bytes of the data in this message.
     */
    uint64_t                            data_size;
    /**
     * The offset in bytes within the entire data transfer of the data in this
     * message.
     */
    uint64_t                            data_offset;
    /**
     * Array of iovec structures that point into the data buffer passed to the
     * read or write which generated this header. For the read case, if the
     * read buffer size is larger than the size of an incoming message,
     * multiple messages may be read. In that case, the data iovec array will
     * point to into the passed buffers which correspond to the data described
     * by this header.
     */
    globus_xio_iovec_t                 *data;
    /** 
     * Number of elements in the data array */
    int                                 data_count;
    /**
     * Pointer to the next header that is related to this read or write. This
     * is NULL if there are no further headers in this read or write.
     */
    struct globus_xio_mode_g_header_s
                                       *next_header;
}
globus_xio_mode_g_header_t;


/**
 * @brief Mode G Connection Driver Specific Error Types
 * @ingroup globus_xio_mode_g_connection_driver
 */
typedef enum
{
    /** The extension cannot be added to the message header */
    GLOBUS_XIO_MODE_G_ERROR_EXTENSION_TOO_BIG,
    /**
     * Data cannot be sent for this Transfer ID because the data sink has
     * replied with the DATA_NO or CONNECTION_CLOSE_REQ bits set.
     */
    GLOBUS_XIO_MODE_G_ERROR_DENIED,
    /**
     * Data cannot be sent for this Transfer ID because the data sink has
     * replied with the TRANSFER_ABORT bit set.
     */
    GLOBUS_XIO_MODE_G_ERROR_ABORTED,
    /**
     * A new transfer flow cannot be started because a message with the
     * CONNECTION_CLOSE_REQ has already be sent.
     */
    GLOBUS_XIO_MODE_G_ERROR_CLOSING,
    /**
     * A new transfer flow cannot be started because there is already
     * an outstanding transfer which has not been acknowledged yet.
     */
    GLOBUS_XIO_MODE_G_ERROR_FLOW_CONTROL,
    /**
     * The message header contains some other invalid descriptor value. This
     * may be either a descriptor value that contains an unknown bit, or a
     * descriptor containing bits that aren't valid for the Transfer ID in its
     * current state.
     */
    GLOBUS_XIO_MODE_G_ERROR_INVALID_DESCRIPTOR,
    /**
     * The incoming message header indicates that the data to read is larger
     * that the buffer passed to the read.
     */
    GLOBUS_XIO_MODE_G_ERROR_BUFFER_TOO_SMALL
} globus_xio_mode_g_error_type_t;

/** doxygen varargs filter stuff
 * GlobusVarArgDefine(
 *      attr, globus_result_t, globus_xio_attr_cntl, attr, driver)
 * GlobusVarArgDefine(
 *      handle, globus_result_t, globus_xio_handle_cntl, handle, driver)
 * GlobusVarArgDefine(
 *      dd, globus_result_t, globus_xio_data_descriptor_cntl, dd, driver)
 */

/**
 * @brief MODE G driver specific data descriptor cntls
 * @ingroup globus_xio_mode_g_driver_cntls
 */
typedef enum
{
    /** GlobusVarArgEnum(dd)
     * Add a new message header to the data descriptor.
     * @ingroup globus_xio_mode_g_connection_driver
     * 
     * @param descriptor
     *      Descriptor value
     * @param transfer_id
     *      Transfer ID
     * @param offset
     *      Data offset in the transfer.
     * @param data
     *      Array of iovec values pointing to the data that will be
     *      written with this header. The data pointed to by this iovec
     *      must be included somewhere in the buffers passed to the write
     *      passed along with this data descriptor to this driver. The
     *      value of the data array is copied to the header structure.
     * @param data_count
     *      Number of elements in the data array
     */
    /* uint16_t                         descriptor,
     * uint32_t                         transfer_id,
     * uint64_t                         offset,
     * globus_xio_iovec_t              *data,
     * int                              data_count */
    GLOBUS_XIO_MODE_G_DD_ADD_HEADER,
    /** GlobusVarArgEnum(dd)
     * Get the list of headers from a data descriptor.
     * @ingroup globus_xio_mode_g_connection_driver
     * 
     * @param header_out
     *      Pointer to be set to the list of headers
     */
    /* globus_xio_mode_g_header_t **header_out */
    GLOBUS_XIO_MODE_G_DD_GET_HEADER,
    /** GlobusVarArgEnum(dd)
     * Add or replace a message header extension in a message header.
     * @ingroup globus_xio_mode_g_connection_driver
     * 
     * @param header_id
     *      Header extension ID
     * @param data
     *      Array of iovec values pointing to the data that will be
     *      written with as the header extension value. The data
     *      pointed to by the iov_base pointers must not be freed by the
     *      caller until the data descriptor is destroyed.
     * @param data_count
     *      Number of elements in the data array
     */
    /* uint16_t                         header_id,
     * globus_xio_iovec_t              *data,
     * int                              data_count */
    GLOBUS_XIO_MODE_G_DD_SET_HEADER_EXTENSION,
    /** GlobusVarArgEnum(dd)
     * Add or replace a message footer extension in a message header.
     * @ingroup globus_xio_mode_g_connection_driver
     * 
     * @param footer_id
     *      Footer extension ID
     * @param data
     *      Array of iovec values pointing to the data that will be
     *      written with as the header extension value. The data
     *      pointed to by the iov_base pointers must not be freed by the
     *      caller until the data descriptor is destroyed.
     * @param data_count
     *      Number of elements in the data array
     */
    /* uint16_t                         footer_id,
     * globus_xio_iovec_t              *data,
     * int                              data_count */
    GLOBUS_XIO_MODE_G_DD_SET_FOOTER_EXTENSION
}
globus_xio_mode_g_dd_cntl_t;

/**
 * @brief MODE G driver specific handle cntls
 * @ingroup globus_xio_mode_g_driver_cntls
 */
typedef enum
{
    /** GlobusVarArgEnum(handle)
     * Get the Transfer IDs for data flows that are in the STARTING or
     * STARTING_ENDING states.
     * @ingroup globus_xio_mode_g_connection_driver
     * 
     * @param transfer_ids_out
     *      Pointer to hold an array of Transfer ID values for data flows. The
     *      caller must free the array.
     * @param transfer_ids_length_out
     *      Pointer to an integer to be set to the length of the
     *      transfer_ids_out array.
     */
    /* uint32_t                       **transfer_ids_out,
     * int                             *transfer_ids_length_out */
    GLOBUS_XIO_MODE_G_HANDLE_GET_STARTING_TRANSFER_IDS,
    /** GlobusVarArgEnum(handle)
     * Enable or disable the automatic generation of flow control messages.
     * @ingroup globus_xio_mode_g_connection_driver
     * 
     * @param automatic_flow_control
     *      Boolean indicating whether to enable or disable automatic
     *      sending of flow control messages.
     */
    /* globus_bool_t                    automatic_flow_control */
    GLOBUS_XIO_MODE_G_HANDLE_SET_AUTOMATIC_FLOW_CONTROL,
    /** GlobusVarArgEnum(handle)
     * Get the Transfer IDs for data flows that are in the ENDING or
     * STARTING_ENDING states.
     * @ingroup globus_xio_mode_g_connection_driver
     * 
     * @param transfer_ids_out
     *      Pointer to hold an array of Transfer ID values for data flows. The
     *      caller must free the array.
     * @param transfer_ids_length_out
     *      Pointer to an integer to be set to the length of the
     *      transfer_ids_out array.
     */
    /* uint32_t                       **transfer_ids_out,
     * int                             *transfer_ids_length_out */
    GLOBUS_XIO_MODE_G_HANDLE_GET_ENDING_TRANSFER_IDS,
    /** GlobusVarArgEnum(handle)
     * Enable or disable the automatic generation of DATA_END replies.
     * @ingroup globus_xio_mode_g_connection_driver
     * 
     * @param automatic_data_end
     *      Boolean indicating whether to enable or disable automatic
     *      sending of DATA_END messages.
     */
    /* globus_bool_t                    automatic_data_end */
    GLOBUS_XIO_MODE_G_HANDLE_SET_AUTOMATIC_DATA_END
}
globus_xio_mode_g_handle_cntl_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* GLOBUS_XIO_MODE_G_CONNECTION_DRIVER_H */
