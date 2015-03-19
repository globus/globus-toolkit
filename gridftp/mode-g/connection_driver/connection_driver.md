XIO MODE G Data Connection Driver {#connection_driver}
=================================

Introduction
------------
This document describes the design of the XIO Mode G Data Connection driver.
This driver is a connection-oriented transfer driver that formats and parses
Mode G block header meta-data and maintains the state of the transfers that are
being processed on the data connection. A higher level XIO MODE G Data Channel
Driver handles multiplexing data transfers across multiple data connections.

Design Overview
---------------
This driver is designed to implement the MODE G block framing protocol. This
protocol is a bidirectional multiplexed data transfer protocol, where multiple
transfers may be happening concurrently on a data connection. By necessity this
driver uses data descriptors to differentiate the different data transfers
happening on the single data connection. However, explicitly creating these
descriptors can be made optional if no simultaneous transfers are attempted on
a particular XIO handle and no protocol extensions are being used.

This driver enforces the flow control behavior defined in the MODE G spec, so
callers may only send data when a transfer is `ACTIVE` or (if it is the only
outbound transfer)  in one of the `STARTING` or `STARTING_ENDING` states. This
driver does not multiplex data across multiple data connections; it implements
a single data connection per XIO handle. Data connections can be multiplexed
using the MODE G Data Channel protocol.

Data Descriptors
----------------
Data descriptors are used in this driver to allow the user of this driver
to manage the message headers sent along with data by this driver. Each
data descriptor contains one or more
@link #globus_xio_mode_g_header_s  `globus_xio_mode_g_header_t` @endlink
structures linked together via their @link globus_xio_mode_g_header_s#next_header next_header @endlink pointer. These structures provide
header information for each message in a particular read or write. These
message headers can be created automatically by this driver when writing
data for a single Transfer ID, but a more complicated transfer will require
using the data descriptor interface.

Writing Data
------------
The Mode G data protocol allows multiple data flows to be in progress on 
each Mode G data connection. This section describes the way that the Mode G
connection driver handles message headers when creating data flows
and writing data.

Starting a Transfer
-------------------
The Mode G data protocol allows multiple data flows to be in progress on 
each Mode G data connection. This driver supports that and enforces the
flow control rules defined in the Mode G protocol definition. Attempts to
start a new flow when it is not permitted will fail with a
`GLOBUS_XIO_MODE_G_ERROR_FLOW_CONTROL` type error.

A new data flow can be created in two ways with this driver, either explicitly
or implicitly. To create a new data flow explicitly, the caller must create a
data descriptor and add message header information. This is required if the
data flow will be using an extension or if multiple data flows are being
processed simultaneously on the same data connection. To create a new data flow
implicitly, pass a write to this driver when no outgoing data flows exist.
This creates the message header containing the `DATA_START` descriptor bit
set and setting the Transfer ID to the next data flow Transfer ID and
the offset to 0.

The driver internally maintains and increments a `transfer_id` counter to
determine what to use as the default Transfer ID. This is always set to the
highest valued Transfer ID of any data flow that has been handled by the
connection.

Creating a Message Header
-------------------------
A message header structure is created by the creation of a data descriptor
for a Mode G Connection Driver XIO handle and then calling the
`GLOBUS_XIO_MODE_G_DD_ADD_HEADER` data descriptor control on that data
descriptor. Each header contains information about the data flow: the
descriptor flags, the message's Transfer ID, the data block (if any), and
extension headers and footers.

This example creates a message header to start a new transfer (error handling
omitted for brevity):

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
globus_xio_data_descriptor_t dd;
globus_xio_iovec_t data_iovec = { .iov_base = data, .iov_len = len };
globus_xio_data_descriptor_init(&dd, handle);
globus_xio_data_descriptor_cntl(
        dd,
        mode_g_connection_driver,
        GLOBUS_XIO_MODE_G_DD_ADD_HEADER,
        (uint16_t) GLOBUS_XIO_MODE_G_DATA_START,
        (uint32_t) transfer_id,
        (uint64_6) 0,
        &data_iovec,
        (int) 1);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note that the `data_iovec[].iov_base` values must contain a valid reference to
the data which is being passed in the write buffers that accompany this data
descriptor.

When writing data without specifying a message header, or if some parameters to
the header creation are left unspecified, then the driver fills in the
parameters as follows:

Header Field | Default if unspecified
------------ | ----------------------
`transfer_id`| _same as previous data flow, or increment the `transfer_id` counter if no data flow exists_
`descriptor` | _0 or `GLOBUS_XIO_MODE_G_DATA_START` if no data flow exists_
`data_length`| _length of buffer_
`data_offset`| _after the end of previous write, or 0 if no data flow exists_

Note that the _length of buffer_ may be 0 if no data is being sent along with
the message header when explicitly creating a data flow.

Adding Header and Footer Extensions
-----------------------------------
Within an XIO driver that implements a header or footer extension 
to the Mode G data protocol, the procedure is to acquire the set of message
headers for the write operation and then add the extension information to
each message it wants to add the extension to. Note that if the extension
driver attempts to retrieve the message headers and none have been created
by the user (the implicit header case), the value returned from the 
`GLOBUS_XIO_MODE_G_DD_GET_HEADER` data descriptor control will contain
the information from the default message header generated by this driver.

This example adds an extension header to the messages in a write.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
globus_xio_mode_g_header_t  *header = NULL;
globus_xio_iovec_t *message_iovec;
int message_iov_count;
globus_xio_iovec_t *extension_header;

globus_xio_driver_data_descriptor_cntl(
        op,
        mode_g_connection_driver,
        GLOBUS_XIO_MODE_G_DD_GET_HEADER,
        &header)
while (header != NULL)
{
    globus_xio_iovec_t *message_iovec;
    if (header->data_size == (uint64_t) GLOBUS_XIO_MODE_G_UNSPECIFIED)
    {
        /* This must only be true for the case when there is a single
         * message header, and the message header will contain all of the
         * data in the write buffer. 
         */
        message_iovec = iovec;
        message_iov_count = iovec_count;
    }
    else
    {
        message_iovec = header->data;
        message_iov_count = header->data_count;
    }

    extension_header = NULL;
    compute_extension_header(
            message_iovec, message_iov_count, &extension_header);
    if (extension_header != NULL)
    {
        /* Will have to free this in write callback */
        globus_xio_driver_data_descriptor_cntl(
            op,
            mode_g_connection_driver,
            GLOBUS_XIO_MODE_G_DD_SET_HEADER_EXTENSION,
            my_extension_id,
            extension_header,
            1);
    }
    header = header->next_header;
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a write completes, its callback will be passed the data descriptor from
the write, so that extension handlers may clean up any data associated with
the messages. If any transfer is aborted by the other end of the connection,
an error object will be passed to that callback. The callback function can
use that information to abort the transfer.

Ending a Data Flow (write)
--------------------------
When a data source is finished sending data for a data flow, it must create a
message header and add the descriptor value `GLOBUS_XIO_MODE_G_DATA_END`
(and `GLOBUS_XIO_MODE_G_TRANSFER_COMPLETE` for end of file) to
the header.  This may be sent along with the final block of data or as
a separate message with no data. Data flows can also be ended by closing the
data connection. This is interpreted by the driver as a request to end all
data flows with a `DATA_END` message and then complete the
`CONNECTION_CLOSE_REQ` - `CONNECTION_CLOSE` handshake.

This example sends an empty message with the `DATA_END` bit set:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
globus_xio_data_descriptor_t dd;
globus_xio_data_descriptor_init(&dd, handle);
globus_xio_data_descriptor_cntl(
        dd,
        mode_g_connection_driver,
        GLOBUS_XIO_MODE_G_DD_ADD_HEADER,
        (uint16_t) GLOBUS_XIO_MODE_G_DATA_END,
        (uint32_t) transfer_id,
        (uint64_6) 0,
        NULL,
        (int) 0);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Reading Data
------------
When registering a read with the Mode G protocol, the caller does not know
what data flow the data will correspond to, or what amount of data will be
in a message. To reduce the XIO overhead when reading with this driver, it
may call the read callback with more than one message in its data descriptor
if the messages are smaller than the data buffer passed to the read.

In the read callback, the application or higher level driver should use the
`GLOBUS_XIO_MODE_G_DD_GET_HEADER` data descriptor control to determine how
to process each message in the read. The message header, as well as extension
headers and footers for each completely read message will be be available
from the `#globus_xio_mode_g_header_t` structure returned from
that control function.

This example reads data from the data connection and then writes it
to local files using a lookup table of fds:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
void
read_callback(
    globus_xio_handle_t                 handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_xio_mode_g_header_t *        headers;

    globus_xio_data_descriptor_cntl(
        dd,
        mode_g_connection_driver,
        GLOBUS_XIO_MODE_G_DD_GET_HEADER,
        &headers);

    while (headers != NULL)
    {
        if (headers->data_size != 0)
        {
            int fd = fd_table[headers->transfer_id];
            if (headers->descriptor & GLOBUS_XIO_MODE_G_DATA_START && fd == -1)
            {
                fd = fd_table[headers->transfer_id] =
                    open(
                        filenames[headers->transfer_id],
                        O_RDWR | O_CREAT,
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            }

            lseek(fd, (off_t) headers->data_offset, SEEK_SET);

            writev(fd, headers->data, headers->data_count);
            if (headers->descriptor & GLOBUS_XIO_MODE_G_DATA_END)
            {
                close(fd);
                fd_table[headers->transfer_id] = -1;
            }
        }
        headers = headers->next_header;
    }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


In the case that the buffer passed to the read is smaller than needed for
the message data, then an error with the type
`GLOBUS_XIO_MODE_G_ERROR_BUFFER_TOO_SMALL` is returned, with information
regarding the minimum data size to process the next message.

A driver which is processing a mode G header or footer extension is able
to read the extension data by looking at the 
[extension_headers](@ref globus_xio_mode_g_header_t#extension_headers)
and
[extension_footers](@ref globus_xio_mode_g_header_t#extension_footers)
members of the `globus_xio_mode_g_header_t` structure. For reads,
the data for the extensions will be automatically freed once the data
descriptor is destroyed by XIO.

Flow Control
------------
The mode G protocol contains data flow control messaging to prevent data
sources from requiring large amounts of data to be buffered in user space when
multiple transfers are being processed. One aspect of this is requiring
the data sink to respond with a `DATA_YES` message prior to a data source
sending data for anything but the first data flow on a data connection.

The diagram on the 
[Mode G Flow States](flow_states.html)
shows the different data flow states.

Flow control management can be handled in two ways by this driver: manually or
automatically.  When manual flow control is enabled (the default), the reader
must explicitly create a message header with the `DATA_YES` or `DATA_NO` bit
set in the data descriptor to control whether data may be sent for each flow.

The reader may determine what data flows are waiting
for the `DATA_YES` message by checking the descriptor field of the
message headers returned to the read callback to see which contain the
`DATA_START` bit, or by calling the
`GLOBUS_XIO_MODE_G_HANDLE_GET_STARTING_TRANSFER_IDS` handle control, which
returns an array of the Transfer IDs of incoming data flows that are in the
`STARTING` or `STARTING_ENDING` states.

When automatic flow control is enabled, this driver will automatically write
a message containing the `DATA_YES` bit after the read callback for a message
containing `DATA_START` bit completes. If the user of the driver detects an
error or an inability to process the read, it may create a new data descriptor
containing a message header with the `DATA_NO` and/or `TRANSFER_ABORT`
descriptor bits set and pass that as a write to prevent the automatic
`DATA_YES` message from being sent.

To choose the flow control method to use for a handle, call the handle control
`GLOBUS_XIO_MODE_G_HANDLE_SET_AUTOMATIC_FLOW_CONTROL` with `GLOBUS_TRUE`
to enable the automatic message, or `GLOBUS_FALSE` to disable the automatic
messages.

Ending a Data Flow (read)
-------------------------
When a data source is finished sending data for a data flow, it will send
a message containing a header with the `DATA_END` bit
set in the descriptor flag. It will then wait for a reply message from the
data sink before considering the flow completed. Similar to the flow control
messaging above, the message header containing the `DATA_END` bit may be
sent manually or automatically.

The reader may determine what data flows are waiting
for the `DATA_END` message by checking the descriptor field of the
message headers returned to the read callback to see which contain the
`DATA_END` bit, or by calling the
`GLOBUS_XIO_MODE_G_HANDLE_GET_ENDING_TRANSFER_IDS` handle control, which
returns an array of the Transfer IDs of incoming data flows that are in the
`ENDING` or `STARTING_ENDING` states.

When automatic `DATA_END` is enabled, this driver will automatically write
a message containing the `DATA_END` bit after the read callback for a message
containing `DATA_END` bit completes. If the user of the driver detects an
error or an inability to process the read, it may create a new data descriptor
containing a message header with the `TRANSFER_ABORT`
descriptor bits set and pass that as a write to prevent the automatic
`DATA_END` message from being sent.

To choose the flow control method to use for a handle, call the handle control
`GLOBUS_XIO_MODE_G_HANDLE_SET_AUTOMATIC_DATA_END` with `GLOBUS_TRUE`
to enable the automatic message, or `GLOBUS_FALSE` to disable the automatic
messages.

Closing a data connection
-------------------------
When closing an mode G data connection handle, the close protocol is
automatically performed. The `CONNECTION_CLOSE_REQ` and `CONNECTION_CLOSE`
bits are set in control messages sent and received by both ends of the
connection. A user of this driver may explicitly set these bits by creating
message header(s) containing them, or the messages will be sent automatically
when the `globus_xio_close` or `globus_xio_register_close()` function is
called.

