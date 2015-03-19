XIO Mode G Transfer Driver {#transfer_driver}
==========================
Introduction
------------
The XIO MODE G Transfer driver multiplexes data transfers across XIO Mode G
Data Connection handles maintained internally. This driver operates on the
Transfer ID level with XIO handles corresponding to the lifetime of a single
Mode G data transfer (perhaps transferring data across multiple data
connections).

Mode G Data Connection Pool
---------------------------
Internally, data transfer operations are done (many-to-many) across a dynamic
pool of data connections. The pool is created and associated with  transfers
via the XIO attribute mechanism. Within a particular named connection pool, all
Mode G Data Connection XIO handles will contain the same configuration and
stack (typically `mode_g_connection`, `gsi`, `tcp`) as well as contact string
(to listen on or connect to).

The XIO handles for the mode g data connection pool are created using a
configuration passed in to the Mode G Transfer Driver during attribute
creation. The configuration includes the transfer parameters negotiated on the
GridFTP control channel: the XIO stack for data connections, passive or active
connection type, and if passive using spdt, the XIO handle to read new TCp fds
on.

The connection pool will remain active until all XIO attributes referring to it
are destroyed and all Mode G Transfer handles created using it are closed. The
connections within the pool will be created or destroyed automatically
according to the Mode G protocol. All connections in a pool may be closed
explicitly by doing an attr control to close the pool.

Passive Data Connections
------------------------
For Mode G, passive data connections may be created in two ways: using the
single port handshake or using the normal passive accept mode. Both of these
are implemented by the Data Connection pool part of the Mode G Transfer Driver.

For the single port handshake, an XIO handle using the XXX driver which  reads
TCP socket file descriptors from the GridFTP server is passed in when the mode
g data connection pool is created. The mode g data connection pool will monitor
and read new tcp connections while the pool remains active. These TCP
connections will passed to an XIO tcp attribute and opened with the Mode G data
connection stack and added to the connection pool. The data connection pool
will explicitly close the tcp socket when the mode g connection XIO handle is
closed.

For the normal passive data connection mode, an XIO server handle using the
mode g data connection stack is passed in when the mode g data connection pool
is created. The mode g data connection pool will monitor and accept new mode g
data connections and add them to the pool.

Active Data Connections
-----------------------
For Mode G, active data connections may be created in two ways: using the
single port handshake or using the normal connect. This are similar and differ
only in the stack being used and the use of the spdt-data attribute. SPDT
transfers will require the spdt data handshake driver to be inserted between
the GSI and TCP drivers and require the spdt-data attribute to be set to the
single port data token.

Closing Data connections
------------------------
Normally, data connections will be closed automatically when they are idle and
all attributes referring to the data connection pool are destroyed. A caller
may explicitly close all data connections by calling the globus_xio_attr_cntl
with an attribute that contains the data pool name and the
GLOBUS_XIO_MODE_G_TRANSFER_CLOSE_ALL attribute.

Opening a Transfer
------------------
The Mode G Data Channel Driver does not use an XIO server handle to create
individual connections but uses those created by the data connection pool. Each
transfer is opened with a special x-mode-g or x-mode-g URL which indicates the
direction of the transfer (independent of the tcp connection direction) and the
Transfer ID. The connection pool attribute must be used for each open in order
for the Mode G data connection stack to be used. 

Opening a Write Transfer
------------------------
To open transfer id XXX for writing, the caller would open the URL
x-mode-g://w:XXX

Once the Mode G Channel driver knows that the connection pool can send the
DATA_START message to the other GridFTP endpoint it will call the open
callback. This will be based on the available connections and whether the flow
control protocol allows the DATA_START message to sent on any existing
connections. The DATA_START may possibly be sent prior to the open callback but
this is not guaranteed.

Opening a Read Transfer
-----------------------
To open transfer id YYY for reading, the caller would open the URL
x-mode-g://r:YYY

The callback for the transfer will return once the DATA_START message has been
received on one Mode G data connection XIO handles. The DATA_YES message will
be automatically sent in reply, but the open callback may be invoked before
that is processed. 

Reading and Writing Data
------------------------
Once the data channel XIO handle is open, the standard XIO read and write
commands will be used to send data on the channel. Depending on available
connections, additional DATA_START messages may be sent on channels which are
now available to process the data. These will be handled by the driver and the
data connection pool.

Data writes will be assumed to be sequential, but writers may generate XIO data
descriptors to write partial data transfers.

Non-blocking data reads will be called back with a data descriptor containing
the offset of the data which was read.

Aborting a Transfer
-------------------
Once a transfer is open, it may be aborted by doing an XIO handle cntl with the
XIO_MODE_G_CHANNEL_ABORT. This may be done for transfers open for reading or
writing. When this occurs, the peer will receive an error object indicating
that the transfer is aborted.

Closing a Transfer
------------------
A transfer may be closed by calling `globus_xio_close` or
`globus_xio_register_close`.

If the transfer handle is a write handle, this will initiate the end of file
handshake for the transfer. The close will complete once that handshake has
completed.

If the transfer handle is a read handle, the close should be called after the
end of file indicator has been received; otherwise this may result in an abort
of the transfer, if the sender is still expecting to be able to send data for
that transfer. The result of the close will be indicate whether the transfer
was aborted or not by the close.
