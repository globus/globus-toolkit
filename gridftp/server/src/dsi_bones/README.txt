
                        DSI Development
                        ===============

The Globus(tm) GridFTP server provides high speed remote access to data 
stores.  There are many different types of data storage systems from 
standard file systems to arrays of magnetic tape.  To allow GridFTP to 
be a transfer interface to as many data storage systems as possible the 
Data Storage Interface (DSI) was created.

The DSI presents a modular abstraction layer to a storage systems.  It 
consists of several function signatures and a set of semantics. When a 
new DSI is created a programmer implements the functions to provided the 
semantics associated with them.  DSIs can be loaded and switched at 
runtime. When the server requires action from the storage system (be it 
data, meta-data, directory creation, etc) it passes a request to the 
loaded DSI module. The DSI then services that request and tells the 
function when it is finished.

This document provides an introduction to the DSI and how to create one.

The Interface
-------------
The set of interface functions that define the DSI can be found in 
globus_gridftp_server.h.  All type definitions starting with 
globus_gfs_storage_*() are part of the DSI interface.

DSI utility API
---------------
An API is provided to the DSI author to assist in implementation.  The 
most interesting parts of this API provide functions that abstract away 
the details of sending data across the data channel. The DSI author is 
not expected to know the intimate details of the data channel protocols 
involved in a GridFTP transfer.  Instead this API provides functions for 
reading and writing data to and from the net.

Implementation
--------------
Here a brief description of part of the DSI implementation process is 
described.

A FTP session is defined from the time a client is authorized to use the 
server until the time the connection is disconnect (disconnect can 
happen due to the client sending QUIT, error, or timeout, etc).  In the 
lifetime of the session the client issues various commands to the FTP 
server.  Some of these commands require access to the storage system, 
and thus require action by the DSI. Whenever such a command is received 
the server calls out to the appropriate DSI interface function 
requesting that the specific operation be performed.

The server passes a globus_gfs_operation_t data type as a parameter to 
all DSI request functions.  When the DSI is finished performing that 
operation it calls a corresponding 
globus_gridftp_server_finished_<type>() function passing it this 
globus_gfs_operation_t structure (and whatever other data is needed for 
the any given operation).  This lets the server know that the operation 
is completed and it can respond to the client appropriately.

As an example we will look at how a simple unix file system DSI would 
implement the stat function.

The DSI's function signature for stat is:

void
(*globus_gfs_storage_stat_t)(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg);

When it is called the DSI is expected to determine all information 
associated with the path: stat_info->pathname fill in a 
globus_gfs_stat_t with that information and then call 
globus_gridftp_server_finished_stat() with that structure

static
void
globus_gfs_storage_example_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    globus_gfs_stat_t                   stat_out;
    struct stat                         stat_in;

    stat(stat_info->pathname, &stat_in);

    stat_out.mode     = stat_in.st_mode;
    stat_out.nlink    = stat_in.st_nlink;
    stat_out.uid      = stat_in.st_uid;
    stat_out.gid      = stat_in.st_gid;
    stat_out.size     = stat_in.st_size;
    stat_out.mtime    = stat_in.st_mtime;
    stat_out.atime    = stat_in.st_atime;
    stat_out.ctime    = stat_in.st_ctime;
    stat_out.dev      = stat_in.st_dev;
    stat_out.ino      = stat_in.st_ino;

    stat_out.name = strdup(stat_info->pathname);

    globus_gridftp_server_finished_stat(op, GLOBUS_SUCCESS, &stat_out, 1);
}

This is obviously a very basic example but it should serve for the purposes of
understanding.

=======================================================================
-----------------------------------------------------------------------
=======================================================================

=========
DSI Bones
=========

Every DSI must register itself with the Globus extensions module 
properly.  This can be a tedious task yet must be done properly. For 
this reason we created distribution that provides a skeleton DSI upon 
which a developer can build. The distribution includes a script to 
generate C stubs for a DSI with all of the proper shared library hooks 
and names needed to work with the globus-gridftp-server. The DSI 
implementor must fill in the stubbed out functions with the necessary 
code specific to their needs.


% ./generate-stubs.sh <dsi name> <flavor>

This command will generate the c source file.  "dsi name" is the string 
that will be associated with the DSI.  It must be unique to your Globus 
installation.  To load it into the server use the -dsi <dsi name> option 
to the server.

% make

This will compile the dsi and create the dynamically loadable library. 
To include additional compile dependencies or libraries open 'Makefile' 
and add them to the appropriate MACRO line.

% make install

This will copy the library to $GLOBUS_LOCATION/lib, thereby making it 
ready for use.

