GridFTP Multicast
=================

GridFTP is a well known, extremely fast and efficient protocol for 
transferring data from one destination to another.  Here we present how 
GridFTP can be used to transfer a single file to many destinations in a 
multicast/broadcast.

globus-url-copy (Quick start)
-----------------------------
The broadcast functionality can be used with globus-url-copy.  We added
the following option:

-mc <filename>

The file must contain a line separated list of destination urls.  For example:

    gsiftp://localhost:5000/home/user/tst1
    gsiftp://localhost:5000/home/user/tst2
    gsiftp://localhost:5000/home/user/tst4

The source url is specified on the command line as always.  A single 
destination url may also be specified on the command line in addition to 
the urls in the file.  An example globus-url-copy command is:

    % globus-url-copy -MC multicast.file gsiftp://localhost/home/user/src_file 

or 

    % globus-url-copy -MC multicast.file gsiftp://localhost/home/user/src_file gsiftp://localhost/home/user/dest_file1


General Architecture
-------------------

The purpose of this work is to efficiently transfer a single data set to 
many locations.  It would be quite simple, yet slow, to simply have the 
client loop over many urls sending the same file to each, but our goal 
is to maximize the usage of all available network cycles to every 
destination.

The client makes a connection with the first destination and forwards to 
it all remaining destination urls.  The first destination removes N urls 
from this list and forms a connection to each one. It then divides the 
remaining urls in the list into N sublists (where N is provided by the 
client) and forwards one subset to each of the N connections.  The 
process continues in a recurse fashion until a spanning tree is formed.

Data is sent from the source to the root destination.  The root 
destination forwards the data to all of its children on a block by block 
basis It proceeds down the tree until all nodes have received the data.  
Forwarding on a block level allows for significantly shorter transfer 
time over forwarding on a file by file basis.

Globus XIO
----------

Because the globus-gridftp-server uses Globus XIO for all of its IO we 
are able to forward data at the block level.  We achieve this by 
allowing the client to add a new xio driver, the gridftp_multicast 
driver, to the gridftp servers disk stack.  Because of the modular 
driver abstraction that Globus XIO provides as the gridftp server writes 
data blocks to its file system the data blocks are first passed through 
the gridftp_multicast driver.  As the gridftp_multicast driver passes 
the data block on to be written to disk, it also forwards the block on 
to other gridftp servers in the tree.

Using this approach to add the multicast functionality is minimally 
invasive to the tested and robust gridftp server and is entirely 
modular.  The driver is written to a well defined and clean abstraction.  
Enabling this feature is a simple matter of inserting the driver in the 
disk stack.

For security reasons the GridFTP server does not allow clients to load 
arbitrary xio drivers into the server.  The GridFTP server admin must 
whitelist the driver individually.  White-listing the gridftp_multicast 
driver is done with the following parameter to the server:

    -fs-whitelist file,gridftp_multicast

Notice that "file" must also be specified.  Without this option the 
"file" driver is the default.  However, if used you must specifically 
list it.

Advanced globus-url-copy Options
--------------------------------

Along with specifying the list of destination urls, a set of options for 
each url can be specified.  This is done appending a ? to the resource 
string in the url and following the ? with a ; separated key value 
pair.  For example:

    gsiftp://dst1.domain.com:5000/home/user/tst1?cc=1;tcpbs=10M;P=4

This indicates that the receiving host "dst1.domain.com" will use 4 
parallel stream, a tcp buffer size of 10 megabytes, and will select 1 
host when forwarding on data blocks.  This url is specified in the -mc 
file as described above.

The following is a list of key=value options and their meanings:

    P=<int>
        -- # of parallel streams this node will use when forwarding
    cc=<int>
        -- the number of urls to which this node will forward data to.
    tcpbs=<formated int>
        -- The TCP buffer size this node will use when forwarding.
    urls=<string list>
        -- the list of urls that must be children of this node when
            the spanning tree is complete
    local_write=<bool: y|n>
        -- determines if this data will be written to a local disk, or
            just forwarded on to the next hop.  This is explained more
            in the 'Network Overlay' section.
    subject=<string>
        -- The DN name to expect from the servers this node is connecting to.


Protocol
--------

The additions to the protocol are exceptionally minor.  Every server in 
the tree (except for leaf nodes) becomes a client to another server, but 
that client speaks the standard gridftp protocol.  The only change 
needed is a command to add the driver to the file system stack, and that 
command has existed in the gridftp server for sometime.

The command is:

SITE SETDISKSTACK 1*{<driver name>[:<driver options>]},

The second parameter to the site command is a comma separated list 
of driver names optionally followed by a : and a set of driver specific 
url encoded options.  From left to right the driver names form a stack 
from bottom to top.

Adding the gridftp_multicast driver to this list will enable the 
multicast functionality.  The set of options are the same as those 
specified in the previous section.  The only difference is that each url 
in the urls= options must be url encoded.


Network Overlay
---------------

In addition to allowing multicast, this function also allows for 
creating user defined network routes.  If the local_write options is set 
to 'n', then no data will be written to the local disk, the data will 
only be forwarded on.  If this option is coupled with the cc=1 option, 
the data will be forwarded on to exactly 1 location.  This allows the 
user to create a network overlay of data hops using each gridftp server 
as a router to the ultimate destination.

