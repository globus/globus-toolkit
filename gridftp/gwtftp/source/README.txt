===============================================
          GridFTP Where There's FTP
-----------------------------------------------
A client proxy to translate from FTP to GridFTP
===============================================

Intro
-----
GridFTP is a fast robust protocol for data transfer on the Grid. It is
an extension of the standard FTP (RFC 959) protocol.  While it has
existed for some time now and has proven quite robust and usable, there
are few clients available that communicate with it. FTP-959 on the other
hand has an innumerable number of clients.

As an alternative to the insurmountable task of modifying each
and every FTP client, we have created an intermediate
program (gwtftp) to act as a proxy between existing FTP clients and GridFTP
servers.  Users can connect to gwtftp with their favortie standard FTP
client and gwtftp will then connect to a GridFTP server on the clients
behalf.

To clients gwtftp will look much like an FTP proxy server. When
wishing to contact a GridFTP server, FTP clients will contact gwtftp
instead. Clients tell gwtftp their ultimate destination via the
FTP USER <username> command.  Instead of entering in their username,
client users send the following:

    USER <gwtftp username>::<gridftp server url>

This command tells gwtftp the GridFTP endpoint with which the client 
wants communication.  An example would be:

    USER bresnaha::gsiftp://wiggum.mcs.anl.gov:2811/

or just

    USER gsiftp://wiggum.mcs.anl.gov:2811/

depending on how gwtftp is configured (this will be discussed later).
Once the session is established the rest of the commands should work
as they normally do.

--------
Building
--------
gwtftp is a standard gpt package.  It is built as all are.  More information
on building gpt packages can be found at:

    http://www.globus.org/toolkit/
    http://www.gridpackagingtools.com/

Most globus 4.1 or greater installations will have gwtftp built.

-------
Running 
-------
gwtftp can be run as a system daemon servicing many users, or it can
be run in user space to only service the user that started it.



gwtftp can only be run on operating systems that are supported by 
globus-gridftp, this includes most flavors of UNIX.  Note: *ANY* 
end user client running on any system can connect to a gwtftp proxy.
As an example, gwtftp can be run on an organizations linux server
and internal clients can connect to it from windows desktop machines,
thereby easily allowing windows machines to interact with GridFTP
servers everywhere.



