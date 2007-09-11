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
servers.  Users can connect to gwtftp with their favorite standard FTP
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

Userspace
---------
The quickest way to get gwtftp running is by starting in your own user
account.  First you must activate your GSI credential with grid-proxy-init.
More information can be found on obtaining GSI credentials at:


    http://www.globus.org/toolkit/docs/3.2/gsi/developer/certificates.html
    http://www-unix.globus.org/toolkit/docs/3.2/gsi/key/index.html
    http://www-unix.globus.org/toolkit/docs/3.2/gsi/user/gridproxyinit.html

Once you have an active proxy run gwtftp:

% gwtftp -p 5000

At this point you can connect to it using the FTP protocol on port
5000 and it will allow you to connect to gridftp servers using your 
gsi credentials.  Take the program 'ftp' for example:

    % localhost 5000
    Connected to localhost.
    220 FTP2GRID
    Name (localhost:bresnaha): gsiftp://wiggum.mcs.anl.gov:2811/
    331 Please specify the password.
    Password:
    230 User bresnaha logged in.
    Remote system type is UNIX.
    Using binary mode to transfer files.
    ftp> 

Notice the the username was 'gsiftp://wiggum.mcs.anl.gov:2811/'.  This
shows how the client connects to gwtftp and tells it where it wants
to ultimately go.

Daemon
------
gwtftp can be used as a service daemon as well.  If run as root on a unix
based machine with the -S flag, it can be used to service many clients.  
Client connected and authenticate with it via the clear text RFC959
protocol (thus it should be run only on trusted networks).  Once authenitcated
the daemon will fork/setuid/exec a new process running as the auntenticated
user.  Note: the user must have an active proxy in their environment in
order to use GSI with the final enpoint gridftp server.


Security Concerns
-----------------
It is highly recommended that security options are enabled when running 
the gwtftp.  When run as shown above the entire network can connect to
your gwtftp proxy and use your credentials.  This is bad.  To secure things
we provide two security options:

    password authentication
    -----------------------
    By using the -pw or --pwfile option you can have standard RFC959 FTP
    authentication with gwtftp.  The program gridftp-password.pl (which 
    comes with the globus-gridftp-server) will help create a proper
    password file.  Simple run:

    % gridftp-password.pl > ~/pwfile
    Password: 

    You will be prompted for a password and the entry will be created in
    the file ~/pwfile.  To use this password against your user run gwtftp
    as follows:

    % gwtftp -p 5000 -pw ~/pwfile

    Now when connecting to port 5000 the client must provide the right
    password in order to make use of you GSI credentials.  Since FTP 
    RFC959 sends passwords in clear text it is highly recommended that 
    connections are only formed to gwtftp proxies on secure networks,
    or better yet via the loopback interface.

    host authentication
    -------------------
    Run gwtftp with the -ah or --authorized-hosts option and provide it with a
    comma separated list of authorized IP masks.  With this option you can
    limit what hosts can freely connect to your gwtftp proxy.  We recommend
    that this is used with the -pw option, or only when limiting to
    the localhost (127.0.0.1) when the user is in complete control of
    the localhost in question.


Supported Platforms
-------------------
gwtftp can only be run on operating systems that are supported by 
globus-gridftp, this includes most flavors of UNIX.  Note: *ANY* 
end user client running on any system can connect to a gwtftp proxy.
As an example, gwtftp can be run on an organizations Linux server
and internal clients can connect to it from windows desktop machines,
thereby easily allowing windows machines to interact with GridFTP
servers everywhere.



