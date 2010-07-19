GFork
=====

Introduction
------------

GFork is user configurable super-server daemon very similar to xinetd. 
It listens on a TCP port.  When clients connect to a port it runs an 
administrator defined program which services that client connection, 
just as x/inetd do.

An unfortunate drawback to x/inetd is that there is no way to maintain 
or share long term information.  Every time a client connects a new 
process is create, and every time that client disconnects the process is 
destroyed.  All of the information regarding the specific interactions 
with a given client is lost with these transient processes.  A further 
disadvantage is that there is no way for these service instances to 
share service specific information with each other while they are 
running.

There are times when it is useful for a service to maintain long term 
service specific state, or for a service to share state across client 
connection.  GFork is designed to address this situation.  GFork runs a 
long term master program (that is user defined) and forms communication 
links, via UNIX pipes, between this process and all client connection 
child processes.  This allows long term state to be maintained in 
memory, and allows for communication between all nodes.

Associated with a GFork instance is a master process.  When GFork starts 
if runs a user defined master program and opens up bi-directional pipes 
to it.  The master program runs for the lifetime of the GFork daemon. 
The master is free to do whatever it wants.  It is a user defined 
program. Some master programs listen on alternative TCP connections to 
have state remotely injected.  Others monitor system resources like 
memory in order to best share resources. As clients connect to the TCP 
listener, child processes are forked which service the client 
connection.  Bi-direction pipes are opened up to the child process as 
well.  These pipes allow for communication between the master program 
and all child processes.  The master program and the child program have 
there own protocol for information exchange over these links.  GFork is 
just a framework for safely and quickly creating these links.

Use Cases
---------

The creation of GFork was motivated by the Globus GridFTP server.  
GridFTP can be run as a striped server where there is a frontend and 
several back ends.  The backends run in tandem to transfer files faster 
by tieing together many NICs.  The frontend is the contact point for the 
client where transfer requests are made.  When the frontend is run out 
of inetd the list of possible backends had to be statically configured. 
Unfortunately backends tend to come and go.  Sometimes backends fail, 
and sometimes backends are added to a pool.  We needed a way to have a 
dynamic pool of backends for use in live transfers.  To accomplish this 
we created GFork.

Configuration
-------------

GFork uses the same file configuration as xinetd with some additional 
options.  Here is an example GFork configuration file:

  service gridftp2
  {
    instances = 100
    env += GLOBUS_LOCATION=/home/bresnaha/Dev/Globus-gfork3/GL
    env += LD_LIBRARY_PATH=/home/bresnaha/Dev/Globus-gfork3/GL/lib
    server = /home/bresnaha/Dev/Globus-gfork3/GL/sbin/globus-gridftp-server
    server_args = -i -aa
    server_args += -d ALL -l /home/bresnaha/tst.log
    server_args += -dsi remote -repo-count 1
    nice = 10
    port = 5000
    master = /home/bresnaha/Dev/Globus-gfork3/GL/libexec/gfs-gfork-master
    master_args = -port 6065 -l /home/bresnaha/master.log -G n
    master_args += -dn /home/bresnaha/master_gridmap
  }


All of the options in the configuration file, other than the last 2, are 
identical to those found in xinetd.  The last two relate to the master 
program.  They work in the same way that 'server' and 'server_args' do.

A major difference between GFork configuration and xinetd is that GFork 
only runs one service per instance, where xinetd runs many per instance 
all associated with many different ports.  GFork takes a single 
configuration file and handles a single service.

If there is demand GFork will be enhanced to handle many services in the 
way that xinetd does.





