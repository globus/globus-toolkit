<?php
$title = "Globus XIO User API Quick Start Guide";
include_once( "/mcs/www-unix.globus.org/include/globus_header.inc" );
?>
<BODY>
    <IMG SRC="globus_top.gif"><br>
    <IMG SRC="globus.gif"><br>
    <IMG SRC="globus_bottom.gif"><br>
    <H2>Globus XIO User API Quick Start</H2>
    <P>
    <h3><a name="Introduction">Introduction</a></h3>
This Guide explains how to use the Globus XIO API for IO operations within 
C programs.  Since Globus XIO is a simple API it is pretty straight 
forward.  The best way to become familiar with it is by looking at an example.
See <A HREF="globus_xio_example.c">globus_xio_example.c</A>

    <h3><a name="ActivateGlobus">Activate Globus</a></h3>
<BR>
Lets examine the case where a user wishes to use globus xio for reading data
from a file.  As in all globus programs the first thing that must be done is
to activate the globus module.  Until activated no globus_xio function
calls can be successfully executed.  It is activated with the following line:
</P>

<PRE>
    globus_module_activate(GLOBUS_XIO_MODULE);
</PRE>

    <h3><a name="LoadDriver">Load Driver</a></h3>
<P>
The next step is to load all the drivers needed to complete the IO operations
in which you are interested.  The function globus_xio_load_driver() is
used to load a driver.  In order to successfully call this function you must
know the name of all the drivers you wish to load.  For this example we only 
want to load the file io driver.  The prepackaged file io drivers name is:
"file".  This driver would be loaded with the following
code:

<PRE>
    globus_result_t                     res;
    globus_xio_driver_t                 driver;

    res = globus_xio_driver_load(&amp;driver, "file");
</PRE>

If upon completion of the above function call res == GLOBUS_SUCCESS then
the driver was successfully loaded and can be referenced with the variable
"driver".  
<BR>
    <h3><a name="CreateStack">Create Stack</a></h3>
Now that globus_xio is activated and we have a driver load we need to build
a driver stack.  In our example the stack is very simple as it consists of
only 1 driver, the file driver.  For more info on the stack see <A HREF="">
</A>.  The stack is established with the following code (building off of the
above code snips):
<PRE>
    globus_xio_stack_t              stack;
    
    globus_xio_stack_init(&amp;stack);
    globus_xio_stack_push_driver(stack, driver);

</PRE>
<h3><a name="OpeningHandle">Opening Handle</a></h3>
<P>
Now that the stack is created we can open a handle to the file.  There are two
ways that a handle can be opened.  The first is a passive open.  An example
of this is a TCP listener.  The open is performed passively by waiting
for some other entity to act upon it.  The second is an active open.  An 
active open is the opposite of a passive open.  The TCP counter example for
this is a connect.  The users initiates the open.  In our example we shall
be performing an active open.
<BR>
Before opening a handle it must be intialized.  The following illustrates
initialization for client side handles:
</P>
<PRE>
    globus_xio_handle_t             handle;

    res = globus_xio_handle_create(&amp;handle, stack);
</PRE>
<P> 
Server side handles are a bit more complicated.  First we must 
introduce the data structure globus_xio_server_t.  This structure 
shares many concepts with a TCP listener, mainly that it spawns handles
("connections") as passive open requests are made.  If the user wishes
to accept a new connection a call to globus_xio_accept() or 
globus_xio_register_accept() will initialize a new handle:
</P>
<PRE>

    globus_xio_server_t         server;
    globus_xio_handle_t         handle;
    globus_result_t             res;

    res = globus_xio_server_create(&amp;server_handle, NULL, stack);
    res = globus_xio_server_accept(&amp;handle, server);

</PRE>
<P>
Once the handle is initialized should be open in order to perform
read and write operations upon it.  It the handle is a client then
a "contact string" is required.  This  string represents the target that
the user wishes to open:
<PRE>
    globus_xio_attr_t           attr;
    char *                      contact_string = "file:/etc/groups";

    globus_xio_attr_init(&amp;attr);
    globus_xio_open(xio_handle, contact_string, attr);
    globus_xio_attr_destroy(attr);
</PRE>
<P> note: attrs can be used to color behaviors of a handle.  For 
conceptual undertanding at this point they are not important and a user 
is free to simple pass NULL where ever and attr is required.
</P>
<BR>
Now that we have an open handle to a file we can read or write data to it
with either globus_xio_read() or globus_xio_write().  Once we are finished
performing IO operations on the handle globus_xio_close(handle) should be
called.
<BR>
<h3><a name="PayOff">Pay Off</a></h3>
This may seem like quite a bit of effort for simple reading a file, and it is.
However the advantages become clear when exploring the swapping of other 
drivers.  In the above example it would be trivial to change the io operations
from file IO to TCP, or HTTP, or ftp.  All the the user would need to do is 
change the driver name string passed to globus_xio_load_driver() and the 
contact string passed to globus_xio_target_init().  This can easily be done
at runtime as the program <A HREF="globus_xio_example.c">globus_xio_example.c
</A> demonstrates.
<BR>
<P>
So the little program <A HREF="globus_xio_example.c">globus_xio_example.c</A>
has the ability to be any reading client, or server, (HTTP, ftp, TCP, file, 
etc) as long as the proper drivers are in the LD_LIBRARY_PATH.  Not bad eh?
</P>
</BODY>
<?php include("/mcs/www-unix.globus.org/include/globus_footer.inc"); ?>



