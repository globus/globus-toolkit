<?php
$title = "Globus XIO Architecture";
include_once( "/mcs/www-unix.globus.org/include/globus_header.inc" );
?>

    <body>
        <CENTER><B><H1> Globus XIO Architecture</H1></B></CENTER>
        <BR>
        This document shall explain the external view of the Globus XIO
        architecture.  To see an explanation of the data types used to 
        implement the system see <A HREF="xio_i_arch.html">Internal arch</A>.
        Globus XIO is broken down into two main components, framework and
        drivers.  The following picture illustrates the architecture:
        <H2>figure 1</H2>
        <IMG SRC="xio_arch.jpg" width="25%">
        <H2>Globus XIO Framework</H2>
        <P>
        The Globus XIO framework manages io operation requests that an 
        application makes via the <A HREF="api/index.html">user API</A>
        The framework does no 
        work to deliver the data in an io operation nor does it manipulate 
        the data.  All of that work is done by the drivers.  The frameworks
        job is to manage requests and map them to the drivers interface.
        It is the drivers themselves that are responsible for manipulating
        and transporting the data.
        <BR>
        <H2>Drivers</H2>
        <P>
        A driver is the component of Globus XIO that is responsible for 
        manipulating and transporting the users data.  There are two types
        of drivers, transform and transport. Transform drivers are those that
        manipulate the data buffers passed to it via the user API and the
        XIO framework.  Transform drivers are those that are capable of
        sending the data over a wire.
        <BR><BR>
        Drivers are grouped into stacks, that is of course one driver on 
        top of another.  When an io operation is requested the Globus XIO
        framework passes the operation request to every driver in the order
        they are in the stack.  When the bottom level driver 
        (the transport driver) finishes shipping the data, it passes the
        data request back to the XIO framework.  Globus XIO will then
        deliver the request back up the stack in this manner until it
        reaches the top, at which point the application will be notified 
        that there request is completed.
        <BR><BR>
        In a driver stack there can only be one 
        transport driver.  The reason for this is simple. The transport
        driver is the one responsible for sending or receiving the data.
        Once this type of operation is performed it makes no sense to 
        pass the request down the stack, the data has just been transfered.
        It is now time to pass the operation back up the stack.
        <BR><BR>
        There can be many transform drivers in any given driver stack.
        A transform driver is one that can manipulate the requested operations
        as they pass.  Some good examples of transport drivers are security
        wrappers and compression.  However a transport driver can also be one 
        that adds additional protocol.  For example a stack could consist of
        a TCP transport driver and an HTTP transform driver.  The HTTP driver 
        would be responsible for marshaling the HTTP protocol and the TCP
        driver would be responsible for shipping that protocol over the wire.
        </P>
        <H2>Example</H2>
        <P>
        In the following picture we illustrate a user application using Globus
        XIO to speak the GridFTP protocol across a TCP connection:
        </P>
        <IMG SRC="xio_app.jpg" width="25%">
        <P>
        The user has built a stack consisting of one transform driver and
        one transport driver.  TCP is the transport driver in this stack, and
        as all transport modules must be, it is at the bottom of the stack.
        Above TCP is the GSI transform driver which performs necessary
        messaging to authenticate a user and the integrity of the data..
        <BR><BR>
        The first thing the user application will do after building the 
        stack is call the XIO user API function globus_xio_open().  The globus
        xio framework will create internal data structures for tracking this
        operation and then pass the operation request to the GSI driver.
        The GSI driver has nothing to do before the underlying stack has
        opened a handle so it simply passes the request down the stack.
        The request is thereby passed to the TCP driver.  The TCP driver
        will then execute the socket level transport code contained within
        in to establish a connection to the given contact string.
        <BR><BR>
        Once the TCP connection has been established the TCP driver will
        notify the xio framework that it has completed its request and thereby
        the GSI driver will be notified that the open operation it had 
        previously passed down the stack has now completed.  At this point the
        GSI driver will start the authentication processes (note that at this
        point the user does not yet have an open handle).  The GSI driver
        has an open handle and upon it several sends and receives are 
        performed to authenticate the connection.  If the GSI driver is not
        satisfied with the authentication process it closes the handle it has
        to the stack below it and tells the XIO framework that it has completed
        the open request with an error.  If it is satisfied it simply tells
        the xio framework that it has completed the open operation.  The user
        is now notified that the open operation completed, and if it was
        successful they now have an open handle.
        <BR><BR>
        Other operations work in much the same way.  When a user posts a read
        the read request is first delivered to the GSI driver.  The GSI driver
        will wrap the buffer and pass the modified buffer down the stack.
        The framework will then deliver the write request with the newly
        modified buffer to the TCP driver.  The TCP driver will write the
        data across the socket mapped to this handle.  When it finishes it
        notifies the frame work, which notifies the GSI driver.  The GSI driver
        has nothing more to do so it notifies the framework that it is 
        complete and the framework then notifies the user.
        </P>
        <H2>Driver Interface</H2>
        <P>
        There is a well defined interface to a driver.  Drivers are modular
        components with specific tasks.  The purpose of drivers in the globus
        xio library is extensibility.  As more and more protocols are developed,
        more and more drivers can be written to implement these protocols.
        As new drivers are written they can be added to globus xio as either
        statically linked libraries or dynamically loaded library's.  In the
        case of dynamic loading it is not even necessary to recompile
        existing source code.  Each driver has a unique name according to 
        the globus XIO driver naming convention.  A program simply
        needs to be aware of this name (this can obviously be passed in 
        via the command line) and the globus xio framework will be responsible 
        for loading that driver.
        </P>
        <H2>Note:</H2>
        <P>
        The above example is simplified for the purposes of understanding.
        There are optimizations built into globus xio which alter the course
        of events outlined above.  However, conceptually the above is accurate.
        </P>
    </body>

<?php include("/mcs/www-unix.globus.org/include/globus_footer.inc"); ?>
