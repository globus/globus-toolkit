<?php
$title = "Globus XIO Features";
include_once( "/mcs/www-unix.globus.org/include/globus_header.inc" );
?>

    <body>
        <CENTER><B><H1>Globus XIO</H1></B></CENTER>

        Globus XIO is a feature rich runtime system.  One of its two main goals
        is to provide the application developer with a simple easy to use API.
        Part of meeting this goal is providing them all the built in features 
        they need.  A library is hardly easy to use if its users have to write 
        most of the needed functionality themselves.
        <BR>
        <BR>
        <B>Globus XIO features.</B>
        <UL>
            <LI>
            <B>Simple API</B><BR><BR>
            Globus XIO provides a simple API for all the basic functionality.  To
            find Globus XIO useful, a user need only be familiar with open, close
            read and write.
            </LI><BR>
            <LI>
            <B>Extensibility with drivers</B><BR><BR>
            Globus XIO is designed to be extended.  The library provides hooks
            for future protocols to be added to it.
            </LI><BR>
            <LI>
            <B>Efficiency</B><BR><BR>
            Globus XIO has been designed to be a very efficient system.  If a 
            users only need is for a highly optimized efficient io library
            then Globus XIO is a good choice.
            </LI><BR>
            <LI>
            <B>Timeouts</B><BR><BR>
            Built into the the library are IO timeouts.  This is a convenience to
            the user in that they do not have to set their own alarms to determine
            if an io operation is taking to long.  With globus_xio they simply set
            a timeout value and they will be notified when if an operation has not
            progressed for the specified amount of time.
            </LI><BR>
            <LI>
            <B>Data Descriptors</B><BR><BR>
            Along with a buffer to be written or read Globus XIO allows the user
            to pass in meta data describing the buffer.  Also, after an IO operation
            has completed, Globus XIO returns a data descriptor to the user.  This
            allows for some interesting extensions.  In the future we hope
            to make it possible for a user to read from the protocol stack and pass
            the buffer and data descriptor received to a write on a completely
            different protocol stack and have things automatically massaged and
            negotiated for compatibility.
            </LI>
        </UL>
    </body>
</html>
