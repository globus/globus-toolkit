<?php
$title = "Globus XIO Introduction";
include_once( "/mcs/www-unix.globus.org/include/globus_header.inc" );
?>
        <CENTER><B><H1> Globus XIO</H1></B></CENTER>
            <P>Globus XIO is an extensible input/output library for the Globus
            Toolkit (tm).  It provides a simple and intuitive API 
            (open/close/read/write) to swappable IO implementations.
            <BR>
            <h2>Globus XIO has 2 main goals:</h2>
            <UL>
                <LI><B>Provide a single user API to all Grid IO Protocols.</B>
                <BR><BR>
                In Distributed programming there are many protocols used for 
                message passing.  There are typically many different APIs for
                using all the different protocols, despite the fact that they
                have the same end goal, moving bytes from end point to end point.
                application developers are forced to code straight to a protocols 
                API.  Therefore if they ever want to change 
                the underlying protocol they originally selected, then they have 
                to change the applications source code to utilize an entirely new API.
                Even subtle differences in the API can cause this to be a 
                difficult task.  This adds to the already  complicated task of 
                keeping up the technology curve. Globus XIO provides a single API
                to any wire protocol.  The API has a very common look and
                feel making it very intuitive to use.  As new protocols are developed 
                they can be added to Globus XIO in the form of "drivers".  A driver
                is completely hidden behind Globus XIO so when new ones are used
                it is transparent to the application developer.  Therefore an
                application programmer can code to the globus_xio user API once
                and then focus on the applications needs throughout its life cycle.
                If a in few years down the line they want the same application
                to work with the latest and greatest protocol for shipping bytes
                around the grid, they do not have to change a line of source code.
                </LI>
                <BR><BR>
                <LI><B>Minimize the development time for creating/prototyping new protocols.</B>
                <BR><BR>
                In grid computing research is done into how to push bytes faster
                and faster around the grid.  Proof of concept is an important
                part of this research.  A problem that often comes up is the 
                time it takes to both design and implement new protocols.
                <BR><BR>
                Globus XIO addressed these issues.  Globus XIO provides a driver
                development interface that allows a developer to concentrate
                on writing code to implement the protocol.  It takes the headache
                of error checking, asynchronous message delivery, timeouts and other
                important issues out of the protocol implementors path.
                <BR><BR>
                Also it allows for a maximum reuse of code with the notion of a 
                driver stack.  Each driver should be one atomic unit that can be
                mixed and matched with other drivers.  For example: GSI security
                can be written once as a driver then stacked on top of TCP, NETBLT
                UDP blast, or any other transport protocol.  This makes it much
                easier to develop the transport protocols, since the only focus
                on the developer are the details of the protocol they are creating.
            </UL>

<?php include("/mcs/www-unix.globus.org/include/globus_footer.inc"); ?>
