<?php
$title = "Globus XIO Driver Quick Start Guide";
include_once( "/mcs/www-unix.globus.org/include/globus_header.inc" );
?>

<BODY>
    <H1>Globus XIO Driver Quick Start Guide</H1>

    <H2><a name="Contents">Contents</a></H2>
    <a href="#DataStructures">Data Structures</a><br>
    <a href="#Attributes">Attributes</a><br>
    <a href="#Target">Target</a><br>
    <a href="#Handle">Handle</a><br>
    <a href="#IO_Op">IO Operations</a><br>
    <a href="#The_Glue">The Glue</a><br>

    <P>
    <H2><a name="Introduction">Introduction</a></H2>
This Guide explains how to create a transport driver for Globus XIO.
For the purpose of exploring both what a transform driver is and how to
write one this guide will walk through an example driver.  The full source
code for the driver can be found at  
<A HREF="globus_xio_file_driver.c">globus_xio_file_driver.c</A>.  This example
implements a file driver for globus_xio.  If a user of globus_xio were to
put this file at the bottom of the stack they could access files on the 
local file system.

    <H2><a name="DataStructures">Data Structures</a></H2>
<P>
There are three data structures that will be explored in this example:
attribute, target, and handle.  The driver defines the memory layout of
these data structures but the globus_xio framework imposes certain 
semantics upon them.  It is up to the driver how to use them, but globus_xio
will be expecting certain behaviors.
</P>
    <H2><a name="Attributes">Attributes</a></H2>
<P>
Each driver may have its own attribute structure.  The attribute gives
the globus_xio user API an opportunity to tweak parameters inside the 
driver.  The single attribute structure is used for all possible driver 
specific attributes:
</P>
<OL>
    <LI>Target attributes</LI>
    <LI>Handle attributes</LI>
    <LI>Server attributes</LI>
</OL>
<P>
How each of these can use the attribute structure will be unveiled as the
tutorial continues.  For now it is simply important to remember there is
attribute structure used to initiate of the driver ADTs.
<BR>
A driver is not required to have an attribute support at all.  However if the 
driver author chooses to support attributes the following functions must
be implemented:
<PRE>
typedef globus_result_t
(*globus_xio_driver_attr_init_t)(
    void **                                     out_attr);

typedef globus_result_t
(*globus_xio_driver_attr_cntl_t)(
    void *                                      attr,
    int                                         cmd,
    va_list                                     ap);

typedef globus_result_t
(*globus_xio_driver_attr_copy_t)(
    void **                                     dst,
    void *                                      src);

typedef globus_result_t
(*globus_xio_driver_attr_destroy_t)(
    void *                                      attr);

[see driver api doc for more information]
</PRE>
<P>
We shall now take our first look at the file driver example.  The file driver
needs a way to provide the user level programmer with a means of setting
the mode and flags when a file is open (akin to the POSIX function open()).
The first step in creating this ability is to define the attribute structure
and implement the globus_xio_driver_attr_init_t function which will initialize
it.
</P>

<PRE>
/*
 *  attribute structure 
 */ 
struct globus_l_xio_file_attr_s
{
    int                                         mode;
    int                                         flags;
}

globus_result_t
globus_xio_driver_file_attr_init(
    void **                                     out_attr)
{
    struct globus_l_xio_file_attr_s *           file_attr;
    
    /*
     *  create a file attr structure and initialize its values
     */
    file_attr = (struct globus_l_xio_file_attr_s *)
        globus_malloc(sizeof(struct globus_l_xio_file_attr_s));

    file_attr->flags = O_CREAT;
    file_attr->mode = S_IRWXU;

    /* set the out parameter to the driver attr */
    *out_attr = file_attr;

    return GLOBUS_SUCCESS;
}
</PRE>

<P>
The above simply defines a structure that can hold two integers, mode and 
flags, then defines a function the will allocate and initialize this 
structure.  
<BR>
globus_xio hides much of the memory management of these attribute structures
from the driver.  However it does need the driver to provide a means of
coping them, and free all resources associated with them.  In the case 
of the file driver example these are both simple.
</P>
<PRE>
globus_result_t
globus_xio_driver_file_attr_copy(
    void **                                     dst,
    void *                                      src)
{
    struct globus_l_xio_file_attr_s *           file_attr;

    file_attr = (struct globus_l_xio_file_attr_s *)
        globus_malloc(sizeof(struct globus_l_xio_file_attr_s));

    memcpy(file_attr, src, sizeof(struct globus_l_xio_file_attr_s));
    
    *dst = file_attr;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_attr_destroy(
    void *                                      attr)
{
    globus_free(attr);
    
    return GLOBUS_SUCCESS;
}
</PRE>
<P>
The above code should be fairly clear.
<BR>
Obviously a method upon which the user can set flags and mode is needed.
This is accomplished with the following interface function:
</P>
<PRE>
globus_result_t
globus_xio_driver_file_attr_cntl(
    void *                                      attr,
    int                                         cmd,
    va_list                                     ap)
{   
    struct globus_l_xio_file_attr_s *           file_attr;
    int *                                       out_i;
    
    file_attr = (struct globus_l_xio_file_attr_s *)attr;
    switch(cmd) 
    {
        case GLOBUS_XIO_FILE_SET_MODE:
            file_attr->mode = va_arg(ap, int);
            break;

        case GLOBUS_XIO_FILE_GET_MODE:
            out_i = va_arg(ap, int *);
            *out_i = file_attr->mode;
            break; 

        case GLOBUS_XIO_FILE_SET_FLAGS:
            file_attr->flags = va_arg(ap, int);
            break;

        case GLOBUS_XIO_FILE_GET_FLAGS:
            out_i = va_arg(ap, int *);
            *out_i = file_attr->flags;
            break;

        default:
            return FILE_DRIVER_ERROR_COMMAND_NOT_FOUND;
            break;
    }

    return GLOBUS_SUCCESS;
}
</PRE>
<P>
This function is called passing the driver an initialized file_attr structure,
a command, and a variable argument list.  Based on the value of cmd the
driver decides either to set flags or mode from the va_args, or to return
flags or mode to the user via a pointer in va_args.
</P>

    <H2><a name="Target">Target</a></H2>
<P>
A target structure represents what a driver will open and is initialized from
a contact string and an attribute.  In the case of a file driver the target
simply holds onto the contact string as a path to the file.  The file
driver implements the following target functions:
</P>
<PRE>
globus_result_t
globus_xio_driver_file_target_init(
    void **                                     out_target,
    void *                                      target_attr,
    const char *                                contact_string,
    globus_xio_driver_stack_t                   stack)
{
    struct globus_l_xio_file_target_s *         target;

    /* create the target structure and copy the contact string into it */
    target = (struct globus_l_xio_file_target_s *)
                globus_malloc(sizeof(struct globus_l_xio_file_target_s));
    strncpy(target->pathname, contact_string, sizeof(target->pathname) - 1);
    target->pathname[sizeof(target->pathname) - 1] = '\0';

    return GLOBUS_SUCCESS;
}

/*
 *  destroy the target structure
 */
globus_result_t
globus_xio_driver_file_target_destroy(
    void *                                      target)
{
    globus_free(target);

    return GLOBUS_SUCCESS;
}
</PRE>
<P>
The above function handle the creation and destruction of the file driver's
target structure.  Note that when the target is created the contact string
is copied into it.  It is invalid to just copy the pointer to the contact
string.  As soon as this interface function returns that pointer is no
longer valid.
</P>

    <H2><a name="Handle">Handle</a></H2>
<P>
The most interesting of the 3 data types discussed here is the handle.
Upon the handle all typical IO operations (open close read write) are
performed.  The handle is the initialized form of the target and an attr.  The
driver developer should use this ADT to keep track of any state information
they will need in order to perform reads and writes.  In the example case
the driver handle is fairly simple as the driver is merely a wrapper around
POSIX calls.

<PRE>
struct globus_l_xio_file_handle_s
{
    int                                         fd;
};
</PRE>

The reader should review 
globus_xio_driver_file_open() globus_xio_driver_file_write()
globus_xio_driver_file_read() globus_xio_driver_file_close() in 
<A HREF="globus_xio_file_driver.c"> globus_xio_file_driver.c</A> in order 
to see how the handle structure is used.
</P>
    <H2><a name="IO_Op">IO Operations</a></H2>
<P>
The read and write interface functions are called in response to a user read or
write request.  Both functions are provided with a vector that, at the least, has the
same members as the 'struct iovec' and a vector length.  As of now, the iovec
elements may contain extra members, so if you wish to use readv() or writev(), you
will have to transfer the iov_base and iov_len members to the POSIX iovec.
</p>
<p>
As with the open and close interface functions, if an error occurs before any
real processing has occurred, the interface function may simply return the error
(in a result_t), effectively canceling the operation.  However, once bytes have
been read or written, you must not return the error.  You have to report the 
number of bytes read/written along with the result.
</p>
<p>
When an operation is done, either by error or successful completion, the operation
must be 'finished'.  To do this, a call must be made to :
</p>
<pre>
globus_result_t
globus_xio_driver_finished_read/write(
  globus_xio_driver_operation_t         op, 
  globus_result_t                       res, 
  globus_ssize_t                        nbytes);
</pre>
---

<h4>Blocking vs Non-blocking calls.</h4>
<p>
In general, the driver developer does not need to concern himself with how the
user made the call.  Whether it was a blocking or an asynchronous call, xio will
handle things correctly.  Should the driver wish to optimize things for the type
of request, he can query the type with:
</p>
<pre>
globus_bool_t
GlobusXIODriverOperationIsBlocking(
  globus_xio_driver_operation_t         op);
</pre>
<p>
However the call was made, the driver developer can call 
globus_xio_driver_finished_{open, read, write, close} either while in the 
original interface call, in a separate thread, or in a separate callback kick out
via the globus_callback API.
</p>
    <H2><a name="The_Glue">The Glue</a></H2>
<p>
Through a process not finalized yet, xio will request the globus_xio_driver_t
structure from the driver.  This structure defines all of the interface functions
that the driver supports.  In detail:
</p>
<pre>
    /*
     *  main io interface functions
     */
    globus_xio_driver_open_t                            open_func;
    globus_xio_driver_close_t                           close_func;
    globus_xio_driver_read_t                            read_func;
    globus_xio_driver_write_t                           write_func;
    globus_xio_driver_handle_cntl_t                     handle_cntl_func;

    globus_xio_driver_target_init_t                     target_init_func;
    globus_xio_driver_target_destroy_t                  target_destroy_finc;

    /*
     * target init functions.  Must have client or server
     */
    globus_xio_driver_server_init_t                     server_init_func;
    globus_xio_driver_server_accept_t                   server_accept_func;
    globus_xio_driver_server_destroy_t                  server_destroy_func;
    globus_xio_driver_server_cntl_t                     server_cntl_func;

    /*
     *  driver attr functions.  All or none may be NULL
     */
    globus_xio_driver_attr_init_t                       attr_init_func;
    globus_xio_driver_attr_copy_t                       attr_copy_func;
    globus_xio_driver_attr_cntl_t                       attr_cntl_func;
    globus_xio_driver_attr_destroy_t                    attr_destroy_func;
    
    /*
     *  data descriptor functions.  All or none
     */
    globus_xio_driver_data_descriptor_init_t            dd_init;  
    globus_xio_driver_driver_data_descriptor_copy_t     dd_copy;
    globus_xio_driver_driver_data_descriptor_destroy_t  dd_destroy;
    globus_xio_driver_driver_data_descriptor_cntl_t     dd_cntl;
</pre>

</BODY>

<?php include("/mcs/www-unix.globus.org/include/globus_footer.inc"); ?>
