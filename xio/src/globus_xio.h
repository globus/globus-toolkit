#if !defined(GLOBUS_XIO_H)
#define GLOBUS_XIO_H

#include "globus_common.h"
#include "globus_xio_types.h"
#include "globus_xio_util.h"
#include "globus_xio_load.h"

/**
 * @mainpage Globus XIO
 *
 * The Globus eXtensible Input Output library.
 *
 * - @ref GLOBUS_XIO_API
 * - @ref GLOBUS_XIO_API_ASSIST 
 * - @ref drivers
 * - @ref driver_api
 * - @ref adv_drivers
 * - @ref dd_driver
 *
 */

/******************************************************************
 *                       target construction
 *****************************************************************/
/**
 *  @defgroup GLOBUS_XIO_API The globus_xio user api
 */
/**
 *  @defgroup GLOBUS_XIO_API_ASSIST User API Assistance.
 *  <BR>
 *  Help understanding the globus_xio api.
 *
 *  These pages should provide insight into the globus_xio user api.
 *  - @ref stack_setup
 *  - @ref target_setup
 *  - @ref handle_setup
 *  - @ref muttable_attrs
 *  - @ref timeouts
 *  - @ref dd_user
 *  - @ref signal_user
 *      
 */

/**
 * @page stack_setup Setting up a stack
 * 
 *  The driver stack that is used for a given xio handle is constructed
 *  using a globus_xio_stack_t.  Each driver is loaded by name or by library
 *  and pushed onto a stack.
 * 
 *  stack setup example:
 * 
 *  // First load the drivers
 *  globus_xio_driver_load("tcp", &tcp_driver);
 *  globus_xio_driver_load("gsi", &gsi_driver);
 * 
 *  //build the stack
 *  globus_xio_stack_init(&stack);
 *  globus_xio_stack_push_driver(stack, tcp_driver, NULL);
 *  globus_xio_stack_push_driver(stack, gsi_driver, NULL);
 */

/**
 *  @page target_setup Setting up a target
 *
 *  A target can be created for active or passive connections.  An active
 *  target is created with a contact string and a driver stack.  The contact
 *  string is intended for the transport layer (???  should have a generic form
 *  and maybe a method for communicating to multple layers?? should targets
 *  have target attrs?).  A passive target is given to the user by a server.
 *  examples of both follow:
 * 
 *  active target setup example:
 *
 *  globus_xio_target_init(&target, "localhost:80", GLOBUS_NULL, stack);
 *
 *  passive target setup example:
 * 
 *  globus_xio_server_attr_init(&server_attr);
 *  globus_xio_server_attr_cntl(server_attr, 
 *          tcp_driver,
 *          TCP_SERVER_ATTR_SET_PORT,
 *          80);
 *  globus_xio_server_init(&server, GLOBUS_NULL, stack);
 *  globus_xio_server_get_contact_string(server, &buf);
 *  globus_libc_fprintf(stdout, "serving at: %s.\n", buf);
 *  globus_xio_server_listen(server, &target);

 *    // build the stack
 *    globus_xio_target_attr_init(&target_attr);
 *    globus_xio_target_push_driver(
 *        target_attr, tcp_driver, tcp_target_attr);
 *    globus_xio_target_push_driver(
 *        target_attr, gsi_driver, GLOBUS_NULL);
 *    globus_xio_target_init(&target, target_attr);
 */

/**
 *  @page handle_setup Handle Construction
 *
 *  Handles are constructed from targets.  Many handles can be created
 *  from a single target.  The state of the target at the time of
 *  handle constructions partially determines the initial state of the
 *  handle.  The initial state is also deteremined of the attribute 
 *  it is created with.
 *
 *  A handle is not constructed until a user makes a call to 
 *  globus_xio_open().  handle_attrs are used to tweak attributes of
 *  the handle.  All imutable attributes must be set on the attr
 *  passed in to globus_xio_open().  Mutable attrs can be altered
 *  via a call to globus_xio_fcntl() described later.
 *
 *  attr ex:
 *
 *  globus_xio_handle_attr_init(&attr);
 *  globus_xio_handle_attr_cntl(attr, 
 *      NULL, 
 *      GLOBUS_XIO_HANDLE_ATTR_SET_MODE,
 *      O_WRONLY);
 *  globus_xio_handle_open(target, &handle, attr);
 */
/**
 *  @page timeouts Timeouts
 *
 *  A user can set a timeout value for any io operation.  Each IO 
 *  operation (open close read write) can have its own timeout value.
 *  If no timeout is set the opperation will be allowed to infinitly
 *  block.
 *
 *  When time expires the outistanding operation is canceled.  If the
 *  timeout callback for the given operation is not NULL it is called first to
 *  notify the user that the operation timed out and give the user a chance to
 *  ignore that timeout.  If canceled, the user will get the callback they 
 *  registered for the operation as well, but it will come with an error
 *  indicating that it has been canceled.
 *
 *  It is possiblie that part of an io operation will complete before
 *  the timeout expires.  In this case the opperation can still be 
 *  canceled.  The user will receive there IO callback with and 
 *  error set and the length value appropriately set to indicate how
 *  much of the operation completed.
 */
/**
 *  @page dd_user Data Desciptor
 *
 *  The data descriptor ADT gives the user a means of attaching/extracting
 *  meta data to a read or write opperation.
 *
 *  Things like offset, out of band message, and protocol used for delivery
 *  (reliable, unreliable, ordered, unorder, etc) are contained in the
 *  data descriptor.
 *
 *  Drivers can also implement functions to set driver specific meta
 *  data attributes on data_descriptors.  An example of driver specific data
 *  is out of band message for tcp.  The driver will provide its own
 *  set of functions for setting values in the data descriptor.
 *
 *  Data descriptors are passed to globus_xio in globus_xio_read() and 
 *  globus_xio_write().  Within the globus_xio framework
 *  it is acceptable to pass NULL instead of a valid data_descriptor,
 *  It is recomended to the driver author to allow for NULL data descriptors
 *  however it is not manditory.  A driver implementation may not accept NULL.
 *  The user needs to be aware of the protocol stack their handle has when
 *  passing a NULL data_descriptor value.
 *
 *
 *  ex:
 *  globus_xio_data_descriptor_init(&desc);
 *  globus_xio_data_descriptor_cntl(desc, 
 *      NULL, 
 *      GLOBUS_XIO_DATA_DESCRIPTOR_SET_OFFSET, 
 *      1024);
 *  globus_xio_data_descriptor_cntl(desc, 
 *      tcp_driver,
 *      GLOBUS_XIO_TCP_DD_SET_OOB,
 *      GLOBUS_TRUE);
 */
/**
 *  @page signal_user Globus XIO Signals
 *
 *  Signals in globus xio give the user a means of requesting 
 *  notification when given things in the system change.  
 *
 *  For example:
 *  It may be useful for the user of globus_xio to know when/if the 
 *  optimal post buffer size changes.  The optimal post buffer size is
 *  a value that tells the user the best posible length of a buffer to 
 *  post for an io operation.  This value is mutable and can be changed
 *  by events internal to globus_xio of which the user is unaware.
 *  The signal API allows the user to register for notification of when
 *  this value changes.
 *
 *  GlobusXIO enumerates the signal types for which the user can register.  
 *  One of these types is GLOBUS_XIO_DRIVER_SPECIFIC.  This type allows
 *  the user to catch driver specific signals.  A driver specific signal
 *  example could be when the TCP window size changes.  Only a TCP driver
 *  can be aware of this information so only it can send the signal.  
 *  Further a user only knows to listen for that signal if it knows that
 *  tcp is in its driver stack.
 *
 *  Once a signal is delivered to the globus_xio user the handle can be 
 *  queried for specific information regarding that signal.
 */

/*************************************************************************
 *    define types
 ************************************************************************/

/**
 *  @ingroup GLOBUS_XIO_API
 *  Lookup a driver structure.
 *
 *  A driver structure is a static pointer that has a globally uniques 
 *  string asociated with it.  This may cause a search in .so
 *  Initialize a handle target with a given attribute set.
 */

globus_result_t
globus_xio_load_driver(
    globus_xio_driver_t *                   driver,
    const char *                            driver_lookup_string);

/**
 *  @page user_attr User Attributes
 *
 *  Globus XIO uses a single attribute object for all of its functions.
 *  Attributes give an the user an extenable mechanism to alter default
 *  values which control parameters in an operation.
 *
 *  In most of the globus xio user api functions a user passes an 
 *  attribute as a parameter.  In many cases the user may ignore the
 *  attribute parameter and just pass in NULL.  However at times the user
 *  will wish to tweak the operation.  The attribute structure is used for
 *  this tweaking.
 *
 *  There are only three attribute functions. @ref globus_xio_attr_init 
 *  @ref globus_xio_attr_cntl and @ref globus_xio_attr_destroy.  The
 *  init and destroy functions are very simple and require little explaination.
 *  Before an atribute can be used it must be intialized, and to clean up all
 *  memory associated with it the user must call destroy on it.
 *
 *  The function @ref globus_xio_attr_cntl manipulates values in the
 *  attribute.  For more info on it see @ref globus_xio_attr_cntl.
 */

/**
 *  Intialize a globus xio attribute.
 *
 *  @param attr
 *         upon return from this function this out parameter will be 
 *         initialized.  Once the user is finished with the attribute
 *         they should make sure they destroy it in order to free 
 *         resources associated with it.
 */
globus_result_t
globus_xio_attr_init(
    globus_xio_attr_t *                     attr);

/**
 *  Manipulate the values associated in the attr.
 *
 *  This function provides a means to access the attr structure.  What
 *  exactly this function does is determined by the value in the parameter
 *  cmd and the value of the patameter driver.  When the driver parameter
 *  is NULL it indicates that this function applies to general globus xio
 *  values.  If it is not NULL it indicates that the function will effect 
 *  driver specific values.  Each driver is resonsible for defining its own
 *  enumeration of values for cmd and the var args associated with that 
 *  command.  The general vlues for cmd that globus xio uses are displayed
 *  below:
 *
 *
 *  TODO: define the values.
 *  .  
 */
globus_result_t
globus_xio_attr_cntl(
    globus_xio_attr_t                       attr,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);


globus_result_t
globus_xio_attr_copy(
    globus_xio_attr_t *                     dst,
    globus_xio_attr_t                       src);

/**
 *  Clean up resources associated with an attribute.
 *
 *  @param attr
 *         Upon completion of this function all resources associated
 *         with this structure will returned to the system and the attr
 *         will no longer be valid.
 */
globus_result_t
globus_xio_attr_destroy(
    globus_xio_attr_t                       attr);

/**
 *  Stack functions
 */

/**
 *  Initialize a stack object 
 */
globus_result_t
globus_xio_stack_init(
    globus_xio_stack_t *                    stack,
    globus_xio_attr_t                       stack_attr);

/**
 *  Push a driver onto a stack.
 *
 *  No attrs are associated with a driver. The stack represents the
 *  ordered lists of transform drivers and 1 transport driver.
 */
globus_result_t
globus_xio_stack_push_driver(
    globus_xio_stack_t                      stack,
    globus_xio_driver_t                     driver);

/**
 *  Destroy a stack object.
 */
globus_result_t
globus_xio_stack_destroy(
    globus_xio_stack_t                      stack);

/**
 *  server 
 */
typedef void
(*globus_xio_accept_callback_t)(
    globus_xio_server_t                     server,
    globus_xio_target_t                     target,
    globus_result_t                         result,
    void *                                  user_arg);

typedef void
(*globus_xio_server_callback_t)(
    globus_xio_server_t                     server,
    void *                                  user_arg);

globus_result_t
globus_xio_server_create(
    globus_xio_server_t *                   server,
    globus_xio_attr_t                       server_attr,
    globus_xio_stack_t                      stack);

globus_result_t
globus_xio_server_register_close(
    globus_xio_server_t                     server,
    globus_xio_server_callback_t            cb,
    void *                                  user_arg);

globus_result_t
globus_xio_server_close(
    globus_xio_server_t                     server);

globus_result_t
globus_xio_server_cntl(
    globus_xio_server_t                     server,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);

globus_result_t
globus_xio_server_accept(
    globus_xio_target_t *                   out_target,
    globus_xio_server_t                     server,
    globus_xio_attr_t                       accept_attr);

globus_result_t
globus_xio_server_register_accept(
    globus_xio_server_t                     server,
    globus_xio_attr_t                       accept_attr,
    globus_xio_accept_callback_t            cb,
    void *                                  user_arg);

/**
 *  client init
 */
globus_result_t
globus_xio_target_init(
    globus_xio_target_t *                   target,
    globus_xio_attr_t                       target_attr,
    const char *                            contact_string,
    globus_xio_stack_t                      stack);

/**
 *  Query the target for info/
 *
 *  TODO: list all the values for cmd
 */
globus_result_t
globus_xio_target_cntl(
    globus_xio_target_t                     target,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);

/**
 *  This only needs to be called if the target object is not passed
 *  to globus_xio_open. 
 */
globus_result_t
globus_xio_target_destroy(
    globus_xio_target_t                     target);

/******************************************************************
 *                      handle construction
 *****************************************************************/

enum globus_xio_handle_attr_cmd_t
{
    GLOBUS_XIO_HANDLE_ATTR_OPEN_TIMEOUT,
    GLOBUS_XIO_HANDLE_ATTR_READ_TIMEOUT,
    GLOBUS_XIO_HANDLE_ATTR_WRITE_TIMEOUT,
    GLOBUS_XIO_HANDLE_ATTR_CLOSE_TIMEOUT,
    GLOBUS_XIO_HANDLE_ATTR_ALL_TIMEOUT,
};

/******************************************************************
 *                      setting timeout values
 *****************************************************************/

/**
 *  @ingroup GLOBUS_XIO_API
 *  The timeout callback function signature.
 *
 *  @param handle
 *         The handle the handle on which the timeout operation was 
 *         requested.
 *
 *  @param type
 *         The type of opperation that timed out:
 *         GLOBUS_XIO_OPERATION_OPEN
 *         GLOBUS_XIO_OPERATION_CLOSE
 *         GLOBUS_XIO_OPERATION_READ
 *         GLOBUS_XIO_OPERATION_WRITE
 *
 *  @param arg
 *         A user arg threaded throw to the callback.
 */

typedef globus_bool_t
(*globus_xio_timeout_callback_t)(
    globus_xio_handle_t                     handle,
    globus_xio_operation_type_t             type);

typedef globus_bool_t
(*globus_xio_timeout_server_callback_t)(
    globus_xio_server_t                     server,
    globus_xio_operation_type_t             type);


/******************************************************************
 *                      data descriptor
 *****************************************************************/

/**
 *  Initialize a data descriptor
 *  @ingroup GLOBUS_XIO_API
 *
 *  @param data_desc
 *         An out parameter.  The data descriptor to be intialized.
 *
 *  @param handle
 *         The handle this data descriptor will be used with.  This
 *         parametter is require in order to optimize the code 
 *         handling the data descriptors use.
 */
globus_result_t
globus_xio_data_descriptor_init(
    globus_xio_data_descriptor_t *          data_desc,
    globus_xio_handle_t                     handle);

/**
 *  @ingroup GLOBUS_XIO_API
 *  clean up a data descriptor.
 */
globus_result_t
globus_xio_data_descriptor_destroy(
    globus_xio_data_descriptor_t            data_desc);

/**
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_data_descriptor_cntl(
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);

/*********************************************************************
 *                         callbacks
 ********************************************************************/
/**
 *  globus_xio_callback_t
 *  @ingroup GLOBUS_XIO_API
 *
 *   This callback is used for the open and close user level asychronous 
 *   operations.
 */
typedef void (*globus_xio_callback_t)(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    void *                                  user_arg);

/**
 *  globus_xio_data_callback_t 
 *  @ingroup GLOBUS_XIO_API
 *
 *  This callback is used for asychronous operations that send or receive
 *  data.
 *
 *  on eof, result_t will be of type GLOBUS_XIO_ERROR_EOF
 */
typedef void (*globus_xio_data_callback_t)(
    globus_xio_handle_t                     handle, 
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes, 
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg);

typedef void (*globus_xio_iovec_callback_t)(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    globus_xio_iovec_t *                    iovec,
    int                                     count,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg);

/**
 *  Query/set information or request a synchronous operation on a handle.
 *  @ingroup GLOBUS_XIO_API
 *
 *  This function allows the user to query information from on set information
 *  on a handle.  The operation performed depends on the value of cmd.
 *  Possible values are:
 *
 *  TODO: list possible values.
 */
globus_result_t
globus_xio_handle_cntl(
    globus_xio_handle_t                     handle,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);

/**
 * Open a handle
 *  @ingroup GLOBUS_XIO_API
 *
 * Creates an open handle based on the state contained in the given
 * factory.
 * 
 * No operation can be preformed on a handle until it is opened.  If 
 * an already open handle used the information contaned in that handle
 * will be destoyed.
 */ 
globus_result_t
globus_xio_register_open(
    globus_xio_handle_t *                   handle,
    globus_xio_attr_t                       attr,
    globus_xio_target_t                     target,
    globus_xio_callback_t                   cb,
    void *                                  user_arg);

/**
 * Read data from a handle
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_register_read(
    globus_xio_handle_t                     handle,
    globus_byte_t *                         buffer,
    globus_size_t                           buffer_length,
    globus_size_t                           waitforbytes,
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_data_callback_t              cb,
    void *                                  user_arg);

/**
 * Read data from a handle into a globus_xio_iovec_t (struct iovec)
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_register_readv(
    globus_xio_handle_t                     handle,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitforbytes,
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_iovec_callback_t             cb,
    void *                                  user_arg);

/**
 * Write data to a handle
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_register_write(
    globus_xio_handle_t                     handle,
    globus_byte_t *                         buffer,
    globus_size_t                           buffer_length,
    globus_size_t                           waitforbytes,
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_data_callback_t              cb,
    void *                                  user_arg);

/**
 * Write data to a handle from a globus_xio_iovec_t (struct iovec)
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_register_writev(
    globus_xio_handle_t                     handle,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitforbytes,
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_iovec_callback_t             cb,
    void *                                  user_arg);


globus_result_t
globus_xio_handle_cancel_operations(
    globus_xio_handle_t                     handle,
    int                                     mask);

/**
 *  Close a handle
 *  @ingroup GLOBUS_XIO_API
 * 
 *  This functions servers as a destoy for the handle.  As soon as the
 *  operations completes (the callback is called).  The handle is
 *  destroyed.
 *
 *  @param handle
 *         the handle to be closed.
 *
 *  @param how 
 *         how indicates what direction to shutdown
 *         SHUT_RD
 *         SHUT_WR
 *         SHUT_RDWR
 *
 *  @param cb
 *         The function to be called when the close operation completes.
 *
 *  @param user_arg
 *         A user pointer that will be threaded through to the callback.
 */
globus_result_t
globus_xio_register_close(
    globus_xio_handle_t                     handle,
    globus_xio_attr_t                       attr,
    globus_xio_callback_t                   cb,
    void *                                  user_arg);

/*********************************************************************
 *                         signal stuff
 ********************************************************************/

/** 
 *  Event Types.
 *  @ingroup GLOBUS_XIO_API
 *  
 *  An enumeration of the signal types of which globus_xio is aware.  
 */
enum globus_xio_signal_type_t
{
    GLOBUS_XIO_SIGNAL_BUFFER_POST_SIZE,
    GLOBUS_XIO_SIGNAL_OPTIMAL_BUFFER_SIZE,
    GLOBUS_XIO_SIGNAL_DRIVER_SPECIFIC,
};

/**
 *  Signal Callback
 *  @ingroup GLOBUS_XIO_API
 *
 *  The callback signature for signal events.
 *
 *  @param handle
 *         The handle associated with the event.
 * 
 *  @param signal_type
 *         The type of signal that occured.
 *
 *  @param driver
 *         The driver that caused this event.  If it is not a driver
 *         specific signal than this will be NULL.
 */
typedef void
(*globus_xio_signal_callback_t)(
    globus_xio_handle_t                     handle,
    globus_xio_signal_type_t                signal_type,
    globus_xio_driver_t                     driver);

/**
 *  Register a signal listener.
 *  @ingroup GLOBUS_XIO_API
 *
 *  Reqest notification when event change in the system relating
 *  to a given handle.
 *
 *  @param handle
 *         The handle on which the user would like to receive 
 *         notifications.
 *
 *  @param signal_mask
 *         A mask of the signals to be observed.
 *
 *  @param driver
 *         The driver to which the signal mask applies.  If this is for a
 *         non driver specific event this will be null.  This function
 *         must be called once for every driver of interest.
 *
 *  @param callback
 *         The funciton to be called when the given events occur.
 *
 *  @param user_arg
 *         A user pointed threaded through to the callback.
 */
globus_result_t
globus_xio_handle_register_signal_handler(
    globus_xio_handle_t                     handle,
    int                                     signal_mask,
    globus_xio_driver_t                     driver,
    globus_xio_signal_callback_t            callback,
    void *                                  user_arg);

/**
 *  Register a signal listener.
 *  @ingroup GLOBUS_XIO_API
 *
 *  Reqest notification when event change in the system relating
 *  to a given factory.
 *
 *  @param factory
 *         The factory on which the user would like to receive 
 *         notifications of events.
 *
 *  @param signal_mask
 *         A mask of the signals to be observed.
 *
 *  @param driver
 *         The driver to which the signal mask applies.  If this is for a
 *         non driver specific event this will be null.  This function
 *         must be called once for every driver of interest.
 *
 *  @param callback
 *         The funciton to be called when the given events occur.
 *
 *  @param user_arg
 *         A user pointed threaded through to the callback.
 */
globus_result_t
globus_xio_server_register_signal_handler(
    globus_xio_server_t                     factory,
    int                                     signal_mask,
    globus_xio_driver_t                     driver,
    globus_xio_callback_t                   callback,
    void *                                  user_arg);

globus_result_t
globus_xio_close(
    globus_xio_handle_t                     handle,
    globus_xio_attr_t                       attr);


globus_result_t
globus_xio_writev(
    globus_xio_handle_t                     user_handle,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitforbytes,
    globus_size_t *                         nbytes,
    globus_xio_data_descriptor_t            data_desc);

globus_result_t
globus_xio_write(
    globus_xio_handle_t                     user_handle,
    globus_byte_t *                         buffer,
    globus_size_t                           buffer_length,
    globus_size_t                           waitforbytes,
    globus_size_t *                         nbytes,
    globus_xio_data_descriptor_t            data_desc);

globus_result_t
globus_xio_readv( 
    globus_xio_handle_t                     user_handle,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           waitforbytes,
    globus_size_t *                         nbytes,
    globus_xio_data_descriptor_t            data_desc);

globus_result_t
globus_xio_read(
    globus_xio_handle_t                     user_handle,
    globus_byte_t *                         buffer,
    globus_size_t                           buffer_length,
    globus_size_t                           waitforbytes,
    globus_size_t *                         nbytes,
    globus_xio_data_descriptor_t            data_desc);

globus_result_t
globus_xio_open(
    globus_xio_handle_t *                   user_handle,
    globus_xio_attr_t                       user_attr,
    globus_xio_target_t                     user_target);


extern globus_module_descriptor_t           globus_i_xio_module;
#define GLOBUS_XIO_MODULE &globus_i_xio_module

GlobusDebugDeclare(GLOBUS_XIO);

#endif
