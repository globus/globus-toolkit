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
 *                       factory construction
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
 *  - @ref factory_setup
 *  - @ref handle_setup
 *  - @ref muttable_attrs
 *  - @ref timeouts
 *  - @ref dd_user
 *  - @ref signal_user
 *      
 */

/**
 *  @page factory_setup Setting up a factory
 *
 *  The driver stack that is used for a given xio handle is constructed
 *  using a globus_xio_factory_t.  Each driver provides a global
 *  globus_xio_driver_t (synonymous to the globus_module_descriptor_t), 
 *  as well as its own means of setting driver specific factory attributes
 *
 *  Once you have a driver module and any factory attrs you need, you can 
 *  push the driver onto a globus_xio_factory_attr_t.  The order that the 
 *  drivers are pushed on determines the order that the are entered for ever
 *  give xio operation.
 *
 *  factory setup example:
 *
 *    // the tcp functions are driver specific (not part of the xio framework
 *    // interface).
 *    globus_xio_tcp_factory_attr_init(&tcp_factory_attr);
 *    globus_xio_tcp_factory_attr_set_listener_port(tcp_factory_attr, 2811);
 *
 *    // build the stack
 *    globus_xio_factory_attr_init(&factory_attr);
 *    globus_xio_factory_push_driver(
 *        factory_attr, GLOBUS_XIO_TCP_DRIVER, tcp_factory_attr);
 *    globus_xio_factory_push_driver(
 *        factory_attr, GLOBUS_XIO_GSI_DRIVER, GLOBUS_NULL);
 *    globus_xio_factory_init(&factory, factory_attr);
 */

/**
 *  @page handle_setup Handle Construction
 *
 *  Handles are constructed from factories.  Many handles can be created
 *  from a single factory.  The state of the factory at the time of
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
 *  globus_xio_handle_attr_set_mode(attr, O_WRONLY);
 *  globus_xio_handle_open(&handle, attr);
 *
 *  driver specific attr example:
 *
 *  globus_xio_handle_attr_init(&attr);
 *  // driver specifi function
 *  globus_xio_tcp_attr_init(&tcp_attr);
 *  globus_xio_tcp_attr_set_nodelay(tcp_attr, GLOBUS_TRUE);
 *  // set driver sepcific attr on xio attr via a driver devel api call
 *  globus_xio_attr_add_driver_attr(attr, tcp_attr);
 *  // open the handle
 *  globus_xio_handle_open(..&handle, attr..);
 *
 *  The driver should implement a convience function for setting attributes
 *  that would initialize the driver specific attr, set the value, and
 *  connect it with the xio_attr all in one call.
 *
 *  When globus_xio_open() is called it may return a warning stating that
 *  a driver specific attribute was reqested on a driver that is not in 
 *  the factories stack.  This would happen if the user requesed that
 *  the gsi driver use encryption and authentication but the stack only
 *  consisted of a TCP driver. 
 */
/**
 *  @page muttable_attrs Mutable Attributes
 *
 *  Mutable attributes are those that can be changed at any time during 
 *  the lifespan of a handle.  The function globus_xio_handle_fcntl() is 
 *  used to both change mutable attributes and query the handle for
 *  values.
 *
 *  Example of setting a muttable attribute:
 * 
 *  globus_xio_attr_init(&attr);
 *  globus_xio_attr_set_optimal_buffer_size(attr, 65536);
 *  globus_xio_handle_fcntl(handle, GLOBUS_XIO_SET_BUFFER_SIZE, attr);
 *
 *  Example of getting a muttable value:
 *
 *  globus_xio_attr_init(&attr);
 *  globus_xio_handle_fcntl(handle, GLOBUS_XIO_GET_BUFFER_SIZE, attr);
 *  globus_xio_attr_get_optimal_buffer_size(attr, &size);
 * 
 *  Driver specific mutable attrs can be set on a handle as well.  This
 *  is done in a similar process but by using a driver_handle_attr.
 *
 *  Example of setting driver specific muttable attrs
 *
 *   globus_xio_tcp_attr_init(&tcp_attr);
 *   globus_xio_tcp_attr_set_window_size(tcp_attr, 65536);
 *   globus_xio_handle_driver_fcntl(
 *       handle, 
 *       GLOBUS_XIO_TCP_DRIVER,
 *       GLOBUS_XIO_TCP_SET_WINDOW_SIZE,
 *       tcp_attr);
 *
 *  and getting driver specific mutable attrs:
 *    
 *   globus_xio_tcp_attr_init(&tcp_attr);
 *   globus_xio_handle_driver_fcntl(
 *       handle, 
 *       GLOBUS_XIO_TCP_DRIVER,
 *       GLOBUS_XIO_TCP_GET_WINDOW_SIZE,
 *       tcp_attr);
 *   globus_xio_tcp_attr_get_window_size(tcp_attr, &window_size);
 *
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
 *  callback for the given operation is not NULL it is called to
 *  notify the user that the operation timed out and thus has been 
 *  canceled.  The user will get the callback they registered for 
 *  the operation as well, but it will come with an error indicating
 *  that it has been canceled.
 *
 *  It is possiblie that part of an io operation will complete before
 *  the timeout expires.  In this case the opperation will still be 
 *  canceled.  The user will receive there IO callback with and 
 *  error set and the length value appropriately set to indicate how
 *  much of the operation completed.
 *
 *  There is no implied order in regard to the timeout callback and the
 *  io operation callback.
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
 *  globus_xio_data_descriptor_set_offset(desc, 1024);
 *  globus_xio_tcp_data_descriptor_set_oob(desc, GLOBUS_TRUE);
 *
 *  note: The driver api provides the tcp driver the power to manipulate the
 *        desc ADT.
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

/**
 *  @ingroup GLOBUS_XIO_API
 *  Initialize a handle factory with a given attribute set.
 */
globus_result_t
globus_xio_factory_init(
    globus_xio_factory_t *                      factory,
    globus_xio_factory_attr_t                   attr);

/**
 *  @ingroup GLOBUS_XIO_API
 *  clean up a factory
 */
globus_result_t
globus_xio_factory_destroy(
    globus_xio_factory_t                        factory);

/**
 *  @ingroup GLOBUS_XIO_API
 *  factory attribute init
 */
globus_result_t
globus_xio_factory_attr_init(
    globus_xio_factory_attr_t *                 attr);

/**
 *  @ingroup GLOBUS_XIO_API
 *  clean up an attr
 */
globus_result_t
globus_xio_factory_attr_destroy(
    globus_xio_factory_attr_t                   attr);

/**
 *  @ingroup GLOBUS_XIO_API
 *  push a driver to the top of the stack
 */
globus_result_t
globus_xio_factory_push_driver(
    globus_xio_factory_attr_t                   factory_attr,
    globus_xio_driver_t                         driver,
    globus_xio_driver_factory_attr_t            driver_factory_attr);

/******************************************************************
 *                      handle construction
 *****************************************************************/

/**
 *  @ingroup GLOBUS_XIO_API
 *  initialize a handle attribute
 */
globus_result_t
globus_xio_handle_attr_init(
    globus_xio_handle_attr_t *                  attr);

/**
 *  @ingroup GLOBUS_XIO_API
 *  clean up a handle attribute
 */
globus_result_t
globus_xio_handle_attr_destroy(
    globus_xio_handle_attr_t                    attr);

/**
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_handle_attr_set_mode(
    globus_xio_handle_attr_t                    attr,
    int                                         mode);

/**
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_handle_attr_get_mode(
    globus_xio_handle_attr_t                    attr,
    int *                                       mode);

/**
 *  @ingroup GLOBUS_XIO_API
 *  Set the best buffer possible buffer size.
 *
 *  Setting this on an attr may cause the function that associates the
 *  attr with a handle to fail (open for example), depending on what is
 *  contained in ther driver stack.
 */
globus_result_t
globus_xio_handle_attr_set_optimal_buffer_size(
    globus_xio_handle_attr_t                    attr,
    globus_size_t                               buffer_size);

/**
 *  @ingroup GLOBUS_XIO_API
 *  Discover the best possible buffer size
 */
globus_result_t
globus_xio_handle_attr_get_optimal_buffer_size(
    globus_xio_handle_attr_t                    attr,
    globus_size_t *                             buffer_size);

/**
 *  @ingroup GLOBUS_XIO_API
 *  Set the best possible outstanding number of buffers to post
 *
 *  Setting this on an attr may cause the function that associates the
 *  attr with a handle to fail (open for example), depending on what is
 *  contained in ther driver stack.
 */
globus_result_t
globus_xio_handle_attr_set_optimal_posted_buffers(
    globus_xio_handle_attr_t                    attr,
    int                                         buffer_size);

/**
 *  @ingroup GLOBUS_XIO_API
 *  Discover the best possible outstanding number of buffers to post
 */
globus_result_t
globus_xio_handle_attr_get_optimal_poseted_buffers(
    globus_xio_handle_attr_t                    attr,
    int *                                       buffer_size);

/**
 *  @ingroup GLOBUS_XIO_API
 *  This function adds a driver specific attribute to an initialized
 *  handle attribute.  The driver specific attr is initilized by
 *  finctions the driver will provide.
 */
globus_result_t
globus_xio_handle_attr_add_driver_attr(
    globus_xio_handle_attr_t                    attr,
    globus_xio_driver_handle_attr_t             driver_attr);

/******************************************************************
 *                      mutable attributes
 *****************************************************************/

/**
 *  @ingroup GLOBUS_XIO_API
 *  set and get mutable attributes on a handle
 */
globus_result_t 
globus_xio_handle_fcntl(
    globus_xio_handle_t                         handle,
    int                                         command,
    ...);

/**
 *  @ingroup GLOBUS_XIO_API
 *  set and get driver specific mutable attributes on a handle
 */
globus_result_t 
globus_xio_handle_driver_fcntl(
    globus_xio_handle_t                         handle,
    globus_xio_driver_t                         driver,
    int                                         command,
    ...);

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
(*globus_xio_timeout_callback)(
    globus_xio_handle_t                         handle,
    globus_xio_operation_type_t                 type,
    void *                                      arg);

/**
 *  @ingroup GLOBUS_XIO_API
 *  Operation types
 *  ---------------
 *
 *  An enumeration of operation types.  Used in the timeout callback
 *  to indicate what operation typed timedout.
 */
enum globus_xio_operation_type_t
{
    GLOBUS_XIO_OPERATION_OPEN,
    GLOBUS_XIO_OPERATION_CLOSE,
    GLOBUS_XIO_OPERATION_READ,
    GLOBUS_XIO_OPERATION_WRITE
};

/**
 *  @ingroup GLOBUS_XIO_API
 *  set timeouts for the various operations
 */
globus_result_t
globus_xio_handle_attr_set_timeout(
    globus_xio_handle_attr_t                    attr,
    globus_reltime_t                            timeout,
    globus_xio_timeout_callback_t               open_cb,
    void *                                      open_arg,
    globus_xio_timeout_callback_t               close_cb,
    void *                                      close_arg,
    globus_xio_timeout_callback_t               read_cb,
    void *                                      read_arg,
    globus_xio_timeout_callback_t               write_cb,
    void *                                      write_arg);
/*
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_handle_attr_set_open_timeout(
    globus_xio_handle_attr_t                    attr,
    globus_reltime_t                            timeout,
    globus_xio_timeout_callback_t               open_cb,
    void *                                      open_arg);
/*
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_handle_attr_set_close_timeout(
    globus_xio_handle_attr_t                    attr,
    globus_reltime_t                            timeout,
    globus_xio_timeout_callback_t               close_cb,
    void *                                      close_arg);

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
    globus_xio_data_descriptor_t *              data_desc,
    globus_xio_handle_t                         handle);

/**
 *  @ingroup GLOBUS_XIO_API
 *  clean up a data descriptor.
 */
globus_result_t
globus_xio_data_descriptor_destroy(
    globus_xio_data_descriptor_t                data_desc);

/**
 *  @ingroup GLOBUS_XIO_API
 *  set the offset in the data descriptor.
 */
globus_result_t
globus_xio_data_descriptor_set_offset(
    globus_xio_data_descriptor_t                data_desc,
    globus_off_t                                offset);

/**
 *  @ingroup GLOBUS_XIO_API
 *  get the offset in the data descriptor.
 */
globus_result_t
globus_xio_data_descriptor_get_offset(
    globus_xio_data_descriptor_t                data_desc,
    globus_off_t *                              offset);

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
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg);

/**
 *  globus_xio_data_callback_t 
 *  @ingroup GLOBUS_XIO_API
 *
 *  This callback is used for asychronous operations that send or receive
 *  data.
 *
 *  a size of -1 indicates end of file.
 */
typedef void (*globus_xio_data_callback_t)(
    globus_xio_handle_t                         handle, 
    globus_result_t                             result,
    globus_byte_t *                             buffer,
    globus_ssize_t                              nbytes, 
    globus_xio_data_descriptor_t                data_desc,
    void *                                      user_arg);

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
    globus_xio_factory_t                        factory,
    globus_xio_handle_t *                       handle,
    globus_xio_handle_attr_t                    attr,
    globus_xio_callback_t                       cb,
    void *                                      user_arg);

/**
 * Read data from a handle
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_register_read(
    globus_xio_handle_t                         handle,
    globus_byte_t *                             buffer,
    globus_size_t                               buffer_length,
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_callback_t                       cb,
    void *                                      user_arg);

/**
 * Write data to a handle
 *  @ingroup GLOBUS_XIO_API
 */
globus_result_t
globus_xio_register_write(
    globus_xio_handle_t                         handle,
    globus_byte_t *                             buffer,
    globus_size_t                               buffer_length,
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_callback_t                       cb,
    void *                                      user_arg);

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
    globus_xio_handle_t                         handle, 
    int                                         how,
    globus_xio_callback_t                       cb,
    void *                                      user_arg);

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
    globus_xio_handle_t                         handle,
    globus_xio_signal_type_t                    signal_type,
    globus_xio_driver_t                         driver);

/**
 *  @ingroup GLOBUS_XIO_API
 *  Get the current optimal buffer size from a handle.
 */
globus_result_t
globus_xio_signal_get_optimal_buffer_size(
    globus_xio_handle_t                         handle,
    globus_size_t *                             buffer_size);

/**
 *  @ingroup GLOBUS_XIO_API
 * Get the current optimal buffer post count
 */
globus_result_t
globus_xio_signal_get_optimal_buffer_post(
    globus_xio_handle_t                         handle,
    int *                                       post);

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
    globus_xio_handle_t                         handle,
    int                                         signal_mask,
    globus_xio_driver_t                         driver,
    globus_xio_signal_callback_t                callback,
    void *                                      user_arg);

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
globus_xio_factory_register_signal_handler(
    globus_xio_factory_t                        factory,
    int                                         signal_mask,
    globus_xio_driver_t                         driver,
    globus_xio_callback_t                       callback,
    void *                                      user_arg);

/***************************************************************
 *                  factory serialization
 *                  ---------------------
 *  The idea here is to provide a way tell a remote application
 *  the protocol stack to use.  So a program could be written 
 *  that, for example, simple routes messages from any protocol
 *  to any protocol where both protocols are determined at
 *  runtime.
 *
 *  There is an issue here with module activation that will need
 *  to be resolved one way or another.  For now we are going
 *  to table this issue in the interest of progress.
 **************************************************************/
/*
 *  Create a serialized string from an initialized factory.
 *
 *  This function will be used to serialized protocol stack 
 *  information.
 */
globus_result_t
globus_xio_factory_serialize(
    globus_xio_factory_t                        factory,
    char *                                      cs);

/*
 *  Take a serialized string and create an initialized factory from 
 *  it.  
 */
globus_result_t
globus_xio_factory_unserialize(
    globus_xio_factory_t *                      factory,
    const char *                                cs);

