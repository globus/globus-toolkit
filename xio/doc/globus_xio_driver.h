/*******************************************************************
 *                      driver interface
 ******************************************************************/
/**
 *  @page drivers Globus XIO Drivers
 *
 *  Globus XIO introduces a notion of a driver stack to its API.
 *  With in globus_xio every IO operation must occur on a globus_xio 
 *  handle.  Associated with each handle is a stack of drivers.
 *  A driver is a module piece of code that implements the globus_xio
 *  driver interface.  The purpose of a driver is manipulate data passed
 *  in by the user in someway.  Each driver in a stack will server its own 
 *  unique purpose.
 *
 *  IO operations pass from driver to driver, starting at the top of the 
 *  stack and ending at the bottom.  When the bottom layer driver finishes 
 *  with the operation it signals globus_xio that it has completed.  
 *  Completion notification then follows the driver stack up to the top.
 *
 *  There are two types of drivers:
 *
 *  Transport driver:
 *     A transport driver is one that is responsible for actually putting
 *     bytes onto the wire.  For example: A TCP driver or a UDP driver would
 *     be an example of transport drivers.  
 *
 *     Per driver stack there must be exactly one transport driver and
 *     must be at the bottom of the stack.  A transform driver is defined
 *     by its lack of passing an operation to the next driver in the stack.
 *     This type of driver does not rely on globus_xio for further completion
 *     of an operation, rather it is self sufficent in this task.
 *
 *  Transform driver:
 *     A tranform driver is any intermediate driver in the stack.  These 
 *     drivers are indentified by there reliance on the driver stack to
 *     complete the operation.  These drivers must pass the operation
 *     down the stack because they cannot complete it themselves.  An
 *     example of a transform driver would be a gsi driver.  This driver
 *     would wrap and unwrap messages, but would not be able to complete
 *     the transport itself, so it would rely on the remaining drivers in
 *     the stack.
 */
/**
 *  @page driver_api Globus XIO Driver API
 * 
 *  The globus xio driver api is a set of functions and interfaces
 *  to allow a developer to create a backend driver for globus_xio.
 *  To create a driver the user must implement all of the interface
 *  functions in the driver specification.
 *  There are also a set of functions provide to assist the driver
 *  author in implemention.
 *
 *  Quick Start:
 *    For basic driver needs the user will have to pay attention to a
 *    few new structures and concepts.
 *
 *    globus_xio_driver_operation_t
 *        This structure represents a request for an operation.  If
 *        the driver can service the operation it does so and the
 *        calls the appropriate finish_operation() function.  If the
 *        driver cannot completely service the operation it can pass()
 *        it along to the next driver in the stack.  As soon as the
 *        operation structure is either finished or passed it is no 
 *        longer valid for use in any other function.
 *
 *    globus_xio_driver_context_t
 *        A context represents a open handle to the driver stack for xio.
 *        The driver obtains a context by calling globus_xio_driver_open().
 *        When the open operation completes (it callback is called) the 
 *        driver then has a context.  The context allows the user to do some
 *        complex things that will be described later.
 *
 *    globus_xio_driver_factory_t
 *        This structure provides the driver with information about the 
 *        driver stack.  It is mainly only used for creating context
 *        as a parameter to globus_xio_driver_open().
 *
 *  Here is a typcial sequence of events for a globus_xio transform
 *  driver:
 *
 *        Open
 *           globus_xio_driver_open_t is called.  This is passed a factory
 *           a operation.  The user calls globus_xio_driver_open() passing
 *           it the operation and the factory and a callback.  When the 
 *           open callback is called the driver is given a new operation
 *           as a parameter.  The driver will then call 
 *           globus_xio_driver_finished_open() passing it the now 
 *           initialized context and the newly received operation.
 *           The call to globus_xio_driver_finished_open() does two things:
 *           1) it tells globus_xio that this driver has finished its open
 *           operation, and 2) it gives xio the context (which contains
 *           information on the drivers below it).
 *
 *        Read/Write
 *            The read or write interface funcion is called.  It receives
 *            a operation as a parameter.  The driver then calls the 
 *            approriate pass operation and waits for the callback.  When
 *            the callback is received the driver calls finished_operation
 *            passing in the operation structure it received in the callback
 *
 *        Close
 *            The close interface function is called and is passed an
 *            operation and a context.  The driver will call 
 *            globus_xio_driver_close() passing it the operation.
 *            When the close callback is received the driver calls
 *            globus_xio_driver_finished_close() passing it the
 *            operation received in the close callback and the context
 *            received in the interface function.  At this point the context
 *            is no longer valid..
 */
/**
 *   @page adv_drivers Globus XIO advanced driver programming
 *
 *   The typical driver implementatin is describe above.  However globus_xio
 *   allows driver authors to do more advanced things.  Some of these things
 *   will be explored here.
 *
 *   Read Ahead
 *
 *   Once a context is open a driver can spawn operation structures from
 *   it.  This gives the driver the ability to request io from the driver
 *   stack before it receives a call to its own interface io interface
 *   function.  So if a driver wishes to read ahead it does the following:
 *   1) it creats an operation by calling globus_xio_driver_create_operation()
 *   and passing it the context it is intereesting in using.
 *   2) call globus_xio_driver_read() using this operations.  When the read
 *   callback is received the driver may call finished_operation() on the
 *   op it receives (this ultimitely results in very little, since this 
 *   operation was started by this driver, but it is good practice and will
 *   free up resources that would otherwise leak).
 *   3) Now when the user finally does receive a read interface call from
 *   globus_xio it can imediately finish it using the operation it just
 *   received as a parameter and updating the iovec structure to represent 
 *   the read that already occured.
 *
 *    <explain finished from previous>
 * 
 *
 *   Preopening handles.
 *   
 *   Once the driver has received a globus_xio_driver_factory_t it can 
 *   open a context.  The globus_xio_driver_factory_t comes in the
 *   call to the interface function globus_xio_driver_factory_init_t().
 *   The driver uses this structure in a call to globus_xio_driver_open().
 *   When this functionality completes the driver has an initialized 
 *   context and can use it to create operations as described above.
 *   The driver can now hang onto this context until it receives an open
 *   interface function call.  At which time it can call 
 *   globus_xio_driver_finished_open() passing in the conext and thereby
 *   glueing the pre opened context with the requested globus_xio operation.
 *
 */
/* 
 *  Entry point interface functions
 *
 *  For all the posix like globus_xio user api functions (open/close/read
 *  /write) there is a driver interface function that the driver author 
 *  must implement.  They are implemented according to the needs of the 
 *  driver.
 *
 *  Factories and handles in the driver interface functions.
 *
 *  Just as there is a notion of facories and handles in the globus_xio
 *  user API, there is in the globus_xio driver interface functions.
 *  These structures are used to maintain state and attributes of a
 *  given handle or fuctory.  In the driver interface functions the handle
 *  and factory are both passed in as void pointers.  This is the case 
 *  because it is left up to the driver implementation to define what
 *  data members are needed in these handles.  When creating a new driver
 *  a programmer should have the feel as though they are creating a new api.
 */
/***********************************************************************
 *                     Factories
 **********************************************************************/
/**
 *  @defgroup driver_api_grp Driver API
 *
 *  These function are avauliable to the driver author to assist in implementation.
 */
/**
 *  @defgroup driver_interface_grp Driver Interface
 *
 *  The set of interface functions that the driver author must implement to create
 *  a driver.
 */
/**
 *  factory init
 *  @ingroup driver_interface_grp
 *
 *  A factory is the data structure from which all handles are created.
 *  The factor contains information regarding the driver stack from which
 *  the user wishes to create a handle.  The driver may also provide a means
 *  for a user to pass driver specific attributes.
 *
 *  This function is called via the user function globus_xio_factory_init().
 *  A driver should allocate and initilaize all storage associated with 
 *  a factory in this function.
 *
 *  @param out_driver_factory
 *         The factory handle for this driver.  The driver implementor
 *         should create and initiliaze memory to maintain the state of
 *         a facotry and then set this pointer to that memory.  All 
 *         subciquent call relating to this factory will pass in this
 *         pointer.
 *
 *  @param driver_factory_attr
 *         The driver specific factory attribute.  This void pointer 
 *         directs the driver to memory containing driver specific 
 *         initialization attribute.  This may be a NULL value.  If it 
 *         is the driver should assume default values.
 *
 *  @param user_factory
 *         The globus_xio user level factory pointer.  This parameter is
 *         a pointer to the user level factory handle.  The driver may 
 *         require this for quering about generic inialization paremeters.
 */
typedef globus_result_t
(*globus_xio_driver_factory_init_t)(
    void **                                     out_driver_factory,
    void *                                      driver_factory_attr,
    globus_xio_driver_factory_t                 user_factory);

/*
 *  factory destroy
 *  @ingroup driver_interface_grp
 *
 *  The driver should clean up all memory associated with a factory here.
 */
typedef globus_result_t
(*globus_xio_driver_factory_destroy_t)(
    void *                                      driver_factory);

/**********************************************************************
 *                          Open
 *********************************************************************/
/**
 *  Interface Function Open
 *  @ingroup driver_interface_grp
 *
 *  Called when the user wished to open a handle from a factory.
 *
 *  @param driver_handle
 *         This is an out parameter.  The driver implementor should
 *         populate it with a pointer to a piece of memory containing
 *         enough information to maintain state for there driver.  This
 *         pointer will be passed into all subsequent calls relating to
 *         this transfer.
 *
 *  @param driver_factory
 *         The driver factory from which the user is opening the handle.
 *
 *  @param driver_handle_attr,
 *         A void pointer to the driver specific attribute that may be 
 *         passed into this function.  This may be NULL, if it is the driver
 *         should assume default values.
 *
 *  @param op
 *         The requested operation.  When the driver has finished dealing
 *         with the operation it should call globus_xio_driver_finished_open()
 *         passing it this operation structure.
 *  
 */
typedef globus_result_t
(*globus_xio_driver_open_t)(
    void **                                     driver_handle,
    void *                                      driver_factory,
    void *                                      driver_handle_attr,
    globus_xio_driver_operation_t               op);

/**
 *  Driver API Open
 *  @ingroup driver_api_grp
 *
 *  This function will pass an open request down the driver stack.
 *  Upon completion of the open operation globus_xio will call the callback 
 *  function.  At which point the context structure will be intialized
 *  and available for use.
 *
 *  @param context
 *         Structure represening the state of the driver stack for this
 *         driver handle.
 *
 *  @param factory
 *         The factory from which the context will be established.  This
 *         parameter is used to determine what drivers are in the stack and
 *         other such information.
 *
 *  @param cb
 *         The function to be called wehn the open operation is complete.
 *
 *  @param user_arg
 *         a user pointer that will be threaded through to the callback.
 */
globus_result_t
globus_xio_driver_open(
    globus_xio_driver_context_t *               context,
    globus_xio_driver_factory_t                 factory,
    globus_xio_driver_callback_t                cb,
    void *                                      user_arg);

/**
 *  Driver API finished open
 *  @ingroup driver_api_grp
 *
 *  This function should be called to signal globus_xio that it has 
 *  completed the open operation requested of it.  It will free up 
 *  resources associated with the open_op and potientially cause xio
 *  to pop the signal up the driver stack.
 *
 *  @param context
 *         The opened context that will be associated with future operations
 *         upon the handle.
 *
 *   @param open_op
 *          The requested open operation that has completed.
 */
globus_result_t
globus_xio_driver_finished_open(
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               open_op);

/**********************************************************************
 *                      Context functions
 *********************************************************************/
/**
 *  Driver API Create Operation
 *  @ingroup driver_api_grp
 *
 *  This function will create an operation from an initialized context.
 *  This operation can then be used for io operations related to the
 *  context that created them.
 *
 *   @param operation
 *          The operation to be created.  When this function returns
 *          this structure will be populated and available for use
 *          for the driver.
 *
 *   @param context
 *          The initialized context representing the user handle from
 *          which the operation will be created.
 *   
 */
globus_result_t
globus_xio_driver_create_operation(
    globus_xio_driver_operation_t *             operation,
    globus_xio_driver_context_t                 context);

/**
 *  Driver API  Get Context
 *  @ingroup driver_api_grp
 *
 *  This function returns the context associated with a given operation
 *  to the user.  Although the context is coupled to operations, for the
 *  sake of efficiecy it is not passed to all interface functions.  This
 *  function allows the driver to obtain the context from an operation.
 *
 *  @param context
 *         This is an out parameter that will point to the context 
 *         associated with the given operation as soon as the function
 *         returns.
 *
 *  @param operation
 *         The operation that is to be queried for a context.
 */
globus_result_t
globus_xio_driver_operaton_get_context(
    globus_xio_driver_context_t *               context,
    globus_xio_driver_operation_t               operation);

/**
 *  Driver API context compare
 *  @ingroup driver_api_grp
 * 
 *  Test 2 contexts for compatablility
 *
 *  If the 2 contexts replresent the same globus_xio user level handle
 *  then this function will return GLOBUS_TRUE.  Onther wise it will
 *  return GLOBUS_FALSE
 *
 */
globus_bool_t
globus_xio_driver_context_compatable(
    globus_xio_driver_context_t                 context1,
    globus_xio_driver_context_t                 context2);

/**
 *   Driver API context and operation compare
 *  @ingroup driver_api_grp
 *
 *   Test an operation to verify that it is compatable with a given
 *   context.  If the operation was create from a context using the same
 *   globus_xio user level handle then the function will return 
 *   GLOBUS_TRUE, otherwise it will return GLOBUS_FALSE.  This function is
 *   equivalent to calling globus_xio_driver_operaton_get_context()
 *   and globus_xio_driver_context_compatable().
 */
globus_bool_t
globus_xio_driver_context_compatable_operation(
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               operation);

/**********************************************************************
 *                          Close
 *********************************************************************/
/**
 *  Close an open handle
 *  @ingroup driver_interface_grp
 *
 *  This is called when a user requests to close a handle.  The driver 
 *  implemntor should clean up all resources connected to there driver handle
 *  when this function is called.
 *
 *  @param driver_handle
 *          The driver handle to be closed.
 *
 *  @param context
 *         The context representing the globus_xio user handle that is
 *         requesting a close operation.
 * 
 *  @param op
 *         The reuqested operation.  When the driver is finished closing
 *         the handle it uses this structure to signal globus_xio that it
 *         has completed the operation requested.  It does this by calling
 *         globus_xio_driver_finished_operation()
 */
typedef globus_result_t
(*globus_xio_driver_close_t)(
    void *                                      driver_handle,
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               op);

/**
 *  Driver API Close
 *  @ingroup driver_api_grp
 *
 *  This function will pass a close request down the driver stack.  Upon
 *  completion of the close operation globus_xio will call the funciton
 *  pointed to by the cb arguement.
 *
 *  @param op
 *         The operation to pass along the driver stack for closing.
 *
 *  @param cb
 *         A pointer to the function to be called once all drivers lower
 *         in the stack have closed.
 *
 *  @param user_arg
 *         A user pointer that will be threaded through to the callback.
 */
globus_result_t
globus_xio_driver_close(
    globus_xio_driver_operation_t               op,
    globus_xio_driver_data_callback_t           cb,
    void *                                      user_arg);

/**
 *  Driver API finished_close
 *  @ingroup driver_api_grp
 *
 *  The driver calls this function after completing a close operation
 *  on a context.  Once this function returns the context is no longer 
 *  valid.
 *
 *  @param op
 *         The close operation that has completed.
 *
 *  @param context
 *         The context to be closed.
 */
globus_result_t
globus_xio_driver_finished_close(
    globus_xio_operation_t                      op,
    globus_xio_driver_context_t                 context);

/*******************************************************************
 *                        callbacks
 ******************************************************************/
/**
 *  callback interface
 *  @ingroup driver_api_grp
 *
 *  This is the function signature of callbacks for the 
 *  globus_xio_driver_open/close().
 *
 *  @param user_arg
 *         The user pointer that is threaded through to the callback.
 *
 *  @param op
 *         The operation structure associated with the open or the
 *         close requested operation.  The driver should call the 
 *         appropriate finished operation to clean up this structure.
 */
typedef globus_result_t
(*globus_xio_driver_callback_t)(
    void *                                      user_arg,
    globus_xio_operation_t                      op);

/**
 *  Data Callback interface
 *  @ingroup driver_api_grp
 *
 *  This is the function signature of read and write operation 
 *  callbacks.  
 *
 *  @param user_arg
 *         The user pointer that is threaded through to the callback.
 *
 *  @param op
 *         The operation structure associated with the read or write
 *         operation request.  The driver should call the approriate
 *         finished operation when it receives this operation.
 *
 *  @param iovec
 *         A pointer to an array of io vectors.
 *
 *  @param iovec_count
 *         the number of iovecs in the iovec array
 */
typedef globus_result_t
(*globus_xio_driver_data_callback_t)(
    void *                                      user_arg,
    globus_xio_operation_t                      op,
    globus_xio_iovec_t *                        iovec,
    int                                         iovec_count);

/**********************************************************************
 *                          Read
 *********************************************************************/
/**
 *  Read data from an open handle.
 *  @ingroup driver_interface_grp
 *
 *  This function is called when the user requests to read data from 
 *  a handle.  The driver author shall implement all code needed to for
 *  there driver to complete a read operations.
 *
 *  @param driver_handle
 *          The driver handle from which data should be read.
 *
 *  @param iovec
 *         An io vector pointing to the buffers to be read into.
 *
 *  @param iovec_count
 *         The number if entries in the io vector.
 *
 *  @param op
 *         The requested operation.  When the driver is finished fullfilling
 *         the requested read operation it must use this structure to 
 *         signal globus_xio that the operation is completed.  This is done
 *         by calling globus_xio_driver_finished_operation()..
 */
typedef globus_result_t
(*globus_xio_driver_read_t)(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op);

/**
 *  Driver read
 *  @ingroup driver_api_grp
 *
 *  This function passes a read operation down the driver stack.  After
 *  this function is called the op structure is no longer valid.  However
 *  when the driver stack finishes servicing the read request it will 
 *  pass a new operation structure in the funciton pointed to by cb.
 *  Finishe read can be called on the new operation received.
 *
 *  @param op
 *         The operation structure representing this requested io
 *         operation.
 *
 *  @param iovec
 *         A pointer to the array of iovecs.
 *
 *  @param iovec_count
 *         The number of iovecs in the array.
 *
 *  @param cb
 *         The function to be called when the operation request is 
 *         completed.
 *
 *  @param user_arg
 *         A user pointer that will be threaded through to the callback.
 */
globus_result_t
globus_xio_driver_read(
    globus_xio_driver_operation_t               op,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_data_callback_t           cb,
    void *                                      user_arg);

/**
 *  Finished Read
 *  @ingroup driver_api_grp
 *
 *  This function is called to signal globus_xio that the requested
 *  read operation has been completed.
 *
 *  @param op
 *         The operation structure representing the requested read
 *         operation.
 *
 */.
globus_result_t
globus_xio_driver_finished_read(
    globus_xio_driver_operation_t               op);

/**********************************************************************
 *                          Write
 *********************************************************************/
/**
 *  Write data from an open handle.
 *  @ingroup driver_interface_grp
 *
 *  This function is called when the user requests to write data to
 *  a handle.  The driver author shall implement all code needed to for
 *  there driver to complete write operations.
 *
 *  @param driver_handle
 *          The driver handle to which data should be writen.
 *
 *  @param iovec
 *         An io vector pointing to the buffers to be written.
 *
 *  @param iovec_count
 *         The number if entries in the io vector.
 *
 *  @param op
 *         The requested operation.  When the driver is finished fullfilling
 *         the requested read operation it must use this structure to 
 *         signal globus_xio that the operation is completed.  This is done
 *         by calling globus_xio_driver_finished_operation()..
 */
typedef globus_result_t
(*globus_xio_driver_write_t)(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op);

/**
 *  Driver write
 *  @ingroup driver_api_grp
 *
 *  This function passes a write operation down the driver stack.  After
 *  this function is called the op structure is no longer valid.  However
 *  when the driver stack finishes servicing the write request it will 
 *  pass a new operation structure in the funciton pointed to by cb.
 *  Finished write can be called on the new operation received.
 *
 *  @param op
 *         The operation structure representing this requested io
 *         operation.
 *
 *  @param iovec
 *         A pointer to the array of iovecs.
 *
 *  @param iovec_count
 *         The number of iovecs in the array.
 *
 *  @param cb
 *         The function to be called when the operation request is 
 *         completed.
 *
 *  @param user_arg
 *         A user pointer that will be threaded through to the callback.
 */
globus_result_t
globus_xio_driver_write(
    globus_xio_driver_operation_t               op,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_data_callback_t           cb,
    void *                                      user_arg);

/**
 *  Finished Write
 *  @ingroup driver_api_grp
 *
 *  This function is called to signal globus_xio that the requested
 *  write operation has been completed.
 *
 *  @param op
 *         The operation structure representing the requested write
 *         operation.
 */.
globus_result_t
globus_xio_driver_finished_write(
    globus_xio_driver_operation_t               op);


/**
 *  Finishes an operation and merge to op structures.
 *  @ingroup driver_api_grp
 *
 *  This function will join to operations together and signal globus_xio
 *  that it has completed.  This is an advanced function.  Most drivers will
 *  not require its use.  This function takes an operation that was created
 *  by this driver and passed on to drivers lower on the stack and an
 *  operation that came in on the interface function (that has seen the top
 *  half of the stack) and joins them together.  The purpose of this function
 *  is to join data descriptors that were prestaged and cached with those
 *  that have later come in at the users request.  See the read ahead doc
 *  for more information.
 *
 *  @param top_op
 *         The operation that has seen the top part of the driver stack.
 *
 *  @param bottom_op
 *         The operation that has seen the bottom part of the driver stack.
 *  
 */
globus_result_t
globus_xio_driver_finished_from_previous(
    globus_xio_driver_operation_t               top_op,
    globus_xio_driver_operation_t               bottom_op);


/**********************************************************************
 *                     data descriptors
 *********************************************************************/
/**
 *  @page dd_driver Data descriptors
 *
 *  globus_xio uses data descriptors to associate meta data with the 
 *  data being writen or the data read.
 *
 *  Data descriptors flow into the drivers read and write interface
 *  functions by way of the operation structure.  If the driver is
 *  interested in viewing the data decriptor it can request it from
 *  the operation structure via a call to 
 *  globus_xio_driver_operation_get_data_descriptor() and it can view
 *  any driver specific data descriptor via a call to
 *  globus_xio_driver_data_descriptor_get_specific().  The driver
 *  can modify values in the data descriptor by setting values before
 *  passing the request down the stack.  Several functions are available
 *  to modify the data descriptors.  There is no need to "set()" the 
 *  data descriptors back into the operation.  The functions for manipluating
 *  the values in a DD affect the values xio has directly.
 *
 *  Data descriptors flow back to the driver in the callbacks for
 *  the data operations.  When calling finished operation on a data 
 *  operation the driver must pass in a data descriptor.  It should get 
 *  this data descriptor from the io operation callback.
 *
 *  Life Cycle:
 *
 *  Passing in a data descriptor:
 *    A data descriptor is first created by the globus_xio user.  The user 
 *    can add driver specific data descriptors to it.  Once the usre has
 *    created and set the attributes on its data descriptor to their liking
 *    they pass it into a globus_xio data operation (either read or write).
 *    When the data descriptor is passed on globus_xio will make an internal
 *    copy of it.  It does this by first coping the user the level
 *    data descriptor and then walkinging through the list of driver specific
 *    data descriptor contianed in to and requesting the the driver make 
 *    a copy of the driver specific data descriptor.  If ever a driver
 *    specific data descriptor is NULL globus_xio need not call into its
 *    drivers dd_copy function.  If ever the user level data descriptor is
 *    NULL globus_xio need not deal with the data descriptor functionality at 
 *    all.  
 *
 *  A data descriptor coming back up the stack
 *    Once an io operation reachs the transport driver (the bottom of the
 *    stack) it takes on a slightly different role.  On the way in it
 *    is describing what is requested to be done with the data, on the way
 *    out it is describing what has actually been done.  Once the transport
 *    driver performs the operation it should adjust the data descriptor
 *    to reflect what has actually happened (few drivers will need to worry
 *    about this).  Each driver on the way up can adjust the data 
 *    descriptor and its driver specific data decriptor.  When xio reachs the
 *    the top of the stack it calls a user callback.  When that callback 
 *    returns all memory associated with the data descriptor is cleaned up.
 *    The interface function globus_xio_driver_data_descriptor_free() is
 *    used for this.
 */

/**
 *  Data Decriptor Copy
 *  @ingroup driver_interface_grp
 *
 *  This function is called when the system requires a copy of a driver
 *  specific data descriptor that was created by this driver.
 */
typedef globus_result_t
(*globus_xio_driver_data_descriptor_copy_t)(
    void **                                     dst_dd,
    void *                                      src_dd);
/**
 *  Data Decriptor Free
 *  @ingroup driver_interface_grp
 *
 *  This function is called when a driver specific data desciptor needs
 *  to be freed.
 */
typedef globus_result_t
(*globus_xio_driver_data_descriptor_free_t)(
    void *                                      dd);

/**
 *  Data Decriptor Getspecific
 *  @ingroup driver_api_grp
 *
 *  This function will return a pointer to this drivers specific data
 *  decriptor.  This value may be NULL.  In which case the user driver
 *  should assume default values.
 */
globus_result_t
globus_xio_driver_data_descriptor_get_specific(
    void **                                     driver_data_desc,
    globus_xio_driver_data_descriptor_t         data_desc);

/**
 *  Get data Descriptor from an operation
 *  @ingroup driver_api_grp
 *
 *  Returns the data descriptor associated with the given operation.
 *  If NULL is returned the driver assumes default values for both the
 *  general xio data descriptor values and the driver specific ones.
 */
globus_result_t
globus_xio_driver_operation_get_data_descriptor(
    globus_xio_driver_data_descriptor_t *       data_desc,
    globus_xio_driver_operation_t               op);

/**
 *  Set a driver specific data structure on an operation.
 *  @ingroup driver_api_grp
 *
 *  This will attach a driver specific data descriptor to an operation
 *  structure.  If the non specifc data structure for this operation is 
 *  NULL this function will result in the creation of one with default 
 *  values set.
 */
globus_result_t
globus_xio_driver_operation_set_specific_data_descriptor(
    globus_xio_driver_operation_t               op,
    void *                                      driver_data_desc);

/**
 *  @ingroup driver_api_grp
 *  This function results in a new data descriptor with default values
 *  attached to the given operation.
 */
globus_result_t
globus_xio_driver_operation_create_data_descriptor(
    globus_xio_driver_operation_t               op);

/*******************************************************************
 *                        signal stuff
 ******************************************************************/
/**
 *  @ingroup driver_api_grp
 *  Signals
 *
 */
typedef void
(*globus_xio_signal_callback_t)(
    void *                                      user_ptr,
    globus_xio_driver_context_t                 context,
    globus_xio_signal_type_t                    signal_type);
/**
 *  @ingroup driver_api_grp
 */
globus_result_t
globus_xio_driver_signal_register_callback(
     globus_xio_driver_context_t                context,
     int                                        signal_mask,
     void *                                     user_ptr);

/**
 *  @ingroup driver_api_grp
 */
globus_result_t
globus_xio_driver_context_get_optimal_buffer_size(
     globus_xio_driver_context_t                context,
     globus_size_t *                            buffer_size);

/**
 *  @ingroup driver_api_grp
 */
globus_result_t
globus_xio_driver_fire_signal(
     globus_xio_driver_context_t                context,
     int                                        signal_mask);

/**********************************************************************
 *                init
 *********************************************************************/

/**
 *  @ingroup driver_api_grp
 */
globus_result_t
globus_xi_driver_init(
    globus_xio_driver_t *                       driver,
    globus_xio_driver_factory_init_t            factory_init,
    globus_xio_driver_factory_destroy_t         factory_destroy,
    globus_xio_driver_open_t                    open,
    globus_xio_driver_close_t                   close,
    globus_xio_driver_read_t                    read,
    globus_xio_driver_write_t                   write,
    globus_xio_driver_data_descriptor_copy_t    dd_copy,
    globus_xio_driver_data_descriptor_free_t    dd_free);
