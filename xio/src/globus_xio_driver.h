#if !defined(GLOBUS_XIO_DRIVER_H)
#define GLOBUS_XIO_DRIVER_H 1

#include "globus_common.h"
#include "globus_xio_load.h"

/************************************************************************
 *                      attribute macros
 ***********************************************************************/
#define GlobusIXIOAttrGetDS(_out_ds, _in_attr, _in_driver)                  \
do                                                                          \
{                                                                           \
    int                                         _ctr;                       \
    globus_i_xio_attr_t *                       _attr;                      \
    globus_xio_driver_t                         _driver;                    \
    globus_i_xio_attr_ent_t *                   _entry;                     \
    void *                                      _ds = NULL;                 \
                                                                            \
    _attr = (_in_attr);                                                     \
    _driver = (_in_driver);                                                 \
                                                                            \
    if(_in_attr == NULL)                                                    \
    {                                                                       \
        _out_ds = NULL;                                                     \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _entry = _attr->entry;                                              \
        for(_ctr = 0; _ctr < _attr->ndx && _ds == NULL; _ctr++)             \
        {                                                                   \
            if(_entry[_ctr].driver == _driver)                              \
            {                                                               \
                _ds = _entry[_ctr].driver_data;                             \
            }                                                               \
    }                                                                       \
        _out_ds = _ds;                                                      \
    }                                                                       \
} while(0)
    
/*
 *  cancel and timeout functions 
 */
#define GlobusXIODriverBlockTimeout(_in_op)                                 \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
                                                                            \
    _op = (_in_op);                                                         \
    _op->block_timeout = GLOBUS_TRUE;                                       \
} while(0)

#define GlobusXIODriverUnblockTimeout(_in_op)                               \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
                                                                            \
    _op = (_in_op);                                                         \
    _op->block_timeout = GLOBUS_FALSE;                                      \
} while(0)

#define GlobusXIOOperationRefreshTimeout(_in_op)                            \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
                                                                            \
    _op = (_in_op);                                                         \
    _op->progress = GLOBUS_TRUE;                                            \
} while(0)

#define GlobusXIODriverEnableCancel(op, _canceled, cb, user_arg)            \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_mutex_t *                                _mutex;                 \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    if(_op->type == GLOBUS_XIO_OPERATION_TYPE_ACCEPT)                       \
    {                                                                       \
        _mutex = &_op->_op_server->mutex;                                   \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _mutex = &_op->_op_context->mutex;                                  \
    }                                                                       \
    globus_mutex_lock(_mutex);                                              \
    {                                                                       \
        _canceled = _op->canceled;                                          \
        if(!_op->canceled)                                                  \
        {                                                                   \
            _op->cancel_cb = (cb);                                          \
            _op->cancel_arg = (user_arg);                                   \
        }                                                                   \
    }                                                                       \
    globus_mutex_unlock(_mutex);                                            \
} while(0)

#define GlobusXIODriverDisableCancel(op)                                    \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                             _op;                    \
    globus_mutex_t *                                _mutex;                 \
                                                                            \
    _op = (globus_i_xio_op_t *)(op);                                        \
    if(_op->type == GLOBUS_XIO_OPERATION_TYPE_ACCEPT)                       \
    {                                                                       \
        _mutex = &_op->_op_server->mutex;                                   \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _mutex = &_op->_op_context->mutex;                                  \
    }                                                                       \
    globus_mutex_lock(_mutex);                                              \
    {                                                                       \
        _op->cancel_cb = NULL;                                              \
        _op->cancel_arg = NULL;                                             \
    }                                                                       \
    globus_mutex_unlock(_mutex);                                            \
} while(0)

#define GlobusXIOOperationGetWaitFor(_in_op)                                \
    ((_in_op)->entry[(_in_op)->ndx - 1]._op_ent_wait_for)

#define GlobusXIOOperationGetDriverSpecificHandle(_in_op)                   \
    ((_in_op)->_op_context->entry[(_in_op)->ndx - 1].driver_handle)

#define GlobusXIOOperationGetDriverHandle(_in_op)                           \
    &((_in_op)->_op_context->entry[(_in_op)->ndx - 1])

#define GlobusXIOOperationGetDataDescriptor(_out_dd, _in_op, _force_create) \
{                                                                           \
    if((_in_op)->entry[(_in_op)->ndx - 1].dd != NULL)                       \
    {                                                                       \
        (void *) _out_dd = (_in_op)->entry[(_in_op)->ndx - 1].dd;           \
    }                                                                       \
    else if((_in_op)->is_user_dd || _force_create)                          \
    {                                                                       \
        globus_i_xio_driver_t *                     _dd_driver;             \
        globus_result_t                             _res;                   \
                                                                            \
        _dd_driver =                                                        \
            (_in_op)->_op_context->entry[(_in_op)->ndx - 1].driver;         \
                                                                            \
        _res = _dd_driver->attr_init_func((void **)&(_out_dd));             \
        if(_res != GLOBUS_SUCCESS)                                          \
        {                                                                   \
            _out_dd = NULL;                                                 \
        }                                                                   \
        else                                                                \
        {                                                                   \
            (_in_op)->entry[(_in_op)->ndx - 1].dd = (_out_dd);              \
        }                                                                   \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        _out_dd = NULL;                                                     \
    }                                                                       \
}

#define GlobusXIOOperationSetDataDescriptor(_in_op, _in_dd)                 \
    ((_in_op)->entry[(_in_op)->ndx - 1].dd) = (_in_dd)


/*******************************************************************
 *                      driver interface
 ******************************************************************/
/**
 *  @defgroup globus_xio_driver Globus XIO Driver
 *
 *  Globus XIO introduces a notion of a driver stack to its API.
 *  With in globus_xio every IO operation must occur on a globus_xio 
 *  handle.  Associated with each handle is a stack of drivers.
 *  A driver is a module piece of code that implements the globus_xio
 *  driver interface.  The purpose of a driver is manipulate data passed
 *  in by the user in someway.  Each driver in a stack will serve its own 
 *  unique purpose.
 *  \n
 *  IO operations pass from driver to driver, starting at the top of the 
 *  stack and ending at the bottom.  When the bottom layer driver finishes 
 *  with the operation it signals globus_xio that it has completed.  
 *  Completion notification then follows the driver stack up to the top.
 *
 *  \par Driver Types:
 * 
 *  \par
 *     <tt>Transport driver:</tt>\n
 *     A transport driver is one that is responsible for actually putting
 *     bytes onto the wire.  For example: A TCP driver or a UDP driver would
 *     be an example of transport drivers.  
 *     \n\n
 *     Per driver stack there must be exactly one transport driver and
 *     must be at the bottom of the stack.  A transform driver is defined
 *     by its lack of passing an operation to the next driver in the stack.
 *     This type of driver does not rely on globus_xio for further completion
 *     of an operation, rather it is self sufficent in this task.
 *
 *  \par 
 *     <tt>Transform driver:</tt>\n
 *     A tranform driver is any intermediate driver in the stack.  These 
 *     drivers are indentified by there reliance on the driver stack to
 *     complete the operation.  These drivers must pass the operation
 *     down the stack because they cannot complete it themselves.  An
 *     example of a transform driver would be a gsi driver.  This driver
 *     would wrap and unwrap messages, but would not be able to complete
 *     the transport itself, so it would rely on the remaining drivers in
 *     the stack.
 *
 *  \par Driver API 
 *  The globus xio driver api is a set of functions and interfaces
 *  to allow a developer to create a backend driver for globus_xio.
 *  To create a driver the user must implement all of the interface
 *  functions in the driver specification.
 *  There are also a set of functions provide to assist the driver
 *  author in implemention.
 *
 *  \par 
 *    <tt>Quick Start:</tt>\n
 *    Four basic driver needs the user will have to pay attention to a
 *    few new structures and concepts.
 *
 *    \par 
*         <tt>globus_xio_operation_t</tt>\n
 *        This structure represents a request for an operation.  If
 *        the driver can service the operation it does so and the
 *        calls the appropriate finish_operation() function.  If the
 *        driver cannot completely service the operation it can pass()
 *        it along to the next driver in the stack.  As soon as the
 *        operation structure is either finished or passed it is no 
 *        longer valid for use in any other function.
 *
 *    \par 
 *      <tt>globus_xio_driver_handle_t</tt>\n
 *        A driver_handle represents a open handle to the driver stack for xio.
 *        The driver obtains a driver_handle by calling 
 *        globus_xio_driver_open().
 *        When the open operation completes (it callback is called) the 
 *        driver then has a driver_hadnle.  The driver_handle 
 *        allows the user to do some
 *        complex things that will be described later.
 *
 *    \par 
 *      <tt>globus_xio_stack_t</tt>\n
 *        This structure provides the driver with information about the
 *        driver stack  It is mainly used for creating driver_handle as a
 *        parameter to lobus_xio_driver_open()..
 * 
 *  \par Typical Sequence:
 *  Here is a typcial sequence of events for a globus_xio transform
 *  driver:
 *
 *        \par 
 *          <tt>Open</tt>\n
 *           globus_xio_driver_open_t is called.  The user calls
 *           globus_xio_driver_open() passing it the operation and 
 *           the stack and a callback.  When the open callback is called 
 *           the driver is given a new operation as a parameter.  The driver
 *           will then call globus_xio_driver_finished_open() passing
 *           it the now initialized driver_handle and the newly received
 *           operation.
 *           The call to globus_xio_driver_finished_open() does two things:
 *           1) it tells globus_xio that this driver has finished its open
 *           operation, and 2) it gives xio the driver_handle (which contains
 *           information on the drivers below it).
 *
 *        \par 
 *          <tt>Read/Write</tt>\n
 *            The read or write interface funcion is called.  It receives
 *            a operation as a parameter.  The driver then calls the 
 *            approriate pass operation and waits for the callback.  When
 *            the callback is received the driver calls finished_operation
 *            passing in the operation structure it received in the callback
 *
 *        \par 
 *            <tt>Close</tt>\n
 *            The close interface function is called and is passed an
 *            operation and a driver_handle.  The driver will call 
 *            globus_xio_driver_close() passing it the operation.
 *            When the close callback is received the driver calls
 *            globus_xio_driver_finished_close() passing it the
 *            operation received in the close callback and the driver_handle
 *            received in the interface function.  At this point the 
 *            driver_handle
 *            is no longer valid..
 */
/**
 *   @addtogroup globus_xio_driver
 *
 *   \par Advanced Driver Programming
 *   The typical driver implementatin is describe above.  However globus_xio
 *   allows driver authors to do more advanced things.  Some of these things
 *   will be explored here.
 *
 *   \par 
 *   <tt>Read Ahead</tt>\n
 *   Once a driver_handle is open a driver can spawn operation structures from
 *   it.  This gives the driver the ability to request io from the driver
 *   stack before it receives a call to its own interface io interface
 *   function.  So if a driver wishes to read ahead it does the following:
 *
 *   \li it creats an operation by calling globus_xio_driver_create_operation()
 *   and passing it the driver_handle it is intereesting in using.
 *
 *   \li call globus_xio_driver_read() using this operations.  When the read
 *   callback is received the driver may call finished_operation() on the
 *   op it receives (this ultimitely results in very little, since this 
 *   operation was started by this driver, but it is good practice and will
 *   free up resources that would otherwise leak).
 *
 *   \li Now when the user finally does receive a read interface call from
 *   globus_xio it can imediately finish it using the operation it just
 *   received as a parameter and updating the iovec structure to represent 
 *   the read that already occured.
 *
 *   \par 
 *   <tt>Preopening handles.</tt>\n
 *   Once the driver has received a globus_xio_driver_stack_t it can 
 *   open a driver_handle.  The globus_xio_driver_stack_t comes in the
 *   call to the interface function globus_xio_server/client_init_t().
 *   The driver uses this structure in a call to globus_xio_driver_open().
 *   When this functionality completes the driver has an initialized 
 *   driver_handle and can use it to create operations as described above.
 *   The driver can now hang onto this driver_handle until it receives an open
 *   interface function call.  At which time it can call 
 *   globus_xio_driver_finished_open() passing in the driver_handle and thereby
 *   glueing the pre opened driver_handle with the requested globus_xio 
 *   operation.
 */
/**
 *  @defgroup driver_pgm Driver Programming
 *
 *  The set of interface functions that the driver author must implement 
 *  to create a driver and the functions to assist in the creation.
 */

#include <stdarg.h>
#include "globus_common.h"
#include "globus_xio_types.h"
#include "globus_xio.h"
#include "globus_xio_util.h"

/*******************************************************************
 *                        callbacks
 ******************************************************************/
/**
 *  callback interface
 *  @ingroup driver_pgm
 *
 *  This is the function signature of callbacks for the 
 *  globus_xio_driver_open/close().
 *
 * @param op
 *         The operation structure associated with the open or the
 *         close requested operation.  The driver should call the 
 *         appropriate finished operation to clean up this structure.
 *
 * @param result
 *         The result of the requested data operation
 *  
 * @param user_arg
 *         The user pointer that is threaded through to the callback.
 */
typedef void
(*globus_xio_driver_callback_t)(
    struct globus_i_xio_op_s *              op,
    globus_result_t                         result,
    void *                                  user_arg);


/**
 *  Data Callback interface
 *  @ingroup driver_pgm
 *
 *  This is the function signature of read and write operation 
 *  callbacks.  
 *
 * @param op
 *         The operation structure associated with the read or write
 *         operation request.  The driver should call the approriate
 *         finished operation when it receives this operation.
 *
 * @param result
 *         The result of the requested data operation
 *  
 * @param nbytes
 *         the number of bytes read or written
 *
 * @param user_arg
 *         The user pointer that is threaded through to the callback.
 */
typedef void
(*globus_xio_driver_data_callback_t)(
    struct globus_i_xio_op_s *              op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg);


typedef globus_result_t
(*globus_xio_driver_push_driver_t)(
    globus_xio_driver_t                     driver,
    globus_xio_stack_t                      stack);

globus_result_t
globus_xio_driver_attr_cntl(
    globus_xio_operation_t                  op,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);

globus_result_t
globus_xio_driver_data_descriptor_cntl(
    globus_xio_operation_t                  op,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);

globus_result_t
globus_xio_driver_handle_cntl(
    globus_xio_driver_handle_t              driver_handle,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);

globus_result_t
globus_xio_driver_server_cntl(
    globus_xio_driver_server_t              driver_server,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);

globus_result_t
globus_xio_driver_target_cntl(
    globus_xio_driver_target_t              driver_target,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...);

/**
 *  @ingroup driver_pgm
 */
typedef globus_result_t
(*globus_xio_driver_get_driver_t)(
    globus_xio_driver_t *                   out_driver);

/**
 *  @ingroup driver_pgm
 *  Driver attribute functions
 *
 *  If the driver wishes to provide driver specific attributes to the
 *  user it must implement the following functions:
 *
 *  globus_xio_driver_attr_init_t
 *  globus_xio_driver_attr_copy_t
 *  globus_xio_driver_attr_cntl_t
 *  globus_xio_driver_attr_destroy_t
 */
/**
 *  @ingroup driver_pgm
 *  Create a driver specific attribute.
 *
 *  The driver should implement this function to create a driver 
 *  specific attribute and return it via the out_attr parameter. 
 * 
 */
typedef globus_result_t
(*globus_xio_driver_attr_init_t)(
    void **                                 out_attr);

/**
 *  @ingroup driver_pgm
 *  Copy a driver attr.
 *
 *  When this function is called the driver will create a copy of the attr 
 *  in parameter src and place it in the parameter dst.
 */
typedef globus_result_t
(*globus_xio_driver_attr_copy_t)(
    void **                                 dst,
    void *                                  src);

/**
 *  @ingroup driver_pgm
 *  Destroy the driver attr.
 *
 *  Clean up all resources associate with the attr. 
 *
 */
typedef globus_result_t
(*globus_xio_driver_attr_destroy_t)(
    void *                                  driver_attr);

/**
 *  @ingroup driver_pgm
 *  get or set information in an attr.
 *
 *  The cmd parameter determines what functionality the user is requesting.
 *  The driver is resonsible for providing documentation to the user on
 *  all the possible values that cmd can be.
 *
 *  @param driver_attr
 *         The driver specific attr, created by 
 *         globus_xio_driver_attr_init_t.
 *
 *  @param cmd
 *         An integer representing what functionality the user is requesting.
 *
 *  @param ap
 *         variable arguments.  These are determined by the driver and the 
 *         value of cmd.
 */
typedef globus_result_t
(*globus_xio_driver_attr_cntl_t)(
    void *                                  attr,
    int                                     cmd,
    va_list                                 ap);

/**
 *  @ingroup driver_pgm
 *  Initialize a server object
 *
 *  The driver developer should implement this function if their driver
 *  handles server operations (pasive opens).  In the tcp driver this 
 *  function should create a listener.
 *
 *  @param out_server
 *         An output parameter.  Upon return from this function this
 *         should point to user defined memory that will serve as a 
 *         handle to this server object.
 *
 *  @param driver_attr
 *         A server attr if the user specified any driver specific 
 *         attributes.  This may be NULL.
 *
 *  @param driver_server
 *         A handle to the internal server object.  Can be used to perform
 *         operations on the server until globus_xio_driver_server_destroy_t
 *         is called upon it.  If the driver has no plans to use
 *         globus_xio_driver_server_cntl() or other functions that require
 *         this value for input then it can be ignored.
 */
typedef globus_result_t
(*globus_xio_driver_server_init_t)(
    void **                                 out_ds_server,
    void *                                  driver_attr);

/**
 *  @ingroup driver_pgm
 *  destroy a server.
 *
 *  When this function is called the driver should free up all resources
 *  associated with a server.
 *
 *  @param server
 *         The server that the driver should clean up.
 *
 *  @param driver_server
 *         The reference to the iunternal server that is being declaired
 *         invaild with this function call.
 */
typedef globus_result_t
(*globus_xio_driver_server_destroy_t)(
    void *                                  driver_server);

/**
 *  @ingroup driver_pgm
 *  Accept a server connection
 *
 *  The driver developer should implement this function if their driver 
 *  handles server operations.  Once the accept operation complets the
 *  connection is esstablished.  The user still has an opertunity to
 *  open the target or destroy it.  The can query the target for 
 *  additional information on which to base a decision to open upon.
 *
 *  @param driver_server
 *         The server object from which the target connection will be 
 *         accepted.
 *
 *  @param driver_attr
 *         If a driver specific attribute was set this will point to it.
 *         Ths parameter may be NULL.
 *
 *  @param op
 *         The reuqested operation.  When the driver is finished acepting
 *         the server connection it uses this structure to signal globus_xio 
 *         that it has completed the operation.
 */

typedef globus_result_t
(*globus_xio_driver_server_accept_t)(
    void *                                  driver_server,
    void *                                  driver_attr,
    globus_xio_operation_t                  accept_op);

globus_result_t
globus_xio_driver_pass_accept(
    globus_xio_operation_t                  in_op,
    globus_xio_driver_callback_t            in_cb,
    void *                                  in_user_arg);


/**
 *  @ingroup driver_pgm
 */
typedef void
(*globus_xio_driver_cancel_callback_t)(
    globus_xio_operation_t                  op,
    void *                                  user_arg);

/**
 *  @ingroup driver_pgm
 */
void
globus_xio_driver_enable_cancel(
    globus_xio_operation_t                  accept_op,
    globus_xio_driver_cancel_callback_t     cancel_cb,
    void *                                  user_arg);

/**
 *  @ingroup driver_pgm
 */
void
globus_xio_server_disable_cancel(
    globus_xio_operation_t                  op);

/**
 *  @ingroup driver_pgm
 *  Driver API finished accept
 *
 *  This function should be called to signal globus_xio that it has 
 *  completed the accept operation requested of it.  It will free up 
 *  resources associated with the accept_op and potientially cause xio
 *  to pop the signal up the driver stack.
 *
 *  @param accept_op
 *          The requested accept operation that has completed.
 *
 *  @param driver_target
 *          This is the initialized driver target that is required on success
 *          of this operation (if result != GLOBUS_SUCCESS, NULL ok)
 * 
 *  @param result
 *          Return status of the completed operation
 */
void
globus_xio_driver_finished_accept(
    globus_xio_operation_t                  accept_op,
    void *                                  driver_target,
    globus_result_t                         result);
    
/**
 *  @ingroup driver_pgm
 *  Query a server for information.
 *
 *  This function allows a user to request information from a driver
 *  specific server handle.
 *
 *  @param driver_server
 *         the server handle.
 *
 *  @param cmd
 *         An integer telling the driver what operation to preform on this
 *         server handle.
 *
 *  @param ap
 *         variable args.
 */
typedef globus_result_t
(*globus_xio_driver_server_cntl_t)(
    void *                                  driver_server,
    int                                     cmd,
    va_list                                 ap);


/**
 *  @ingroup driver_pgm
 *  Initalize a target.
 *
 *  This function is only called when the user is setting up a client
 *  target.  It does not imply any i/o operation will be preformed.  It
 *  mearly gives the driver a chance to set up memory for a client target.
 *
 *  @param out_target
 *         An output parameter.  upon return from this function this should
 *         point to a area of memory that will serve as a handle to the
 *         target.
 *
 *  @param driver_attr
 *         If the user added any driver specific attributes for this 
 *         operation this will point to a driver specific operation.
 *
 *  @param contact_string
 *         The contact string to which the user wishes to open a connection.
 *
 *  @param stack
 *         The stack object.  This contains information explaining
 *         the stack of drivers that the user wished to use.  I can be used
 *         to create driver_handles and will be valid until server_destroy is 
 *         called. 
 *
 *  @param driver_target
 *         The internal reference to the xio target.  If the driver will not
 *         be calling globus_xio_driver_target_cntl or other function that
 *         requires this paremeter, then it can be ignored.
 */
typedef globus_result_t
(*globus_xio_driver_target_init_t)(
    void **                                 out_target,
    void *                                  driver_attr,
    const char *                            contact_string);

/**
 *  @ingroup driver_pgm
 */
typedef globus_result_t
(*globus_xio_driver_target_cntl_t)(
    void *                                  driver_target,
    int                                     cmd,
    va_list                                 ap);

/**
 *  @ingroup driver_pgm
 *  destroy a target
 *
 *  The driver should clean up all resources associated with the target
 *  when this function is called.
 *
 *  @param driver_target
 *         The target to be destroyed.
 *
 *  @param driver_target
 *         The internal target reference that is invalid when this function
 *         returns.
 */
typedef globus_result_t
(*globus_xio_driver_target_destroy_t)(
    void *                                  driver_target);


/**********************************************************************
 *                          Open
 *********************************************************************/

/**
 *  Open a handle
 *  @ingroup driver_pgm
 *
 *  This is called when a user requests to close a handle.  The driver 
 *  implemntor should clean up all resources connected to there driver handle
 *  when this function is called.
 *
 *  @param driver_handle
 *          An unitialized pointer is passed in.  The driver will assign 
 *          this pointwe to some memory and then reference pass in back.
 *          Futrue interface funstion calls will be passed this value.
 *
 *  @param driver_attr
 *         A attribute describing how to open.  This points to a piece of 
 *         memory created by the globus_xio_driver_driver_attr_init_t
 *         interface funstion.
 *
 *  @param target
 *         Holds stack information and tells the user how to preform the
 *         open operation.
 * 
 *  @param server
 *         If a passive open is requested this will be the value passed 
 *         back by the drivers globus_xio_driver_server_init() function.
 *         If an active open has been requested this will be NULL.
 *
 *  @param contact_string
 *         This value will be NULL if a passive open is taking place.
 *         If it is not NULL an active open is requested and the this 
 *         parameter points to the contact string.
 *    
 *  @param op
 *         The reuqested operation.  When the driver is finished opening
 *         the handle it uses this structure to signal globus_xio that it
 *         has completed the operation requested.  It does this by calling
 *         globus_xio_driver_finished_open()
 *         
 */
typedef globus_result_t
(*globus_xio_driver_transform_open_t)(
    void *                                  driver_target,
    void *                                  driver_attr,
    globus_xio_operation_t                  op);

/**
 *  @ingroup driver_pgm
 *  transport open
 */
typedef globus_result_t
(*globus_xio_driver_transport_open_t)(
    void *                                  driver_target,
    void *                                  driver_attr,
    globus_xio_driver_handle_t              handle,
    globus_xio_operation_t                  op);

/**
 *  Driver API Open
 *  @ingroup driver_pgm
 *
 *  This function will pass an open request down the driver stack.
 *  Upon completion of the open operation globus_xio will call the callback 
 *  function.  At which point the handle structure will be intialized
 *  and available for use.
 *
 *  As soon as the function returns the handle is valid for creating 
 *  other operations.
 *
 *  @param handle
 *         Structure represening the state of the driver stack for this
 *         driver handle.
 *
 *  @param op
 *         The operation from which the handle will be established.  This
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
globus_xio_driver_pass_open(
    globus_xio_driver_handle_t *            handle,
    globus_xio_operation_t                  op,
    globus_xio_driver_callback_t            cb,
    void *                                  user_arg);

/**
 *  Driver API finished open
 *  @ingroup driver_pgm
 *
 *  This function should be called to signal globus_xio that it has 
 *  completed the open operation requested of it.  It will free up 
 *  resources associated with the open_op and potientially cause xio
 *  to pop the signal up the driver stack.
 *
 *  @param handle
 *         The opened handle that will be associated with future operations
 *         upon the handle.  useful if merging handles.  For the non
 *         advanced user this will always be the same value acieved
 *         from pass open.
 *
 *  @param open_op
 *          The requested open operation that has completed.
 *
 *  @param result
 *o         Return status of the completed operation
 */
void
globus_xio_driver_finished_open(
    globus_xio_driver_handle_t              handle,
    void *                                  driver_handle,
    globus_xio_operation_t                  open_op,
    globus_result_t                         result);

/**********************************************************************
 *                      Context functions
 *********************************************************************/
/**
 *  Driver API Create Operation
 *  @ingroup driver_pgm
 *
 *  This function will create an operation from an initialized handle
 *  This operation can then be used for io operations related to the
 *  handle that created them.
 *
 *   @param operation
 *          The operation to be created.  When this function returns
 *          this structure will be populated and available for use
 *          for the driver.
 *
 *   @param handle
 *          The initialized handle representing the user handle from
 *          which the operation will be created.
 *   
 */
globus_result_t
globus_xio_driver_operation_create(
    globus_xio_operation_t *                operation,
    globus_xio_driver_handle_t              driver_handle);

/**
 *  @ingroup driver_pgm
 */
void
globus_xio_driver_operation_destroy(
    globus_xio_operation_t                  operation);

/**
 *  @ingroup driver_pgm
 */
globus_result_t
globus_xio_driver_operation_cancel(
    globus_xio_operation_t                  operation);

/**
 *  Is Operation blocking.
 *  @ingroup driver_pgm
 *
 *  If the operation is blocking the driver developer may be able to make
 *  certian optimizations.  The function returns true if the given operation
 *  was created via a user call to a blocking funciton.
 */
globus_bool_t
globus_xio_driver_operation_is_blocking(
    globus_xio_operation_t                  operation);

/**
 *  @ingroup driver_pgm
 */
typedef globus_result_t
(*globus_xio_driver_handle_cntl_t)(
    void *                                  handle,
    int                                     cmd,
    va_list                                 ap);

/**********************************************************************
 *                          Close
 *********************************************************************/
/**
 *  Close an open handle
 *  @ingroup driver_pgm
 *
 *  This is called when a user requests to close a handle.  The driver 
 *  implemntor should clean up all resources connected to there driver handle
 *  when this function is called.
 *
 *  @param driver_specific_handle
 *          The driver handle to be closed.
 *
 *  @param driver_handle
 *         The driver_handle representing the globus_xio user handle that is
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
    void *                                  driver_specific_handle,
    void *                                  driver_attr,
    globus_xio_driver_handle_t              driver_handle,
    globus_xio_operation_t                  op);

/**
 *  Driver API Close
 *  @ingroup driver_pgm
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
globus_xio_driver_pass_close(
    globus_xio_operation_t                  op,
    globus_xio_driver_callback_t            cb,
    void *                                  user_arg);

/**
 *  Driver API finished_close
 *  @ingroup driver_pgm
 *
 *  The driver calls this function after completing a close operation
 *  on a driver_handle.  Once this function returns the driver_handle is 
 *  no longer 
 *  valid.
 *
 *  @param op
 *         The close operation that has completed.
 *
 *  @param result
 *          Return status of the completed operation
 */
void
globus_xio_driver_finished_close(
    globus_xio_operation_t                  op,
    globus_result_t                         result);

/**
 *  @ingroup driver_pgm
 *
 *  Close a driver_handle
 *
 *  Once a driver has finished using a driver_handle it should close it 
 *  to return the resources it is using to globus_xio.  In typical
 *  cases this function will be caled imediuately after calling 
 *  globus_xio_driver_finished_close().  However the driver is free
 *  tocache the driver_handle for use with handles that the user may possibily 
 *  open in the future.
 *
 *  @param driver_handle
 *         The driver_handle atd that the driver is finished using and wishes 
 *         to close.
 */
globus_result_t
globus_xio_driver_handle_close(
    globus_xio_driver_handle_t              driver_handle);

/**********************************************************************
 *                          Read
 *********************************************************************/
/**
 *  Read data from an open handle.
 *  @ingroup driver_pgm
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
    void *                                  driver_specific_handle,
    const globus_xio_iovec_t *              iovec,
    int                                     iovec_count,
    globus_xio_operation_t                  op);

/**
 *  Driver read
 *  @ingroup driver_pgm
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
 *  @param waitforbtyes
 *         The minimum number of bytes to read before returning... if a driver
 *         has no specifc requirement, he should use the user's request...
 *         available via GlobusXIOOperationMinimumRead(op)
 *  @param cb
 *         The function to be called when the operation request is 
 *         completed.
 *
 *  @param user_arg
 *         A user pointer that will be threaded through to the callback.
 */
globus_result_t
globus_xio_driver_pass_read(
    globus_xio_operation_t                  op,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           wait_for,
    globus_xio_driver_data_callback_t       cb,
    void *                                  user_arg);

/**
 *  Finished Read
 *  @ingroup driver_pgm
 *
 *  This function is called to signal globus_xio that the requested
 *  read operation has been completed.
 *
 *  @param op
 *         The operation structure representing the requested read
 *         operation.
 *
 *  @param result
 *          Return status of the completed operation
 * 
 *  @param nread
 *          The number of bytes read
 */
void
globus_xio_driver_finished_read(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nread);

/**********************************************************************
 *                          Write
 *********************************************************************/
/**
 *  Write data from an open handle.
 *  @ingroup driver_pgm
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
    void *                                  driver_specific_handle,
    const globus_xio_iovec_t *              iovec,
    int                                     iovec_count,
    globus_xio_operation_t                  op);

/**
 *  Driver write
 *  @ingroup driver_pgm
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
 *  @param waitforbtyes
 *         The minimum number of bytes to write before returning... if a driver
 *         has no specifc requirement, he should use the user's request...
 *         available via GlobusXIOOperationMinimumWrite(op)
 * 
 *  @param cb
 *         The function to be called when the operation request is 
 *         completed.
 *
 *  @param user_arg
 *         A user pointer that will be threaded through to the callback.
 */
globus_result_t
globus_xio_driver_pass_write(
    globus_xio_operation_t                  op,
    globus_xio_iovec_t *                    iovec,
    int                                     iovec_count,
    globus_size_t                           wait_for,
    globus_xio_driver_data_callback_t       cb,
    void *                                  user_arg);

/**
 *  Finished Write
 *  @ingroup driver_pgm
 *
 *  This function is called to signal globus_xio that the requested
 *  write operation has been completed.
 *
 *  @param op
 *         The operation structure representing the requested write
 *         operation.
 *
 *  @param result
 *          Return status of the completed operation
 * 
 *  @param nwritten
 *          The number of bytes written
 */
void
globus_xio_driver_finished_write(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nwritten);

/**
 *  Finishes an operation and merge to op structures.
 *  @ingroup driver_pgm
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
 *  (result is always success in this case.. if there is an error, use the
 * other finish() call)
 */
globus_result_t
globus_xio_driver_finished_from_previous(
    globus_xio_operation_t                  top_op,
    globus_xio_operation_t                  bottom_op);


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

globus_result_t
globus_xio_driver_init(
    globus_xio_driver_t *                   driver,
    const char *                            driver_name,
    void *                                  user_data);

/**
 *  @ingroup driver_pgm
 */
globus_result_t
globus_xio_driver_get_user_data(
    globus_xio_driver_t                     in_driver,
    void **                                 out_user_data);

/**
 *  @ingroup driver_pgm
 */
globus_result_t
globus_xio_driver_destroy(
    globus_xio_driver_t                     driver);

/**
 *  @ingroup driver_pgm
 */
globus_result_t
globus_xio_driver_set_transport(
    globus_xio_driver_t                     driver,
    globus_xio_driver_transport_open_t      transport_open_func,
    globus_xio_driver_close_t               close_func,
    globus_xio_driver_read_t                read_func,
    globus_xio_driver_write_t               write_func,
    globus_xio_driver_handle_cntl_t         handle_cntl_func);

/**
 *  @ingroup driver_pgm
 */
globus_result_t
globus_xio_driver_set_transform(
    globus_xio_driver_t                     driver,
    globus_xio_driver_transform_open_t      transform_open_func,
    globus_xio_driver_close_t               close_func,
    globus_xio_driver_read_t                read_func,
    globus_xio_driver_write_t               write_func,
    globus_xio_driver_handle_cntl_t         handle_cntl_func,
    globus_xio_driver_push_driver_t         push_driver_func);

/**
 *  @ingroup driver_pgm
 */
globus_result_t
globus_xio_driver_set_client(
    globus_xio_driver_t                     driver,
    globus_xio_driver_target_init_t         target_init_func,
    globus_xio_driver_target_cntl_t         target_cntl_func,
    globus_xio_driver_target_destroy_t      target_destroy_func);

/**
 *  @ingroup driver_pgm
 */
globus_result_t
globus_xio_driver_set_server(
    globus_xio_driver_t                     driver,
    globus_xio_driver_server_init_t         server_init_func,
    globus_xio_driver_server_accept_t       server_accept_func,
    globus_xio_driver_server_destroy_t      server_destroy_func,
    globus_xio_driver_server_cntl_t         server_cntl_func,
    globus_xio_driver_target_destroy_t      target_destroy_func);

/**
 *  @ingroup driver_pgm
 */
globus_result_t
globus_xio_driver_set_attr(
    globus_xio_driver_t                     driver,
    globus_xio_driver_attr_init_t           attr_init_func,
    globus_xio_driver_attr_copy_t           attr_copy_func,
    globus_xio_driver_attr_cntl_t           attr_cntl_func,
    globus_xio_driver_attr_destroy_t        attr_destroy_func);

#endif /* GLOBUS_XIO_DRIVER_H */
