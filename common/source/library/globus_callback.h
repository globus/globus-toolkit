/******************************************************************************
globus_callback.h

Description:

CVS Information:

  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/

/**
 *  Globus Callback
 *  ---------------
 */
#if !defined(GLOBUS_INCLUDE_GLOBUS_CALLBACK_H)
#define GLOBUS_INCLUDE_GLOBUS_CALLBACK_H

/******************************************************************************
			             Include header files
******************************************************************************/
#include "globus_common_include.h"
#include "globus_time.h"
#include GLOBUS_THREAD_INCLUDE

/***************************************************************************
 *                              Macros
 **************************************************************************/

/**
 *  Block until an event occurs.
 */
#define globus_poll_blocking()                                              \
    globus_callback_poll((globus_abstime_t *)&globus_i_abstime_infinity)
/**
 *  nonblock poll.  Check to see if an event is ready but do not block
 */
#define globus_poll_nonblocking()                                           \
{                                                                           \
    globus_callback_poll((globus_abstime_t *)&globus_i_abstime_zero);       \
}

/**
 *  nonblocking poll.
 */
#define globus_poll()                                                       \
    globus_poll_nonblocking()

/**
 *  Unregister a callback.
 *  This will unregister a callback function.  It is a non blocking operation.
 */
#define globus_callback_unregister(handle)                                  \
    globus_i_callback_register_cancel(&(handle), GLOBUS_NULL, GLOBUS_NULL)

EXTERN_C_BEGIN

/******************************************************************************
			       Type definitions
******************************************************************************/
/**
 *  globus_callback handle.
 *  -----------------------
 *  This datatype allows the user to reference a registered callback.
 */
typedef int                                 globus_callback_handle_t;

/**
 *  A callback function definition.
 */
typedef
globus_bool_t
(*globus_callback_func_t)(
    globus_abstime_t * const                time_stop,
    void *                                  user_args);

/**
 *  a wakeup function definition.
 *  The wakeup function is used to alert a threaded callback that it must end soon.
 *  A threaded callback is given its own thread to consume, therefore the user can 
 *  allow it run enteranlly.  The wakeup function notion provides a way to asychronously
 *  signal the callback that it may no longer run.  This generally only happens when the
 *  callback module is deactivated.
 */
typedef
void
(*globus_wakeup_func_t)(
    void *                              user_args);

/**
 *  This callback is used to signal the user that their unregister operation has 
 *  completed.
 */
typedef
void
(*globus_unregister_callback_func_t)(
    void *                              user_args);

/******************************************************************************
			      Function prototypes
******************************************************************************/

/**
 *  Register a oneshot callback.
 *
 *  This will register callback_func to be called once delay_time has expired.
 *  The function may be called in more than delay_time, but will not be called
 *  in less.  The function will only be called once.
 *
 *  @param  callback_handle
 *          a reference to this registered event.  This variable can be used
 *          to cancel the callback at a later time.  This value may be NULL.  If this 
 *          value is not null the user must destroy their reference to it by calling
 *          globus_callback_handle_destroy().       
 *
 *  @param delay_time
 *         The amount of time the system will wait before calling this callback.
 *
 *  @param callback_func
 *         The function the system will call.
 *
 *  @param callback_user_args
 *         user argument that will be threaded through to the callback.
 *
 *  @param wakeup_func
 *         The wakeup function.  If this value is non-null a thread will
 *         be devote to the execution of this callback.  When the wake up 
 *         function is called the user must allow the thread to end.
 *
 *  @param wakeup_usr_args
 *         a user argument that willbe threaded through to the wakeup function.
 */
globus_result_t
globus_callback_register_oneshot(
    globus_callback_handle_t *              callback_handle,    
    globus_reltime_t *                      delay_time,
    globus_callback_func_t		            callback_func,
    void *                                  callback_user_args,
    globus_wakeup_func_t                    wakeup_func,
    void *                                  wakeup_user_args);

/**
 *  Register a periodic callback.
 *
 *  This will register callback_func to be called once delay_time has expired, 
 *  and at every period_time interval.
 *  The function may be called in more than delay_time, but will not be called
 *  in less.  The function will only be periodically according to period_time
 *  until canceled or until this module is deactivated.
 *
 *  @param  callback_handle
 *          a reference to this registered event.  This variable can be used
 *          to cancel the callback at a later time.  This value may be NULL.  If this 
 *          value is not null the user must destroy their reference to it by calling
 *          globus_callback_handle_destroy().       
 *
 *  @param delay_time
 *         The amount of time the system will wait before calling this callback.
 *
 *  @param period_time
 *         The amount of time inbtween calls to this callback.
 *
 *  @param callback_func
 *         The function the system will call.
 *
 *  @param callback_user_args
 *         user argument that will be threaded through to the callback.
 *
 *  @param wakeup_func
 *         The wakeup function.  If this value is non-null a thread will
 *         be devote to the execution of this callback.  When the wake up 
 *         function is called the user must allow the thread to end.
 *
 *  @param wakeup_usr_args
 *         a user argument that willbe threaded through to the wakeup function.
 */
globus_result_t
globus_callback_register_periodic(
    globus_callback_handle_t *              callback_handle,    
    globus_reltime_t *                      delay_time,
    globus_reltime_t *                      period_time,
    globus_callback_func_t        	        callback_func,
    void *                                  callback_user_args,
    globus_wakeup_func_t                    wakeup_func,
    void *                                  wakeup_user_args);

/**
 *  Destroy the user reference to the callback handle.
 *
 *  If a callback was registered with a callback handle the user must 
 *  destroy the handle.
 *
 *  TODO: add a globus_callback_handle_init() for symetry.
 */
globus_result_t
globus_callback_handle_destroy(
   globus_callback_handle_t *               callback_handle);

/**
 *  Allow the callback system to poll its events.  The callback code
 *  is allowed to block until timestop expires.
 */
void
globus_callback_poll(
    globus_abstime_t *                      timestop);

/**
 *  Allow the callback system to poll its events.  The callback code
 *  is allowed to block until timestop expires.
 */
void
globus_poll_timeout(
    globus_abstime_t *                      abstimestop);

/**
 *  Get the amount of time for which the callback may continue to block.
 *
 *  When a callback is called one of its parameters is how long it is allowed to
 *  block.  This function will populate time_left how much longer the current callback may block.
 *  This function must be called from a callback.  It returns a boolean
 *  indicating whether or not time has expired.
 */
globus_bool_t
globus_callback_get_timeout(
    globus_reltime_t *                      time_left);

/**
 *  Get the absolute time by when the current callback must return.
 *
 *  When a callback is called one of its parameters is how long it is allowed to
 *  block.  This function populate tim_stop with the absolute time when the callback
 *  must return.  This function must be called from a callback.  It returns a boolean
 *  indicating whether or not time has expired.
 *
 */
globus_bool_t
globus_callback_get_timestop(  
    globus_abstime_t *                      time_stop);

/**
 *  Return a boolan indicating whether or not this callbacks run time has expired.
 *  When a callback is called one of its parameters is how long it is allowed to
 *  block.  When this function returns true, time has expired. 
 */
globus_bool_t
globus_callback_has_time_expired();

/**
 *
 */
globus_bool_t
globus_callback_was_restarted();

/**
 *  This function allows the user to adjust the time period associated with a callback
 *  on the fly.
 */
globus_bool_t
globus_callback_adjust_period(
    globus_callback_handle_t *               handle,
    globus_reltime_t *                       period);

/*
 *  internal functions
 */
int
globus_i_callback_register_cancel(
    globus_callback_handle_t *              calback_handle,
    globus_unregister_callback_func_t       unregister_callback,
    void *                                  unreg_args);

int
globus_i_callback_blocking_cancel(
    globus_callback_handle_t *              callback_handle);

void
globus_i_unregister_callback(
    void *                                  user_args);

/******************************************************************************
 *		       Module definition
 ******************************************************************************/
extern globus_module_descriptor_t	globus_i_callback_module;

#define GLOBUS_CALLBACK_MODULE (&globus_i_callback_module)
#define GLOBUS_POLL_MODULE     (&globus_i_callback_module)

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_CALLBACK */


