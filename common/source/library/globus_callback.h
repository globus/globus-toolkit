#ifndef GLOBUS_INCLUDE_GLOBUS_CALLBACK
#define GLOBUS_INCLUDE_GLOBUS_CALLBACK
/**
 * @file globus_callback.h Globus Callback API
 *
 * $Source$<br />
 * $Date$<br />
 * $Revision$<br />
 * $Author$<br />
 */

/**
 * @defgroup globus_callback Globus Callback
 *
 *
 */
/* @{ */

#include "globus_common.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

extern globus_module_descriptor_t       globus_i_callback_module;

/**
 * @name Module Specific
 */
/* @{ */

/**
 * @hideinitializer
 *
 * Module descriptor for for globus_callback module.  Must be activated before
 * any of the following api is called.
 *
 * Note:  You would not normally activate this module directly.  Activating
 * the GLOBUS_COMMON_MODULE will in turn activate this also.
 */
#define GLOBUS_CALLBACK_MODULE (&globus_i_callback_module)

/**
 * @hideinitializer
 * @deprecated
 *
 * Backward compatible name
 */
#define GLOBUS_POLL_MODULE GLOBUS_CALLBACK_MODULE

/**
 * @hideinitializer
 *
 * Possible error types returned by the api in this module.  You can use the
 * error API to check results against these types.
 *
 * @see globus_generic_error_utility
 */
typedef enum
{
    /** The callback handle is not valid or it has already been destroyed */
    GLOBUS_CALLBACK_ERROR_INVALID_CALLBACK_HANDLE = 1024,
    /** The space handle is not valid or it has already been destroyed */
    GLOBUS_CALLBACK_ERROR_INVALID_SPACE,
    /** Could not allocate memory for an internal structure */
    GLOBUS_CALLBACK_ERROR_MEMORY_ALLOC,
    /** One of the arguments is NULL or out of range */
    GLOBUS_CALLBACK_ERROR_INVALID_ARGUMENT,
    /** Attempted a blocking cancel on a callback in the current stack */
    GLOBUS_CALLBACK_ERROR_BLOCKING_CANCEL_RUNNING,
    /** Attempt to unregister running callback, unregister will be defferred */
    GLOBUS_CALLBACK_ERROR_CANCEL_RUNNING,
    /** Attempt to retrieve info about a callback not in callers's stack */
    GLOBUS_CALLBACK_ERROR_NO_ACTIVE_CALLBACK,
    /** The behavior argument is out of range or not valid for this build */
    GLOBUS_CALLBACK_ERROR_INVALID_BEHAVIOR
} globus_callback_error_type_t;

/**
 * Handle for a periodic callback.  This handle can be copied or compared.
 */
typedef int                             globus_callback_handle_t;

/**
 * Handle for a callback space.  This handle can be copied or compared.
 */
typedef int                             globus_callback_space_t;

/**
 * Handle for a space attr.  This handle can be copied or compared.
 */
typedef int                             globus_callback_space_attr_t;
/* @} */

/**
 * @defgroup globus_callback_api Globus Callback API
 *
 *
 */
/* @{ */

/**
 * @name Convenience Macros
 */
/* @{ */
/**
 * @hideinitializer
 *
 * Specifies the global space for globus_callback_space_poll(). argument is
 * the timeout
 *
 * @see globus_callback_space_poll()
 */
#define globus_callback_poll(a)                                             \
    globus_callback_space_poll((a), GLOBUS_CALLBACK_GLOBAL_SPACE)

/**
 * @hideinitializer
 *
 * Specifies that globus_callback_space_poll() should poll on the global space
 * with an infinite timeout
 *
 * @see globus_callback_space_poll()
 */
#define globus_poll_blocking()                                              \
    globus_callback_poll(&globus_i_abstime_infinity)

/**
 * @hideinitializer
 *
 * Specifies that globus_callback_space_poll() should poll on the global space
 * with an imediate timeout (at most, one callback will be fired)
 *
 * @see globus_callback_space_poll()
 */
#define globus_poll_nonblocking()                                           \
    globus_callback_poll(&globus_i_abstime_zero)

/**
 * @hideinitializer
 *
 * Specifies that globus_callback_space_poll() should poll on the global space
 * with an imediate timeout (at most, one callback will be fired)
 *
 * @see globus_callback_space_poll()
 */
#define globus_poll()                                                       \
    globus_poll_nonblocking()

/**
 * @hideinitializer
 *
 * Counterpart to globus_poll().
 *
 * @see globus_callback_signal_poll()
 */
#define globus_signal_poll()                                                \
    globus_callback_signal_poll()

/**
 * @hideinitializer
 *
 * Specifies the global space for globus_callback_space_register_oneshot()
 * all other arguments are the same as specified there.
 *
 * @see globus_callback_space_register_oneshot()
 */
#define globus_callback_register_oneshot(a,b,c,d,e,f)                       \
    globus_callback_space_register_oneshot((a),(b),(c),(d),(e),(f),         \
        GLOBUS_CALLBACK_GLOBAL_SPACE)

/**
 * @hideinitializer
 *
 * Specifies the global space for
 * globus_callback_space_register_abstime_oneshot()
 * all other arguments are the same as specified there.
 *
 * @see globus_callback_space_register_abstime_oneshot()
 */
#define globus_callback_register_abstime_oneshot(a,b,c,d,e,f)               \
    globus_callback_space_register_abstime_oneshot((a),(b),(c),(d),(e),(f), \
        GLOBUS_CALLBACK_GLOBAL_SPACE)

/**
 * @hideinitializer
 *
 * Specifies the global space for globus_callback_space_register_periodic()
 * all other arguments are the same as specified there.
 *
 * @see globus_callback_space_register_periodic()
 */
#define globus_callback_register_periodic(a,b,c,d,e,f,g)                    \
    globus_callback_space_register_periodic((a),(b),(c),(d),(e),(f),(g),    \
        GLOBUS_CALLBACK_GLOBAL_SPACE)
/* @} */

/**
 * @name Callback Prototypes
 */
/* @{ */

/**
 * Globus callback prototype
 *
 * This is the signature of the function registered with the 
 * globus_callback_register_* calls.
 *
 * If this is a periodic callback, it is guaranteed that the call canNOT
 * be reentered unless globus_thread_blocking_space_will_block() is called
 * (explicitly, or implicitly via globus_cond_wait()).  Also, if
 * globus_callback_unregister() is called to cancel this periodic from within 
 * this callback, it is guaranteed that the callback will NOT be requeued again
 * (will still return GLOBUS_CALLBACK_ERROR_CANCEL_RUNNING).
 *
 * @param time_now
 *        The current time
 *
 * @param time_stop
 *        The timeout for this callback.  The user either must not violate this
 *        timeout, or he must call globus_thread_blocking_space_will_block()
 *
 * @param user_args
 *        The user argument registered with this callback
 *
 * @return
 *        - void
 * 
 * @see globus_callback_space_register_oneshot()
 * @see globus_callback_space_register_abstime_oneshot()
 * @see globus_callback_space_register_periodic()
 * @see globus_thread_blocking_space_will_block()
 */
typedef
void
(*globus_callback_func_t)(
    const globus_abstime_t *            time_now,
    const globus_abstime_t *            time_stop,
    void *                              user_args);

/**
 * Globus wakeup callback prototype
 *
 * This is the signature of the wake up function registered with the 
 * globus_callback_register_* calls.  When this function is called, the user
 * must terminate any callback he has running that was registered with this
 * wakeup function
 *
 * @param user_args
 *        The user argument registered with this wakeup callback
 *
 * @return
 *        - void
 * 
 * @see globus_callback_space_register_oneshot()
 * @see globus_callback_space_register_abstime_oneshot()
 * @see globus_callback_space_register_periodic()
 */
typedef
void
(*globus_callback_wakeup_func_t)(
    void *                              user_args);

/**
 * Globus unregister callback prototype
 *
 * The callback registered with globus_callback_unregister().
 * This is called when the user's callback had been canceled and will NOT run
 * any more.
 *
 * @param user_args
 *        The user argument registered with this unregister callback
 *
 * @return
 *        - void
 * 
 * @see globus_callback_unregister()
 */
typedef
void
(*globus_callback_unregister_func_t)(
    void *                              user_args);
/* @} */

/**
 * @name Oneshot Callbacks
 */
/* @{ */

/**
 * Register a oneshot some delay from now
 *
 * This function registers the callback_func to start some delay_time from
 * now.  
 *
 * @param callback_handle
 *        Storage for a handle.  This may be NULL.  If it is NOT NULL, you
 *        must unregister the callback to reclaim resources.
 *
 * @param delay_time
 *        The relative time from now to fire this callback
 *
 * @param callback_func
 *        the user func to call
 *
 * @param callback_user_args
 *        user args that will be passed to callback
 *
 * @param wakeup_func
 *        if this is NOT NULL, then this callback will run in its own thread
 *        this function will be called when it is necessary to terminate that
 *        thread.
 *
 *        Note:  This and the following arguments are ignored on non-threaded
 *        builds.
 *
 * @param wakeup_user_args
 *        user args that will be passed to the wakeup callback
 *
 * @param space
 *        The space with which to register this callback
 *
 * @return
 *        - GLOBUS_CALLBACK_ERROR_INVALID_ARGUMENT
 *        - GLOBUS_CALLBACK_ERROR_MEMORY_ALLOC
 *        - GLOBUS_SUCCESS
 * 
 * @see globus_callback_func_t
 * @see globus_callback_wakeup_func_t
 * @see globus_callback_spaces
 */
globus_result_t
globus_callback_space_register_oneshot(
    globus_callback_handle_t *          callback_handle,
    const globus_reltime_t *            delay_time,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_callback_wakeup_func_t       wakeup_func,
    void *                              wakeup_user_args,
    globus_callback_space_t             space);

/**
 * Register a oneshot for a specific time
 *
 * This function registers the callback_func to start at a specific time
 *
 * @param callback_handle
 *        Storage for a handle.  This may be NULL.  If it is NOT NULL, you
 *        must unregister the callback to reclaim resources.
 *
 * @param start_time
 *        The absolute time to fire this callback
 *
 * @param callback_func
 *        the user func to call
 *
 * @param callback_user_args
 *        user args that will be passed to callback
 *
 * @param wakeup_func
 *        if this is NOT NULL, then this callback will run in its own thread
 *        this function will be called when it is necessary to terminate that
 *        thread.
 *
 *        Note:  This and the following arguments are ignored on non-threaded
 *        builds.
 *
 * @param wakeup_user_args
 *        user args that will be passed to the wakeup callback
 *
 * @param space
 *        The space with which to register this callback
 *
 * @return
 *        - GLOBUS_CALLBACK_ERROR_INVALID_ARGUMENT
 *        - GLOBUS_CALLBACK_ERROR_MEMORY_ALLOC
 *        - GLOBUS_SUCCESS
 * 
 * @see globus_callback_func_t
 * @see globus_callback_wakeup_func_t
 * @see globus_callback_spaces
 */
globus_result_t
globus_callback_space_register_abstime_oneshot(
    globus_callback_handle_t *          callback_handle,
    const globus_abstime_t *            start_time,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_callback_wakeup_func_t       wakeup_func,
    void *                              wakeup_user_args,
    globus_callback_space_t             space);
/* @} */

/**
 * @name Periodic Callbacks
 */
/* @{ */

/**
 * Register a periodic callback
 *
 * This function registers a periodic callback_func to start some delay_time 
 * and run every period from then.
 *
 * @param callback_handle
 *        Storage for a handle.  This may be NULL.  If it is NOT NULL, you
 *        must cancel the periodic to reclaim resources.
 *
 * @param delay_time
 *        The relative time from now to fire this callback
 *
 * @param period
 *        The relative period of this callback
 *
 * @param callback_func
 *        the user func to call
 *
 * @param callback_user_args
 *        user args that will be passed to callback
 *
 * @param wakeup_func
 *        if this is NOT NULL, then this callback will run in its own thread
 *        this function will be called when it is necessary to terminate that
 *        thread.
 *
 * @param wakeup_user_args
 *        user args that will be passed to the wakeup callback
 *
 * @param space
 *        The space with which to register this callback
 *
 * @return
 *        - GLOBUS_CALLBACK_ERROR_INVALID_ARGUMENT
 *        - GLOBUS_CALLBACK_ERROR_MEMORY_ALLOC
 *        - GLOBUS_SUCCESS
 * 
 * @see globus_callback_unregister()
 * @see globus_callback_func_t
 * @see globus_callback_wakeup_func_t
 * @see globus_callback_spaces
 */
globus_result_t
globus_callback_space_register_periodic(
    globus_callback_handle_t *          callback_handle,
    const globus_reltime_t *            delay_time,
    const globus_reltime_t *            period,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_callback_wakeup_func_t       wakeup_func,
    void *                              wakeup_user_args,
    globus_callback_space_t             space);

/**
 * Unregister a callback
 *
 * This function will cancel a callback and free the resources 
 * associcated with the callback handle.  If the callback was able to be 
 * canceled immediately, GLOBUS_SUCCESS is returned and it is guaranteed that
 * there are no running instances of the callback. 
 *
 * If the callback is currently running (or unstoppably about to be run), then
 * the unregister is prevented from being requeued, but, the 'official' cancel
 * is defferred until the last running instance of the callback returns  In 
 * this case, GLOBUS_CALLBACK_ERROR_CANCEL_RUNNING is returned.  (This is an 
 * informative error) If you need to know when the callback is guaranteed to 
 * have been canceled, pass an unregister callback.
 *
 * @param callback_handle
 *        the handle received from a globus_callback_space_register_*()
 *        call
 *
 * @param unregister_callback
 *        the function to call when the callback has been canceled and
 *        there are no running instances of it
 *
 * @param unreg_args
 *        user args that will be passed to the unregister callback
 *
 * @return
 *        - GLOBUS_CALLBACK_ERROR_INVALID_CALLBACK_HANDLE
 *        - GLOBUS_CALLBACK_ERROR_CANCEL_RUNNING
 *        - GLOBUS_SUCCESS
 * 
 * @see globus_callback_space_register_periodic()
 * @see globus_callback_unregister_func_t
 */
globus_result_t
globus_callback_unregister(
    globus_callback_handle_t            callback_handle,
    globus_callback_unregister_func_t   unregister_callback,
    void *                              unreg_args);

/**
 * Block, canceling a callback
 *
 * This function will block until a callback has been canceled.
 * It is an error to call this function within the callback to be canceled.  In
 * this case (if you havent called globus_thread_blocking_space_will_block()
 * or globus_cond_wait()) just call globus_callback_unregister()
 * with a NULL unregister callback.  The callback will not be fired again.
 *
 * @param callback_handle
 *        the handle received from a globus_callback_space_register_periodic()
 *        call
 *
 * @return
 *        - GLOBUS_CALLBACK_ERROR_INVALID_CALLBACK_HANDLE
 *        - GLOBUS_CALLBACK_ERROR_BLOCKING_CANCEL_RUNNING
 *        - GLOBUS_SUCCESS
 * 
 * @see globus_callback_space_register_periodic()
 */
globus_result_t
globus_callback_blocking_unregister(
    globus_callback_handle_t            callback_handle);

/**
 * Adjust the period of a periodic callback.
 *
 * This function allows a user to adjust the period of a previously
 * registered callback.  It is safe to call this within or outside of
 * the callback that is being modified.
 *
 * This func also allows a user to effectively 'suspend' a periodic callback
 * until another time by passing a period of NULL.  The callback can later
 * be resumed by passing in a new period.
 *
 * Note that the new period (or suspension) will take place 'as soon as
 * possible'.  If the callback was previously suspended, it will be fired no
 * sooner than new_period from now. A 'suspended' callback
 * must still be canceled to free its resources.
 *
 * @param callback_handle
 *        the handle received from a globus_callback_space_register_periodic()
 *        call
 *
 * @param period
 *        The new period.  If NULL or globus_i_reltime_infinity, then
 *        callback will be 'suspended' as soon as the last running instance of
 *        it returns.
 *
 * @return
 *        - GLOBUS_CALLBACK_ERROR_INVALID_CALLBACK_HANDLE
 *        - GLOBUS_SUCCESS
 * 
 * @see globus_callback_space_register_periodic()
 */
globus_result_t
globus_callback_adjust_period(
    globus_callback_handle_t            callback_handle,
    const globus_reltime_t *            new_period);
/* @} */

/**
 * @name Callback Polling
 */
/* @{ */

/**
 * Poll for ready callbacks
 *
 * This function is used to poll for registered callbacks.  
 *
 * For non-threaded builds, callbacks are not/can not be delivered unless this
 * is called.  Any call to this can cause callbacks registered with the 
 * 'global' space to be fired.  Whereas callbacks registered with a user's 
 * space will only be delivered when this is called with that space.
 *
 * For threaded builds, this only needs to be called to poll user spaces with
 * behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED.  The 'global' space
 * and user spaces with behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_THREADED
 * are constantly polled in a separate thread.  (If it is called in a threaded
 * build for these spaces, it will just yield its thread)
 *
 * In general, you never need to call this function directly.  It is called
 * (when necessary) by globus_cond_wait().  The only case in which a user may
 * wish to call this explicitly is if the application has no aspirations of 
 * ever being built threaded.
 *
 * This function (when not yielding) will block up to timestop or until 
 * globus_callback_signal_poll() is called by one of the fired callbacks.  It
 * will always try and kick out one ready callback, regardless of the timestop.
 *
 * @param timestop
 *        The time to block until.  If this is NULL or less than the cuurent
 *        time, an attempt to fire one ready callback is made.
 *
 * @param space
 *        The callback space to poll.  Note: regardless of what space is passed
 *        here, the 'global' space is also always polled.
 *
 * @return
 *        - void
 * 
 * @see globus_callback_spaces
 */
void
globus_callback_space_poll(
    const globus_abstime_t *            timestop,
    globus_callback_space_t             space);

/**
 * Signal the poll
 *
 * This function signals globus_callback_space_poll() that something has
 * changed and it should return to its caller as soon as possible.
 *
 * In general, you never need to call this function directly.  It is called
 * (when necessary) by globus_cond_signal() or globus_cond_broadcast.  The only
 * case in which a user may wish to call this explicitly is if the application 
 * has no aspirations of ever being built threaded.
 *
 * @return
 *        - void
 * 
 * @see globus_callback_space_poll()
 */
void
globus_callback_signal_poll();
/* @} */

/**
 * @name Miscellaneous
 */
/* @{ */

/**
 * Get the amount of time left in a callback
 *
 * This function retrieves the remaining time a callback is allowed to run.
 * If a callback has already timed out, time_left will be set to zero and
 * GLOBUS_TRUE returned.  This function is intended to be called within a 
 * callback's stack, but is harmless to call anywhere (will return 
 * GLOBUS_FALSE and an infinite time_left)
 *
 * @param time_left
 *        storage for the remaining time.  If this is NULL, this function
 *        behaves similarly to globus_callback_has_time_expired()
 *
 * @return
 *        - GLOBUS_FALSE if time remaining
 *        - GLOBUS_TRUE if already timed out
 */
globus_bool_t
globus_callback_get_timeout(
    globus_reltime_t *                  time_left);

/**
 * See if there is remaining time in a callback
 *
 * This function returns GLOBUS_TRUE if the running time of a callback has
 * already expired.  This function is intended to be called within a callback's
 * stack, but is harmless to call anywhere (will return GLOBUS_FALSE)
 *
 * @return
 *        - GLOBUS_FALSE if time remaining
 *        - GLOBUS_TRUE if already timed out
 */
globus_bool_t
globus_callback_has_time_expired();

/**
 * See if a callback has been restarted.
 *
 * If the callback is a oneshot, this merely means the callback called 
 * globus_thread_blocking_space_will_block (or globus_cond_wait() at 
 * some point.
 *
 * For a periodic, it signifies the same and also that the periodic has been
 * requeued.  This means that the callback function may be reentered if the
 * period is short enough (on a threaded build)
 *
 * @return
 *        - GLOBUS_FALSE if not restarted
 *        - GLOBUS_TRUE if restarted
 * 
 * @see something_else
 */
globus_bool_t
globus_callback_was_restarted();
/* @} */
/* @} */

/**
 * @defgroup globus_callback_spaces Globus Callback Spaces
 *
 *
 */
/* @{ */
/**
 * @hideinitializer
 *
 * The 'global' space handle.
 *
 * This is the default space handle implied if no spaces are 
 * explicitly created.
 */
#define GLOBUS_CALLBACK_GLOBAL_SPACE -1


/**
 * Callback space behaviors
 */
typedef enum
{
    GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED,  /* default */
    GLOBUS_CALLBACK_SPACE_BEHAVIOR_THREADED
} globus_callback_space_behavior_t;

/**
 * brief_desc
 *
 * long_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @return
 *        - possible_return
 *        - possible_return
 * 
 * @see something_else
 */
globus_result_t
globus_callback_space_init(
    globus_callback_space_t *           space,
    globus_callback_space_attr_t        attr);

/**
 * brief_desc
 *
 * long_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @return
 *        - possible_return
 *        - possible_return
 * 
 * @see something_else
 */
globus_result_t
globus_callback_space_destroy(
    globus_callback_space_t             space);

/**
 * brief_desc
 *
 * long_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @return
 *        - possible_return
 *        - possible_return
 * 
 * @see something_else
 */
globus_result_t
globus_callback_space_attr_init(
    globus_callback_space_attr_t *      attr);

/**
 * brief_desc
 *
 * long_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @return
 *        - possible_return
 *        - possible_return
 * 
 * @see something_else
 */
globus_result_t
globus_callback_space_attr_destroy(
    globus_callback_space_attr_t        attr);

/**
 * brief_desc
 *
 * long_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @return
 *        - possible_return
 *        - possible_return
 * 
 * @see something_else
 */
globus_result_t
globus_callback_space_attr_set_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t    behavior);

/**
 * brief_desc
 *
 * long_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @return
 *        - possible_return
 *        - possible_return
 * 
 * @see something_else
 */
globus_result_t
globus_callback_space_attr_get_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t *  behavior);

/**
 * brief_desc
 *
 * long_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @return
 *        - possible_return
 *        - possible_return
 * 
 * @see something_else
 */
globus_bool_t
globus_callback_space_is_valid(
    globus_callback_space_t             space);

/**
 * brief_desc
 *
 * long_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @param arg_name
 *        arg_desc
 *
 * @return
 *        - possible_return
 *        - possible_return
 * 
 * @see something_else
 */
globus_result_t
globus_callback_space_get(
    globus_callback_space_t *           space);
/* @} */

EXTERN_C_END

/* @} */

#endif /* GLOBUS_INCLUDE_GLOBUS_CALLBACK */
