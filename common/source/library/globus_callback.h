#ifndef GLOBUS_INCLUDE_GLOBUS_CALLBACK
#define GLOBUS_INCLUDE_GLOBUS_CALLBACK

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

#define GLOBUS_CALLBACK_MODULE (&globus_i_callback_module)
#define GLOBUS_POLL_MODULE GLOBUS_CALLBACK_MODULE

#define GLOBUS_CALLBACK_GLOBAL_SPACE -1

typedef enum
{
    GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED,  /* default */
    GLOBUS_CALLBACK_SPACE_BEHAVIOR_THREADED
} globus_callback_space_behavior_t;

typedef enum
{
    GLOBUS_CALLBACK_ERROR_INVALID_CALLBACK_HANDLE = 1024,
    GLOBUS_CALLBACK_ERROR_INVALID_SPACE,
    GLOBUS_CALLBACK_ERROR_MEMORY_ALLOC,
    GLOBUS_CALLBACK_ERROR_INVALID_ARGUMENT,
    GLOBUS_CALLBACK_ERROR_BLOCKING_CANCEL_RUNNING,
    GLOBUS_CALLBACK_ERROR_NO_ACTIVE_CALLBACK,
    GLOBUS_CALLBACK_ERROR_INVALID_BEHAVIOR
} globus_callback_error_type_t;

typedef int                             globus_callback_handle_t;
typedef int                             globus_callback_space_t;
typedef int                             globus_callback_space_attr_t;

typedef
void
(*globus_callback_func_t)(
    const globus_abstime_t *            time_now,
    const globus_abstime_t *            time_stop,
    void *                              user_args);

typedef
void
(*globus_wakeup_func_t)(
    void *                              user_args);

typedef
void
(*globus_unregister_callback_func_t)(
    void *                              user_args);

/* compatibility aliases */

#define globus_callback_poll(x)                                             \
    globus_callback_space_poll((x), GLOBUS_CALLBACK_GLOBAL_SPACE)

#define globus_poll_blocking()                                              \
    globus_callback_poll(&globus_i_abstime_infinity)

#define globus_poll_nonblocking()                                           \
    globus_callback_poll(&globus_i_abstime_zero)

#define globus_poll()                                                       \
    globus_poll_nonblocking()

#define globus_signal_poll()                                                \
    globus_callback_signal_poll()

#define globus_callback_register_oneshot(a,b,c,d,e)                         \
    globus_callback_space_register_oneshot((a),(b),(c),(d),(e),             \
        GLOBUS_CALLBACK_GLOBAL_SPACE)

#define globus_callback_register_periodic(a,b,c,d,e,f,g)                    \
    globus_callback_space_register_periodic((a),(b),(c),(d),(e),(f),(g),    \
        GLOBUS_CALLBACK_GLOBAL_SPACE)

#define globus_callback_register_abstime_oneshot(a,b,c,d,e)                 \
    globus_callback_space_register_abstime_oneshot((a),(b),(c),(d),(e),     \
        GLOBUS_CALLBACK_GLOBAL_SPACE)

globus_result_t
globus_callback_space_register_oneshot(
    const globus_reltime_t *            delay_time,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_wakeup_func_t                wakeup_func,
    void *                              wakeup_user_args,
    globus_callback_space_t             space);

globus_result_t
globus_callback_space_register_periodic(
    globus_callback_handle_t *          callback_handle,
    const globus_reltime_t *            delay_time,
    const globus_reltime_t *            period,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_wakeup_func_t                wakeup_func,
    void *                              wakeup_user_args,
    globus_callback_space_t             space);

globus_result_t
globus_callback_space_register_abstime_oneshot(
    const globus_abstime_t *            start_time,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_wakeup_func_t                wakeup_func,
    void *                              wakeup_user_args,
    globus_callback_space_t             space);

globus_result_t
globus_callback_register_cancel_periodic(
    globus_callback_handle_t            callback_handle,
    globus_unregister_callback_func_t   unregister_callback,
    void *                              unreg_args);

globus_result_t
globus_callback_blocking_cancel_periodic(
    globus_callback_handle_t            callback_handle);

globus_result_t
globus_callback_adjust_period(
    globus_callback_handle_t            handle,
    const globus_reltime_t *            period);

globus_result_t
globus_callback_space_init(
    globus_callback_space_t *           space,
    globus_callback_space_attr_t        attr);

globus_result_t
globus_callback_space_destroy(
    globus_callback_space_t             space);

globus_bool_t
globus_callback_space_is_valid(
    globus_callback_space_t             space);

globus_result_t
globus_callback_space_attr_init(
    globus_callback_space_attr_t *      attr);

globus_result_t
globus_callback_space_attr_destroy(
    globus_callback_space_attr_t        attr);

globus_result_t
globus_callback_space_attr_set_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t    behavior);

globus_result_t
globus_callback_space_attr_get_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t *  behavior);

void
globus_callback_space_poll(
    const globus_abstime_t *            timestop,
    globus_callback_space_t             space);

void
globus_callback_signal_poll();

globus_result_t
globus_callback_get_space(
    globus_callback_space_t *           space);
    
globus_bool_t
globus_callback_get_timeout(
    globus_reltime_t *                  time_left);

globus_bool_t
globus_callback_get_timestop(
    globus_abstime_t *                  time_stop);

globus_bool_t
globus_callback_has_time_expired();

globus_bool_t
globus_callback_was_restarted();

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_CALLBACK */
