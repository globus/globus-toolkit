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

#if !defined(GLOBUS_INCLUDE_GLOBUS_CALLBACK)
#define GLOBUS_INCLUDE_GLOBUS_CALLBACK

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common.h"

#define globus_poll_blocking()     globus_callback_poll((globus_abstime_t *)&globus_i_abstime_infinity)
#define globus_poll_nonblocking()                    \
{                                                    \
    globus_callback_poll((globus_abstime_t *)&globus_i_abstime_zero); \
}

#define globus_poll()              globus_poll_nonblocking()

#define globus_callback_unregister(handle)  \
globus_i_callback_register_cancel(&(handle), GLOBUS_NULL, GLOBUS_NULL)


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

/******************************************************************************
			       Type definitions
******************************************************************************/

/******************************************************************************
                               handle stuff
******************************************************************************/
typedef int                globus_callback_handle_t;

void
print_inside_info(int type);

typedef
globus_bool_t
(*globus_callback_func_t)(
    globus_abstime_t *                  time_stop,
    void *                              user_args);

typedef
void
(*globus_wakeup_func_t)(
    void *                              user_args);

typedef
void
(*globus_unregister_callback_func_t)(
    void *                              user_args);

/******************************************************************************
			      Function prototypes
******************************************************************************/

int
globus_callback_register_oneshot(
    globus_callback_handle_t *          callback_handle,    
    globus_reltime_t *                  delay_time,
    globus_callback_func_t		callback_func,
    void *                              callback_user_args,
    globus_wakeup_func_t                wakeup_func,
    void *                              wakeup_user_args);

int
globus_callback_register_periodic(
    globus_callback_handle_t *          callback_handle,    
    globus_reltime_t *                  delay_time,
    globus_reltime_t *                  period,
    globus_callback_func_t        	callback_func,
    void *                              callback_user_args,
    globus_wakeup_func_t                wakeup_func,
    void *                              wakeup_user_args);

int
globus_i_callback_register_cancel(
    globus_callback_handle_t *          calback_handle,
    globus_unregister_callback_func_t   unregister_callback,
    void *                              unreg_args);

int
globus_i_callback_blocking_cancel(
    globus_callback_handle_t *          callback_handle);

void
globus_i_unregister_callback(
    void *                              user_args);

globus_result_t
globus_callback_handle_destroy(
   globus_callback_handle_t *          calback_handle);

void
globus_callback_poll(
    globus_abstime_t *           timestop);

void
globus_poll_timeout(
    globus_abstime_t *                  abstimestop);

globus_bool_t
globus_callback_get_timeout(globus_reltime_t * time_left);

globus_bool_t
globus_callback_get_timestop(globus_abstime_t * time_stop);

globus_bool_t
globus_callback_has_time_expired();

globus_bool_t
globus_callback_was_restarted();

globus_bool_t
globus_callback_adjust_period(
    globus_callback_handle_t *                   handle,
    globus_reltime_t *                           period);
/******************************************************************************
			       Module definition
******************************************************************************/
extern globus_module_descriptor_t	globus_i_callback_module;

#define GLOBUS_CALLBACK_MODULE (&globus_i_callback_module)
#define GLOBUS_POLL_MODULE     (&globus_i_callback_module)

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_CALLBACK */
