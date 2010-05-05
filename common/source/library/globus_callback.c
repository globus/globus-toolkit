/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_callback.h"
#include "globus_i_callback.h"
#include "globus_thread.h"
#include "version.h"

static
int
globus_l_callback_activate(void);

static
int
globus_l_callback_deactivate(void);

globus_module_descriptor_t       globus_i_callback_module =
{
    "globus_callback",
    globus_l_callback_activate,
    globus_l_callback_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static
int
globus_l_callback_activate(void)
{
    globus_module_activate(GLOBUS_THREAD_MODULE);
    if (globus_i_am_only_thread())
    {
        globus_module_activate(GLOBUS_CALLBACK_NONTHREADED_MODULE);
    }
    else
    {
        globus_module_activate(GLOBUS_CALLBACK_THREADED_MODULE);
    }
    return 0;
}

static
int
globus_l_callback_deactivate(void)
{
    if (globus_i_am_only_thread())
    {
        globus_module_deactivate(GLOBUS_CALLBACK_NONTHREADED_MODULE);
    }
    else
    {
        globus_module_deactivate(GLOBUS_CALLBACK_THREADED_MODULE);
    }
    return globus_module_deactivate(GLOBUS_THREAD_MODULE);
}

#define DECLARE_THREADED_AND_NONTHREADS(return_type, symbol, arg_types)\
return_type symbol##_nothreads arg_types; \
return_type symbol##_threads arg_types;

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_register_oneshot,
    (globus_callback_handle_t *          callback_handle,
    const globus_reltime_t *            delay_time,
    globus_callback_func_t              callback_func,
    void *                              callback_user_arg,
    globus_callback_space_t             space))

globus_result_t
globus_callback_space_register_oneshot(
    globus_callback_handle_t *          callback_handle,
    const globus_reltime_t *            delay_time,
    globus_callback_func_t              callback_func,
    void *                              callback_user_arg,
    globus_callback_space_t             space)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_register_oneshot_nothreads(
                callback_handle,
                delay_time,
                callback_func,
                callback_user_arg,
                space);
    }
    else
    {
        return globus_callback_space_register_oneshot_threads(
                callback_handle,
                delay_time,
                callback_func,
                callback_user_arg,
                space);
    }
}


DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_register_periodic,
    (globus_callback_handle_t *          callback_handle,
    const globus_reltime_t *            delay_time,
    const globus_reltime_t *            period,
    globus_callback_func_t              callback_func,
    void *                              callback_user_arg,
    globus_callback_space_t             space))

globus_result_t
globus_callback_space_register_periodic(
    globus_callback_handle_t *          callback_handle,
    const globus_reltime_t *            delay_time,
    const globus_reltime_t *            period,
    globus_callback_func_t              callback_func,
    void *                              callback_user_arg,
    globus_callback_space_t             space)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_register_periodic_nothreads(
                callback_handle,
                delay_time,
                period,
                callback_func,
                callback_user_arg,
                space);
    }
    else
    {
        return globus_callback_space_register_periodic_threads(
                callback_handle,
                delay_time,
                period,
                callback_func,
                callback_user_arg,
                space);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_unregister,
    (
    globus_callback_handle_t            callback_handle,
    globus_callback_func_t              unregister_callback,
    void *                              unreg_arg,
    globus_bool_t *                     active))

globus_result_t
globus_callback_unregister(
    globus_callback_handle_t            callback_handle,
    globus_callback_func_t              unregister_callback,
    void *                              unreg_arg,
    globus_bool_t *                     active)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_unregister_nothreads(
                callback_handle,
                unregister_callback,
                unreg_arg,
                active);
    }
    else
    {
        return globus_callback_unregister_threads(
                callback_handle,
                unregister_callback,
                unreg_arg,
                active);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    globus_result_t,
    globus_callback_adjust_oneshot, (
    globus_callback_handle_t            callback_handle,
    const globus_reltime_t *            new_delay))

globus_result_t
globus_callback_adjust_oneshot(
    globus_callback_handle_t            callback_handle,
    const globus_reltime_t *            new_delay)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_adjust_oneshot_nothreads(
                callback_handle,
                new_delay);
    }
    else
    {
        return globus_callback_adjust_oneshot_threads(
                callback_handle,
                new_delay);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_adjust_period,
    (
    globus_callback_handle_t            callback_handle,
    const globus_reltime_t *            new_period))

globus_result_t
globus_callback_adjust_period(
    globus_callback_handle_t            callback_handle,
    const globus_reltime_t *            new_period)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_adjust_period_nothreads(
                callback_handle,
                new_period);
    }
    else
    {
        return globus_callback_adjust_period_threads(
                callback_handle,
                new_period);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern void,
    globus_callback_space_poll,(
    const globus_abstime_t *            timestop,
    globus_callback_space_t             space))

void
globus_callback_space_poll(
    const globus_abstime_t *            timestop,
    globus_callback_space_t             space)
{
    if (globus_i_am_only_thread())
    {
        globus_callback_space_poll_nothreads(timestop, space);
    }
    else
    {
        globus_callback_space_poll_threads(timestop, space);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern void,
    globus_callback_signal_poll, (void))

void
globus_callback_signal_poll(void)
{
    if (globus_i_am_only_thread())
    {
        globus_callback_signal_poll_nothreads();
    }
    else
    {
        globus_callback_signal_poll_threads();
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_bool_t,
    globus_callback_get_timeout, (
    globus_reltime_t *                  time_left))

globus_bool_t
globus_callback_get_timeout(
    globus_reltime_t *                  time_left)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_get_timeout_nothreads(time_left);
    }
    else
    {
        return globus_callback_get_timeout_threads(time_left);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_bool_t,
    globus_callback_has_time_expired, (void))

globus_bool_t
globus_callback_has_time_expired(void)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_has_time_expired_nothreads();
    }
    else
    {
        return globus_callback_has_time_expired_threads();
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_bool_t,
    globus_callback_was_restarted, (void))

globus_bool_t
globus_callback_was_restarted(void)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_was_restarted_nothreads();
    }
    else
    {
        return globus_callback_was_restarted_threads();
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_init, (
    globus_callback_space_t *           space,
    globus_callback_space_attr_t        attr))

globus_result_t
globus_callback_space_init(
    globus_callback_space_t *           space,
    globus_callback_space_attr_t        attr)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_init_nothreads(space, attr);
    }
    else
    {
        return globus_callback_space_init_threads(space, attr);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_reference,(
    globus_callback_space_t             space))

globus_result_t
globus_callback_space_reference(
    globus_callback_space_t             space)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_reference_nothreads(space);
    }
    else
    {
        return globus_callback_space_reference_threads(space);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_destroy,(
        globus_callback_space_t             space))

globus_result_t
globus_callback_space_destroy(
    globus_callback_space_t             space)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_destroy_nothreads(space);
    }
    else
    {
        return globus_callback_space_destroy_threads(space);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_attr_init,(
    globus_callback_space_attr_t *      attr))

globus_result_t
globus_callback_space_attr_init(
    globus_callback_space_attr_t *      attr)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_attr_init_nothreads(attr);
    }
    else
    {
        return globus_callback_space_attr_init_threads(attr);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_attr_destroy,(
    globus_callback_space_attr_t        attr))

globus_result_t
globus_callback_space_attr_destroy(
    globus_callback_space_attr_t        attr)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_attr_destroy_nothreads(attr);
    }
    else
    {
        return globus_callback_space_attr_destroy_threads(attr);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_attr_set_behavior,(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t    behavior))

globus_result_t
globus_callback_space_attr_set_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t    behavior)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_attr_set_behavior_nothreads(attr, behavior);
    }
    else
    {
        return globus_callback_space_attr_set_behavior_threads(attr, behavior);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_attr_get_behavior,(
        globus_callback_space_attr_t        attr,
        globus_callback_space_behavior_t *  behavior))

globus_result_t
globus_callback_space_attr_get_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t *  behavior)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_attr_get_behavior_nothreads(attr, behavior);
    }
    else
    {
        return globus_callback_space_attr_get_behavior_threads(attr, behavior);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_get, (
    globus_callback_space_t *           space))

globus_result_t
globus_callback_space_get(
    globus_callback_space_t *           space)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_get_nothreads(space);
    }
    else
    {
        return globus_callback_space_get_threads(space);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern int,
    globus_callback_space_get_depth,(
    globus_callback_space_t             space))

int
globus_callback_space_get_depth(
    globus_callback_space_t             space)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_get_depth_nothreads(space);
    }
    else
    {
        return globus_callback_space_get_depth_threads(space);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_bool_t,
    globus_callback_space_is_single, (
    globus_callback_space_t             space))

globus_bool_t
globus_callback_space_is_single(
    globus_callback_space_t             space)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_is_single_nothreads(space);
    }
    else
    {
        return globus_callback_space_is_single_threads(space);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_space_register_signal_handler,(
    int                                 signum,
    globus_bool_t                       persist,
    globus_callback_func_t              callback_func,
    void *                              callback_user_arg,
    globus_callback_space_t             space))

globus_result_t
globus_callback_space_register_signal_handler(
    int                                 signum,
    globus_bool_t                       persist,
    globus_callback_func_t              callback_func,
    void *                              callback_user_arg,
    globus_callback_space_t             space)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_space_register_signal_handler_nothreads(
                signum,
                persist,
                callback_func,
                callback_user_arg,
                space);
    }
    else
    {
        return globus_callback_space_register_signal_handler_threads(
                signum,
                persist,
                callback_func,
                callback_user_arg,
                space);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern globus_result_t,
    globus_callback_unregister_signal_handler,(
    int                                 signum,
    globus_callback_func_t              unregister_callback,
    void *                              unreg_arg))

globus_result_t
globus_callback_unregister_signal_handler(
    int                                 signum,
    globus_callback_func_t              unregister_callback,
    void *                              unreg_arg)
{
    if (globus_i_am_only_thread())
    {
        return globus_callback_unregister_signal_handler_nothreads(
                signum, unregister_callback, unreg_arg);
    }
    else
    {
        return globus_callback_unregister_signal_handler_threads(
                signum, unregister_callback, unreg_arg);
    }
}

DECLARE_THREADED_AND_NONTHREADS(
    extern void,
    globus_callback_add_wakeup_handler,(
    void                                (*wakeup)(void *),
    void *                              user_arg))


void
globus_callback_add_wakeup_handler(
    void                                (*wakeup)(void *),
    void *                              user_arg)
{
    if (globus_i_am_only_thread())
    {
        globus_callback_add_wakeup_handler_nothreads(wakeup, user_arg);
    }
    else
    {
        globus_callback_add_wakeup_handler_threads(wakeup, user_arg);
    }
}
