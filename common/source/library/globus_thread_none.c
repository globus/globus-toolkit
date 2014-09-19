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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_thread_none.c
 * @brief Non-threaded stubs for the Globus Threads interface
 */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_i_common_config.h"
#include "globus_common_include.h"
#include "globus_thread.h"
#include "globus_thread_common.h"
#include "globus_i_thread.h"
#include "version.h"
#include "globus_time.h"
#include "globus_libc.h"
#include "globus_handle_table.h"

/* Module activation function prototypes */
static int
globus_l_thread_none_activate(void);

static int
globus_l_thread_none_deactivate(void);

static
void *
globus_l_thread_none_get_impl(void);

static
void *
globus_l_thread_none_keys[512];

static
int
globus_l_thread_none_next_key = 0;

/* Module definition */
globus_module_descriptor_t
globus_i_thread_none_module =
{
    "globus_thread_none",
    globus_l_thread_none_activate,
    globus_l_thread_none_deactivate,
    GLOBUS_NULL,
    globus_l_thread_none_get_impl,
    &local_version
};

/**
 * globus_i_thread_pre_activate()
 *
 * Since globus_module depends on threads and globus_thread depends on
 * globus_module, we need this bootstrapping function.
 * 
 */
static
int
globus_l_thread_none_pre_activate(void)
{
#ifndef WIN32
    return globus_i_thread_ignore_sigpipe();
#else
    return 1;
#endif
}

static
int
globus_l_thread_none_activate(void)
{
    return globus_module_activate(GLOBUS_THREAD_COMMON_MODULE);
}
/* globus_l_thread_none_activate() */


static
int
globus_l_thread_none_deactivate()
{
    return globus_module_deactivate(GLOBUS_THREAD_COMMON_MODULE);
}
/* globus_l_thread_none_deactivate() */


/**
 * Return GLOBUS_TRUE (non-zero) if we are using preemptive threads.
 */
static
globus_bool_t
globus_l_thread_none_preemptive_threads(void)
{
    return GLOBUS_FALSE;
}
/* globus_thread_none_preemptive_threads() */


/*
 * globus_thread_none_key_create()
 */
static
int
globus_l_thread_none_key_create(
    globus_thread_key_t *               key,
    globus_thread_key_destructor_func_t func)
{
    key->none = globus_l_thread_none_next_key++;
    globus_l_thread_none_keys[key->none] = NULL;

    return 0;
}
/* globus_key_create() */


/*
 * globus_thread_none_key_setspecific()
 */
static
int
globus_l_thread_none_key_setspecific(
    globus_thread_key_t                 key,
    void *                              value)
{
    globus_l_thread_none_keys[key.none] = value;

    return 0;
}
/* globus_thread_none_setspecific() */

static
int
globus_l_thread_none_key_delete(
    globus_thread_key_t                 key)
{
    return 0;
} /* globus_thread_none_key_delete() */

/*
 * globus_thread_none_getspecific()
 */
static
void *
globus_l_thread_none_key_getspecific(
    globus_thread_key_t                 key)
{
    return globus_l_thread_none_keys[key.none];
}
/* globus_thread_none_getspecific() */

/*
 * globus_thread_none_once()
 */
static
int
globus_l_thread_none_once(
    globus_thread_once_t *              once_control,
    void                                (*init_routine)(void))
{
    if (once_control == NULL || init_routine == NULL)
    {
        return EINVAL;
    }
    if (once_control->none == GLOBUS_THREAD_ONCE_INIT_VALUE.none)
    {
        once_control->none = !GLOBUS_THREAD_ONCE_INIT_VALUE.none;
        (*init_routine)();
    }
    return 0;
}
/* globus_thread_none_once() */


/*
 * globus_thread_none_self()
 */
static
globus_thread_t
globus_l_thread_none_self(void)
{
    static globus_thread_t self;

    self.none = 0;

    return self;
}
/* globus_thread_none_self() */


/*
 * globus_thread_none_equal()
 */
static
int
globus_l_thread_none_equal(
    globus_thread_t                     thread1,
    globus_thread_t                     thread2)
{
    return (thread1.none == thread2.none);
}
/* globus_thread_none_equal() */

static
globus_bool_t
globus_l_thread_none_i_am_only_thread(void)
{
    return GLOBUS_TRUE;
}

/*
 * globus_thread_none_create()
 */
static
int
globus_l_thread_none_thread_create(
    globus_thread_t *                   thread,
    globus_threadattr_t *               attr,
    globus_thread_func_t                func,
    void *                              user_arg)
{
    thread->none = -1;

    return EAGAIN;
}

static
void
globus_l_thread_none_yield(void)
{
    globus_poll_nonblocking();
}
/* globus_thread_none_yield() */

/*
 * globus_none_condattr_init()
 */
static
int
globus_l_thread_none_condattr_init(
    globus_condattr_t *                 attr)
{
    globus_callback_space_reference(GLOBUS_CALLBACK_GLOBAL_SPACE);
    attr->none = GLOBUS_CALLBACK_GLOBAL_SPACE;
    return 0;
}

/*
 * globus_none_condattr_destroy()
 */
static
int
globus_l_thread_none_condattr_destroy(
    globus_condattr_t *                 attr)
{
    globus_callback_space_destroy(attr->none);
    attr->none = 0;

    return 0;
}

/*
 * globus_none_condattr_setspace()
 */
static
int
globus_l_thread_none_condattr_setspace(
    globus_condattr_t *                 attr,
    int                                 space)
{
    if (globus_callback_space_reference(space))
    {
        return GLOBUS_FAILURE;
    }
    else
    {
        globus_callback_space_destroy(attr->none);
        attr->none = space;
        return 0;
    }
}

/*
 * globus_none_condattr_getspace()
 */
static
int
globus_l_thread_none_condattr_getspace(
    globus_condattr_t *                 attr,
    int *                               space)
{
    *space = attr->none;

    return 0;
}

/*
 * globus_none_cond_init()
 */
static
int
globus_l_thread_none_cond_init(
    globus_cond_t *                     cv,
    globus_condattr_t *                 attr)
{
    if (attr != NULL)
    {
        cv->none = attr->none;
    }
    else
    {
        cv->none = GLOBUS_CALLBACK_GLOBAL_SPACE;
    }
    return globus_callback_space_reference(cv->none);
}
/* globus_none_cond_init() */


/*
 *  globus_none_cond_destroy()
 */
static
int
globus_l_thread_none_cond_destroy(
    globus_cond_t *                     cv)
{
    globus_callback_space_destroy(cv->none);
    cv->none = GLOBUS_NULL_HANDLE;

    return 0;
}
/* globus_none_cond_destroy() */


/*
 *  globus_none_cond_wait()
 */
static
int
globus_l_thread_none_cond_wait(
    globus_cond_t *                     cv,
    globus_mutex_t *                    mut)
{
    mut->none = 0;
    globus_thread_blocking_space_will_block(cv->none);
    globus_callback_space_poll(&globus_i_abstime_infinity, cv->none);
    mut->none = 1;

    return 0;
}
/* globus_none_cond_wait() */

/*
 *  globus_none_cond_timedwait()
 */
static
int
globus_l_thread_none_cond_timedwait(
    globus_cond_t *                     cv,
    globus_mutex_t *                    mut,
    globus_abstime_t *                  abstime)
{

    mut->none = 0;
    globus_thread_blocking_space_will_block(cv->none);
    globus_callback_space_poll(abstime, cv->none);
    mut->none = 1;

    if (time(NULL) >= abstime->tv_sec)
    {
        return ETIMEDOUT;
    }
    else
    {
        return 0;
    }
}
/* globus_none_cond_timedwait() */


/*
 *  globus_none_cond_signal()
 */
static
int
globus_l_thread_none_cond_signal(
    globus_cond_t *                     cv)
{
    globus_callback_signal_poll();
    return 0;
}
/* globus_none_cond_signal () */

static
void
globus_l_thread_none_thread_exit(
    void *                              value)
{
    exit(0);
}
/* globus_l_thread_none_thread_exit() */

/*
 *  globus_none_cond_broadcast()
 */
static
int
globus_l_thread_none_cond_broadcast(
    globus_cond_t *                     cv)
{
    globus_callback_signal_poll();
    return 0;
}
/* globus_none_cond_broadcast() */

static
int
globus_l_thread_none_kill(
    globus_thread_t                     thread,
    int                                 sig)
{
    int                                 rc;
    if (thread.none != 0)
    {
        return ESRCH;
    }
    rc = raise(sig);
    if (rc != 0)
    {
        rc = errno;
    }
    return rc;
}
/* globus_l_thread_none_kill() */

static globus_thread_impl_t globus_l_thread_none_impl =
{
    NULL /* mutex_init */,
    NULL /* mutex_destroy */,
    NULL /* mutex_lock */,
    NULL /* mutex_unlock */,
    NULL /* mutex_trylock */,
    globus_l_thread_none_cond_init,
    globus_l_thread_none_cond_destroy,
    globus_l_thread_none_cond_wait,
    globus_l_thread_none_cond_timedwait,
    globus_l_thread_none_cond_signal,
    globus_l_thread_none_cond_broadcast,
    NULL /* mutexattr_init */,
    NULL /* mutexattr_destroy */,
    globus_l_thread_none_condattr_init,
    globus_l_thread_none_condattr_destroy,
    globus_l_thread_none_condattr_setspace,
    globus_l_thread_none_condattr_getspace,
    globus_l_thread_none_thread_create,
    globus_l_thread_none_key_create,
    globus_l_thread_none_key_delete,
    globus_l_thread_none_once,
    globus_l_thread_none_key_getspecific,
    globus_l_thread_none_key_setspecific,
    globus_l_thread_none_yield,
    globus_l_thread_none_thread_exit,
#   if HAVE_SIGPROCMASK
    sigprocmask,
#   else
    NULL,
#   endif
    globus_l_thread_none_kill,
    NULL,
    NULL,
    NULL,
    globus_l_thread_none_self,
    globus_l_thread_none_equal,
    globus_l_thread_none_preemptive_threads,
    globus_l_thread_none_i_am_only_thread,
    NULL,
    globus_l_thread_none_pre_activate
};

static
void *
globus_l_thread_none_get_impl(void)
{
    return &globus_l_thread_none_impl;
}
