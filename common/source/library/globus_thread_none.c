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

/******************************************************************************
globus_thread_none.c

Description:

  Stubs for the Globus threads package, to be used when Globus has been
  configured not to use threads.

CVS Information:

  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common_include.h"
#include "globus_thread_none.h"
#include "globus_thread_common.h"
#include "globus_i_thread.h"
#include "version.h"
#include "globus_time.h"
#include "globus_libc.h"
#include "globus_common.h"

/******************************************************************************
			       Define macros
******************************************************************************/


/******************************************************************************
                    Module activation function prototypes
******************************************************************************/
static int
globus_l_thread_activate(void);

static int
globus_l_thread_deactivate(void);


/******************************************************************************
                              Module definition
******************************************************************************/
globus_module_descriptor_t             globus_i_thread_module =
{
    "globus_thread_none",
    globus_l_thread_activate,
    globus_l_thread_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};



/******************************************************************************
			      Function prototypes
******************************************************************************/

/*
 * globus_i_thread_pre_activate()
 *
 * Since globus_module depends on threads and globus_thread depends on
 * globus_module, we need this bootstrapping function.
 * 
 */
int
globus_i_thread_pre_activate()
{
#ifndef WIN32
    return globus_i_thread_ignore_sigpipe();
#else
    return 1;
#endif
}

/*
 * globus_l_thread_activate()
 */
static int
globus_l_thread_activate()
{
    return globus_module_activate(GLOBUS_THREAD_COMMON_MODULE);
}
/* globus_l_thread_activate() */


/*
 * globus_l_thread_deactivate()
 */
static int
globus_l_thread_deactivate()
{
    return globus_module_deactivate(GLOBUS_THREAD_COMMON_MODULE);
}
/* globus_l_thread_deactivate() */


/*
 * globus_thread_preemptive_threads
 *
 * Return GLOBUS_TRUE (non-zero) if we are using preemptive threads.
 */
globus_bool_t
globus_thread_preemptive_threads(void)
{
    return GLOBUS_FALSE;/* globus_macro_thread_is_preemptive();*/
}
/* globus_thread_preemptive_threads() */


/*
 * globus_thread_key_create()
 */
#undef globus_thread_key_create
int
globus_thread_key_create(
    globus_thread_key_t *		key,
    globus_thread_key_destructor_func_t	func)
{
    int rc;

    rc = globus_macro_thread_key_create(key, func);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globusthread_key_create() failed\n"));
    return (rc);
}
/* globus_key_create() */


/*
 * globus_thread_setspecific()
 */
#undef globus_thread_setspecific
int
globus_thread_setspecific(
    globus_thread_key_t			key,
    void *				value)
{
    int rc;

    rc = globus_macro_thread_setspecific(key, value);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_thread_setspecific() failed\n"));
    return (rc);
}
/* globus_thread_setspecific() */

#undef globus_thread_key_delete
int
globus_thread_key_delete(
    globus_thread_key_t key)
{
    return globus_macro_thread_key_delete(key);
} /* globus_thread_key_delete() */

/*
 * globus_thread_getspecific()
 */
#undef globus_thread_getspecific
void *
globus_thread_getspecific(
    globus_thread_key_t			key)
{
    void *value;

    value = globus_macro_thread_getspecific(key);
    return (value);
}
/* globus_thread_getspecific() */



/*
 * globus_thread_once()
 */
#undef globus_thread_once
int
globus_thread_once(
    globus_thread_once_t *		once_control,
    void				(*init_routine)(void))
{
    return (globus_macro_thread_once(once_control, init_routine));
}
/* globus_thread_once() */


/*
 * globus_thread_self()
 */
#undef globus_thread_self
globus_thread_t
globus_thread_self(void)
{
    return(globus_macro_thread_self());
}
/* globus_thread_self() */


/*
 * globus_thread_equal()
 */
#undef globus_thread_equal
int
globus_thread_equal(
    globus_thread_t			thread1,
    globus_thread_t			thread2)
{
    return (globus_macro_thread_equal(thread1, thread2));
}
/* globus_thread_equal() */


/*
 * globus_thread_create()
 */
#undef globus_thread_create
int
globus_thread_create(
    globus_thread_t *			thread,
    globus_threadattr_t *		attr,
    globus_thread_func_t		func,
    void *				user_arg)
{
    return (globus_macro_thread_create(thread, attr, func, user_arg));
}

/*
 * globus_thread_yield()
 */
#undef globus_thread_yield
void
globus_thread_yield(void)
{
    globus_macro_thread_yield();
}
/* globus_thread_yield() */


/*
 * globus_mutex_init()
 */
#undef globus_mutex_init
int
globus_mutex_init(
    globus_mutex_t *			mut,
    globus_mutexattr_t *		attr)
{
    int rc;

    rc = globus_macro_mutex_init(mut, attr);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_mutex_init() failed\n"));
    return (rc);
}
/* globus_mutex_init() */


/*
 *  globus_mutex_destroy()
 */
#undef globus_mutex_destroy
int
globus_mutex_destroy(
    globus_mutex_t *			mut)
{
    int rc;

    rc = globus_macro_mutex_destroy(mut);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_mutex_destroy() failed\n"));
    return (rc);
}
/* globus_mutex_destroy() */


/* 
 *  globus_mutex_lock()
 */
#undef globus_mutex_lock
int
globus_mutex_lock(
    globus_mutex_t *			mut)
{
    int rc;

    rc = globus_macro_mutex_lock(mut);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_mutex_lock() failed\n"));
    return (rc);
}
/* globus_mutex_lock() */


/*
 *  globus_mutex_unlock()
 */
#undef globus_mutex_unlock
int
globus_mutex_unlock(
    globus_mutex_t *			mut)
{
    int rc;

    rc = globus_macro_mutex_unlock(mut);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_mutex_unlock() failed\n"));
    return (rc);
}
/* globus_mutex_unlock() */


/*
 *  globus_mutex_trylock()
 */
#undef globus_mutex_trylock
int
globus_mutex_trylock(
    globus_mutex_t *			mut)
{
    int rc;

    rc = globus_macro_mutex_trylock(mut);
    /*
     * trylock is allowed to return non-0 value, so don't call
     * globus_i_thread_test_rc() on the return code
     */
#   if 0
    {
	/* 
	 * This could probably be checked in all cases except EBUSY, though.
	 */
	globus_i_thread_test_rc(rc, "NEXUS: globus_mutex_trylock() failed\n");
    }
#   endif
    return (rc);
}
/* globus_mutex_trylock() */


/*
 * globus_condattr_init()
 */
#undef globus_condattr_init
int globus_condattr_init(globus_condattr_t *attr)
{
    int rc;
    rc = globus_macro_condattr_init(attr);
    return (rc);
}

/*
 * globus_condattr_destroy()
 */
#undef globus_condattr_destroy
int globus_condattr_destroy(globus_condattr_t *attr)
{
    int rc;
    rc = globus_macro_condattr_destroy(attr);
    return (rc);
}

/*
 * globus_condattr_setspace()
 */
#undef globus_condattr_setspace
int globus_condattr_setspace(
    globus_condattr_t *                 attr,
    int                                 space)
{
    int rc;
    rc = globus_macro_condattr_setspace(attr, space);
    return (rc);
}

/*
 * globus_condattr_getspace()
 */
#undef globus_condattr_getspace
int globus_condattr_getspace(
    globus_condattr_t *                 attr,
    int *                               space)
{
    int rc;
    rc = globus_macro_condattr_getspace(attr, space);
    return (rc);
}

/*
 * globus_cond_init()
 */
#undef globus_cond_init
int
globus_cond_init(
    globus_cond_t *			cv,
    globus_condattr_t *			attr)
{
    int rc;

    rc = globus_macro_cond_init(cv, attr);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_cond_init() failed\n"));
    return (rc);
}
/* globus_cond_init() */


/*
 *  globus_cond_destroy()
 */
#undef globus_cond_destroy
int
globus_cond_destroy(
    globus_cond_t *			cv)
{
    int rc;

    rc = globus_macro_cond_destroy(cv);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_cond_destroy() failed\n"));
    return (rc);
}
/* globus_cond_destroy() */


/*
 *  globus_cond_wait()
 */
#undef globus_cond_wait
int
globus_cond_wait(
    globus_cond_t *			cv,
    globus_mutex_t *			mut)
{
    int rc;

    rc = globus_macro_cond_wait(cv, mut);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_cond_wait() failed\n"));
    return (rc);
}
/* globus_cond_wait() */

/*
 *  globus_cond_timedwait()
 */
#undef globus_cond_timedwait
int
globus_cond_timedwait(
    globus_cond_t *			cv,
    globus_mutex_t *			mut,
    globus_abstime_t *                  abstime)
{
    int rc;

    rc = globus_macro_cond_timedwait(cv, mut, abstime);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_cond_wait() failed\n"));
    return (rc);
}
/* globus_cond_timedwait() */


/*
 *  globus_cond_signal()
 */
#undef globus_cond_signal
int
globus_cond_signal(
    globus_cond_t *			cv)
{
    int rc;

    rc = globus_macro_cond_signal(cv);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_cond_signal() failed\n"));
    return (rc);
}
/* globus_cond_signal () */


/*
 *  globus_cond_broadcast()
 */
#undef globus_cond_broadcast
int
globus_cond_broadcast(
    globus_cond_t *			cv)
{
    int rc;

    rc = globus_macro_cond_broadcast(cv);
    globus_i_thread_test_rc(rc, _GCSL("NEXUS: globus_cond_broadcast() failed\n"));
    return (rc);
}
/* globus_cond_broadcast() */

void
globus_thread_prefork(void)
{
}

void
globus_thread_postfork(void)
{
}

void
globus_i_thread_id(globus_thread_t *Thread_ID)
{
    *Thread_ID = 0;
}

