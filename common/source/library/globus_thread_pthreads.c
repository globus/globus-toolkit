/*
 * Copyright 1999-2010 University of Chicago
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
 * @file globus_thread_pthreads.c
 * @brief POSIX Threads Bindings
 */

#include "globus_i_common_config.h"
#include "globus_common.h"
#include "globus_thread.h"
#include "globus_thread_common.h"
#include "globus_i_thread.h"
#include "version.h"

#if _POSIX_THREADS

#if defined __GNUC__ && defined __EXCEPTIONS
#undef __EXCEPTIONS
#include <pthread.h>
#define __EXCEPTIONS 1
#else
#include <pthread.h>
#endif

typedef struct globus_i_thread_s
{
    globus_thread_func_t                user_func;
    void *                              user_arg;
    struct globus_i_thread_s *          next_free;
} globus_i_thread_t;

/*
 * globus_l_thread_self()
 *
 * Set *Thread (globus_i_thread_t **) to the calling thread.
 */
#define globus_l_thread_self(Thread) \
    *(Thread) = (globus_i_thread_t *)pthread_getspecific(globus_thread_all_global_vars.globus_thread_t_pointer) 

#define GLOBUS_L_THREAD_GRAN 256

typedef struct globus_i_thread_global_vars_s
{
    pthread_key_t               globus_thread_t_pointer;
    pthread_attr_t              threadattr;
} globus_i_thread_global_vars_t;

globus_i_thread_global_vars_t globus_thread_all_global_vars;

static globus_bool_t    globus_l_thread_already_initialized=GLOBUS_FALSE;
/*
 * Free list of globus_i_thread_t structures
 */
static globus_i_thread_t *              thread_freelist;
static globus_mutex_t                   thread_mem_mutex;

static void *                           thread_starter(void *temparg);
static globus_i_thread_t *              new_thread(void);
static void                             set_tsd(globus_i_thread_t *);


static
void *
globus_l_pthread_get_impl(void);
static int globus_l_pthread_activate();
static int globus_l_pthread_deactivate();

GlobusExtensionDefineModule(globus_thread_pthread) = 
{
    "globus_thread_pthreads",
    globus_l_pthread_activate,
    globus_l_pthread_deactivate,
    GLOBUS_NULL,
    globus_l_pthread_get_impl,
    &local_version
};

static
int
globus_l_pthread_pre_activate( void )
{
  int rc;

#ifndef _WIN32
    rc = globus_i_thread_ignore_sigpipe();
#endif
    return rc;
} /* globus_i_thread_pre_activate() */

/*
 * globus_l_thread_activate()
 *
 * This should be used to initialize all the thread related things
 * that Globus threads will be using, including things that might be
 * specified by arguments.
 */
static int
globus_l_pthread_activate(void)
{
    int rc;
    globus_i_thread_t *thread;

    globus_module_activate(GLOBUS_THREAD_COMMON_MODULE);
    if(globus_l_thread_already_initialized)
    {
        return GLOBUS_SUCCESS;
    }

    globus_l_thread_already_initialized = GLOBUS_TRUE;

    /*
     * Setup the default thread attributes
     */
    rc = pthread_attr_init(&(globus_thread_all_global_vars.threadattr));
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_attr_init() failed\n" ));

    /*
     * Setup thread specific storage which contains
     * a pointer to the globus_i_thread_t structure for the thread.
     */
    rc = pthread_key_create(&(globus_thread_all_global_vars.globus_thread_t_pointer),
                             NULL);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_key_create() failed\n"));
    
    globus_mutex_init(&(thread_mem_mutex),
                      (globus_mutexattr_t *) NULL);

    /*
     * Initialize the globus_i_thread_t structure for this initial thread
     */
    thread = new_thread();
    set_tsd(thread);
    
    return GLOBUS_SUCCESS;
} /* globus_l_thread_activate() */


/*
 * globus_l_thread_deactivate()
 */
static int
globus_l_pthread_deactivate(void)
{
    int rc;
    rc = globus_module_deactivate(GLOBUS_THREAD_COMMON_MODULE);
    return rc;
} /* globus_l_thread_deactivate() */




/*
 * new_thread()
 *
 * Allocate and return a globus_i_thread_t thread structure.
 */
static globus_i_thread_t *
new_thread( void )
{
    int i;
    globus_i_thread_t *new_thread;
    int mem_req_size;
    
    globus_mutex_lock(&thread_mem_mutex);
    
    if (thread_freelist == NULL)
    {
        mem_req_size = sizeof(globus_i_thread_t) * GLOBUS_L_THREAD_GRAN;
        GlobusThreadMalloc(new_thread(),
                           thread_freelist,
                           globus_i_thread_t *, 
                           mem_req_size);
        
        for( i = 0; i < GLOBUS_L_THREAD_GRAN-1; i++ )
        {
            thread_freelist[i].next_free = &thread_freelist[i+1];
        }
        thread_freelist[GLOBUS_L_THREAD_GRAN-1].next_free = NULL;
    }
    new_thread = thread_freelist;
    if (thread_freelist != NULL)
    {
        thread_freelist = thread_freelist->next_free;
    }

    globus_mutex_unlock(&thread_mem_mutex);
    
    return (new_thread);
} /* new_thread() */


/*
 * terminate_thread()
 */
static void
terminate_thread(globus_i_thread_t *thread,
                 void *status,
                 globus_bool_t really_terminate)
{
    /* Free up the thread storage */
    globus_mutex_lock(&thread_mem_mutex);
    thread->next_free = thread_freelist;
    thread_freelist = thread;
    globus_mutex_unlock(&thread_mem_mutex);

    /* Exit the thread */
    if (really_terminate)
    {
        pthread_exit(NULL);
    }

} /* terminate_thread() */


/*
 * globus_thread_exit()
 */
static
void
globus_l_pthread_thread_exit(void *status)
{
    globus_i_thread_t *victim;
    globus_l_thread_self(&victim);
    terminate_thread(victim, status, GLOBUS_TRUE);
} /* globus_thread_exit() */


/*
 * set_tsd()
 *
 * Save the globus_i_thread_t thread structure in the pthread's thread
 * specific storage.
 */
static void
set_tsd(globus_i_thread_t *thread)
{
    pthread_setspecific(
        globus_thread_all_global_vars.globus_thread_t_pointer,
        (void *) thread );
} /* set_tsd() */


/*
 * thread_starter()
 *
 * Wrapper to get a Globus Thread function started.
 */
static void *
thread_starter( void *temparg )
{
    globus_i_thread_t *thread;
    void *status;

    thread = (globus_i_thread_t *) temparg;

    set_tsd(thread);

    /* Call the user function */
    status = (*thread->user_func)(thread->user_arg);
    
    /* Terminate the thread */
    terminate_thread(thread, status, GLOBUS_FALSE);
  
    return (NULL);
} /* thread_starter() */


/*
 * globus_thread_create
 */
static
int
globus_l_pthread_thread_create(
    globus_thread_t *                   user_thread,
    globus_threadattr_t *               attr,
    globus_thread_func_t                func,
    void *                              user_arg)
{
    int rc;
    globus_i_thread_t *thread;
    pthread_t thread_id;

    thread = new_thread();
  
    /* Initialize the thread data that needs to be passed to the new thread */
    thread->user_func = func;
    thread->user_arg = user_arg;
  
    rc = pthread_attr_setdetachstate(
        attr
            ? &attr->pthread :
            &(globus_thread_all_global_vars.threadattr),
            PTHREAD_CREATE_DETACHED);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD:pthread_attr_setdetachstate() failed\n"));

    rc = pthread_create(&thread_id,
                        (attr
                            ? &attr->pthread
                            : &(globus_thread_all_global_vars.threadattr)),
                        thread_starter,
                        thread);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_create() failed\n") );

    if (user_thread)
    {
        user_thread->pthread = thread_id;
     }

    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_detach() failed\n") );

    return (0);
} /* globus_thread_create() */


/*
 * globus_thread_preemptive_threads
 *
 * Return GLOBUS_TRUE (non-zero) if we are using preemptive threads.
 */
static
globus_bool_t
globus_l_pthread_preemptive_threads(void)
{
    return GLOBUS_TRUE;
} /* globus_thread_preemptive_threads() */




/*
 * globus_threadattr_destroy()
 */
int globus_threadattr_destroy(globus_threadattr_t *attr)
{
    return pthread_attr_destroy(&attr->pthread);
}

/*
 * globus_thread_key_create()
 */
static
int
globus_l_pthread_thread_key_create(
    globus_thread_key_t *               key,
    globus_thread_key_destructor_func_t destructor_func)
{
    int rc;
    rc = pthread_key_create(&key->pthread, destructor_func);
    if (rc != 0 && rc != EAGAIN)
    {
        globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: globus_thread_key_create() failed\n"));
    }
    return(rc);
} /* globus_thread_key_create() */


/*
 * globus_thread_key_delete()
 */
static
int
globus_l_pthread_thread_key_delete(
    globus_thread_key_t                 key)
{
    int rc=0;
#ifndef __MINGW32__
    rc = pthread_key_delete(key.pthread);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: globus_thread_key_delete() failed\n"));
#endif
    return(rc);
} /* globus_thread_key_delete() */


/*
 * globus_thread_setspecific()
 */
static
int
globus_l_pthread_thread_setspecific(
    globus_thread_key_t                 key,
    void *                              value)
{
    int rc;
    rc = pthread_setspecific(key.pthread, value);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: globus_thread_setspecific() failed\n"));
    return(rc);
} /* globus_thread_setspecific() */


/*
 * globus_thread_getspecific()
 */
static
void *
globus_l_pthread_thread_getspecific(
    globus_thread_key_t                 key)
{
    return pthread_getspecific(key.pthread);
} /* globus_thread_getspecific() */

/*
 * globus_thread_self()
 */
static
globus_thread_t
globus_l_pthread_thread_self(void)
{
    globus_thread_t tmp;
    tmp.pthread = pthread_self();
    return tmp;
} /* globus_thread_self() */


/*
 * globus_thread_equal()
 */
static
int
globus_l_pthread_thread_equal(
    globus_thread_t                     t1,
    globus_thread_t                     t2)
{
    return pthread_equal(t1.pthread, t2.pthread);
} /* globus_thread_equal() */


/*
 * globus_thread_once()
 */
static
int
globus_l_pthread_thread_once(
    globus_thread_once_t *              once_control,
    void (*init_routine)(void))
{
    return pthread_once(&once_control->pthread, init_routine);
} /* globus_thread_once() */


/*
 * globus_thread_yield
 */
static
void
globus_l_pthread_thread_yield(void)
{
#if _POSIX_PRIORITY_SCHEDULING > 0
    sched_yield();
#endif
} /* globus_thread_yield() */


/*
 * globus_i_am_only_thread()
 */
static
globus_bool_t
globus_l_pthread_i_am_only_thread(void)
{
    return GLOBUS_FALSE;
}

/*
 * globus_mutexattr_init()
 */
static
int
globus_l_pthread_mutexattr_init(
    globus_mutexattr_t *                attr)
{
    int rc;
    rc = pthread_mutexattr_init(&attr->pthread);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_mutexattr_init() failed\n"));
    return (rc);
}

/*
 * globus_mutexattr_destroy()
 */
static
int
globus_l_pthread_mutexattr_destroy(
    globus_mutexattr_t *                attr)
{
    int rc;
    rc = pthread_mutexattr_destroy(&attr->pthread);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_mutexattr_destroy() failed\n"));
    return (rc);
}

/*
 * globus_mutex_init()
 */
static
int
globus_l_pthread_mutex_init(
    globus_mutex_t *                    mut,
    globus_mutexattr_t *                attr)
{
    int rc;
    rc = pthread_mutex_init(&mut->pthread, &attr->pthread);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_init() failed\n" ));
    return(rc);
} /* globus_mutex_init() */


/*
 *  globus_mutex_destroy()
 */
static
int
globus_l_pthread_mutex_destroy(
    globus_mutex_t *                    mut)
{
    int rc; 
    rc = pthread_mutex_destroy(&mut->pthread);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_destroy() failed\n" ));
    return(rc);
} /* globus_mutex_destroy() */


/* 
 *  globus_mutex_lock()
 */
static
int
globus_l_pthread_mutex_lock(
    globus_mutex_t *                    mut)
{
    int rc;
    rc = pthread_mutex_lock(&mut->pthread);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_lock() failed\n" ));
    return(rc);
} /* globus_mutex_lock() */


/* 
 *  globus_mutex_trylock()
 */
static
int
globus_l_pthread_mutex_trylock(
    globus_mutex_t *                    mut)
{
    int rc;

    rc = pthread_mutex_trylock(&mut->pthread);
    if (rc != EBUSY)
    {
        globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_trylock() failed\n" ));
    }
    return(rc);
} /* globus_mutex_trylock() */


/*
 *  globus_mutex_unlock()
 */
static
int
globus_l_pthread_mutex_unlock(
    globus_mutex_t *                    mut)
{
    int rc;
    rc = pthread_mutex_unlock(&mut->pthread);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_unlock() failed\n" ));
    return(rc);
} /* globus_mutex_unlock() */


/*
 * globus_condattr_setspace()
 */
static
int
globus_l_pthread_condattr_setspace(
    globus_condattr_t *                 attr,
    int                                 space)
{
    if (globus_callback_space_reference(space))
    {
        return GLOBUS_FAILURE;
    }
    globus_callback_space_destroy(attr->pthread.space);
    attr->pthread.space = space;
    return 0;
}

/*
 * globus_condattr_getspace()
 */
static
int
globus_l_pthread_condattr_getspace(
    globus_condattr_t *                 attr,
    int *                               space)
{
    *space = attr->pthread.space;

    return 0;
}

/*
 * globus_condattr_init()
 */
static
int
globus_l_pthread_condattr_init(
    globus_condattr_t *                 attr)
{
    globus_callback_space_reference(GLOBUS_CALLBACK_GLOBAL_SPACE);
    attr->pthread.space = GLOBUS_CALLBACK_GLOBAL_SPACE;

    return pthread_condattr_init(&attr->pthread.attr);
}

/*
 * globus_condattr_destroy()
 */
static
int
globus_l_pthread_condattr_destroy(
    globus_condattr_t *                 attr)
{
    globus_callback_space_destroy(attr->pthread.space);
    return pthread_condattr_destroy(&attr->pthread.attr);
}

/*
 * globus_cond_init()
 */
static
int
globus_l_pthread_cond_init(
    globus_cond_t *                     cv,
    globus_condattr_t *                 attr)
{
    if (attr)
    {
        cv->pthread.space = attr->pthread.space;
    }
    else
    {
        cv->pthread.space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    }
    globus_callback_space_reference(cv->pthread.space);
    cv->pthread.poll_space = globus_callback_space_is_single(cv->pthread.space);

    return pthread_cond_init(&cv->pthread.cond,
            attr ? &attr->pthread.attr : NULL);
} /* globus_cond_init() */


/*
 *  globus_cond_destroy()
 */
static
int
globus_l_pthread_cond_destroy(
    globus_cond_t *                     cv)
{
    globus_callback_space_destroy(cv->pthread.space);
    return pthread_cond_destroy(&cv->pthread.cond);
} /* globus_cond_destroy() */


/*
 *  globus_cond_wait()
 */
static
int
globus_l_pthread_cond_wait(
    globus_cond_t *                     cv,
    globus_mutex_t *                    mut)
{
    globus_thread_blocking_space_will_block(cv->pthread.space);
    if (!cv->pthread.poll_space)
    {
        return pthread_cond_wait(&cv->pthread.cond, &mut->pthread);
    }
    else
    {
        pthread_mutex_unlock(&mut->pthread);
        globus_callback_space_poll(&globus_i_abstime_infinity, cv->pthread.space);
        pthread_mutex_lock(&mut->pthread);
        return 0;
    }
} /* globus_cond_wait() */

/*
 *  globus_cond_wait()
 */
static
int 
globus_l_pthread_cond_timedwait(
    globus_cond_t *                     cv, 
    globus_mutex_t *                    mut,
    globus_abstime_t *                  abstime)
{
    int rc;

    globus_thread_blocking_space_will_block(cv->pthread.space);

    if (!cv->pthread.poll_space)
    {
        rc = pthread_cond_timedwait(&cv->pthread.cond, &mut->pthread, abstime);
#       if defined(ETIME)
        {
            if (rc == ETIME)
            {
                rc = ETIMEDOUT;
            }
        }
#       endif
        return rc;
    }
    else
    {
        pthread_mutex_unlock(&mut->pthread);
        globus_callback_space_poll(abstime, cv->pthread.space);
        pthread_mutex_lock(&mut->pthread);
        return (time(NULL) >= abstime->tv_sec) ? ETIMEDOUT : 0;
    }
} /* globus_cond_timedwait() */

/*
 *  globus_cond_signal()
 */
static
int
globus_l_pthread_cond_signal(
    globus_cond_t *                     cv)
{
    if (!cv->pthread.poll_space)
    {
        return pthread_cond_signal(&cv->pthread.cond);
    }
    else
    {
        globus_callback_signal_poll();
        return 0;
    }
} /* globus_cond_signal () */


/*
 *  globus_cond_broadcast()
 */
static
int
globus_l_pthread_cond_broadcast(
    globus_cond_t *                     cv)
{
    if (!cv->pthread.poll_space)
    {
        return pthread_cond_broadcast(&cv->pthread.cond);
    }
    else
    {
        globus_callback_signal_poll();

        return 0;
    }
} /* globus_cond_broadcast() */

#if !defined(_WIN32) && !defined(__MINGW32__)
static
int
globus_l_pthread_thread_sigmask(
    int                                 how,
    const sigset_t *                    newmask,
    sigset_t *                          oldmask)
{
    int rc; 
    rc = pthread_sigmask(how, newmask, oldmask); 
    globus_i_thread_test_rc(rc, "GLOBUSTHREAD: pthread_sigmask() failed\n");
    return(rc);
}

static
int
globus_l_pthread_thread_kill(
    globus_thread_t                     thread,
    int                                 sig)
{
    return pthread_kill(thread.pthread, sig);
}
#endif

static
int
globus_l_pthread_thread_cancel(
    globus_thread_t                     thread)
{
    return pthread_cancel(thread.pthread);
}

static
void
globus_l_pthread_thread_testcancel(void)
{
    pthread_testcancel();
}

static
int
globus_l_pthread_thread_setcancelstate(
    int                                 state,
    int *                               oldstate)
{
    return pthread_setcancelstate(state, oldstate);
}

static
void *
globus_l_pthread_thread_cancellable_func(
    void *                              (*func)(void *),
    void *                              func_arg,
    void                                (*cleanup_func)(void *),
    void *                              cleanup_arg,
    globus_bool_t                       execute_cleanup)
{
    void *                              result;

    pthread_cleanup_push(cleanup_func, cleanup_arg);
    result = (*func)(func_arg);
    pthread_cleanup_pop(execute_cleanup);

    return result;
}
/* globus_l_pthread_thread_cancellable_func() */

static globus_thread_impl_t globus_l_pthread_impl =
{
    globus_l_pthread_mutex_init,
    globus_l_pthread_mutex_destroy,
    globus_l_pthread_mutex_lock,
    globus_l_pthread_mutex_unlock,
    globus_l_pthread_mutex_trylock,
    globus_l_pthread_cond_init,
    globus_l_pthread_cond_destroy,
    globus_l_pthread_cond_wait,
    globus_l_pthread_cond_timedwait,
    globus_l_pthread_cond_signal,
    globus_l_pthread_cond_broadcast,
    globus_l_pthread_mutexattr_init,
    globus_l_pthread_mutexattr_destroy,
    globus_l_pthread_condattr_init,
    globus_l_pthread_condattr_destroy,
    globus_l_pthread_condattr_setspace,
    globus_l_pthread_condattr_getspace,
    globus_l_pthread_thread_create,
    globus_l_pthread_thread_key_create,
    globus_l_pthread_thread_key_delete,
    globus_l_pthread_thread_once,
    globus_l_pthread_thread_getspecific,
    globus_l_pthread_thread_setspecific,
    globus_l_pthread_thread_yield,
    globus_l_pthread_thread_exit,
#if !defined(_WIN32) && !defined(__MINGW32__)
    globus_l_pthread_thread_sigmask,
    globus_l_pthread_thread_kill,
#else
    NULL,
    NULL,
#endif
    globus_l_pthread_thread_setcancelstate,
    globus_l_pthread_thread_testcancel,
    globus_l_pthread_thread_cancel,
    globus_l_pthread_thread_self,
    globus_l_pthread_thread_equal,
    globus_l_pthread_preemptive_threads,
    globus_l_pthread_i_am_only_thread,
    globus_l_pthread_thread_cancellable_func,
    globus_l_pthread_pre_activate
};

static
void *
globus_l_pthread_get_impl(void)
{
    return &globus_l_pthread_impl;
}
#endif /* _POSIX_THREADS */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
