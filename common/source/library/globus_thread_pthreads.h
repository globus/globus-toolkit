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

/** @file globus_thread_pthreads.h POSIX Threads Bindings for Globus */

#if !defined GLOBUS_THREAD_PTHREADS_H
#define GLOBUS_THREAD_PTHREADS_H 1

#include "globus_time.h"
#include "globus_module.h"

#if _POSIX_THREADS

#if defined __GNUC__ && defined __EXCEPTIONS
#undef __EXCEPTIONS
#include <pthread.h>
#define __EXCEPTIONS 1
#else
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    pthread_cond_t                      cond;
    globus_bool_t                       poll_space;
    int                                 space;
} globus_pthread_cond_t;

typedef struct
{
    pthread_condattr_t                  condattr;
    int                                 space;
} globus_pthread_condattr_t;

extern
int
globus_thread_create(
    pthread_t *                         thread,
    pthreadattr_t *                     attr,
    globus_thread_func_t                func,
    void *                              user_arg);

extern
void
globus_thread_exit(void *status);

extern
int
globus_threadattr_init(
    pthreadattr_t *                     attr);

extern
int
globus_threadattr_destroy(
    pthreadattr_t *                     attr);

extern
int
globus_threadattr_setstacksize(
    pthreadattr_t *                     attr,
    size_t                              stacksize);

extern
int
globus_threadattr_getstacksize(
    globus_threadattr_t *               attr,
    size_t *                            stacksize);

extern
int
globus_thread_key_create(
    pthread_key_t *                     key,
    globus_thread_key_destructor_func_t destructor_func);

extern
int
globus_thread_key_delete(
    pthread_key_t                       key);

extern
int
globus_thread_setspecific(
    pthread_key_t                       key,
    void *                              value);

extern
void *
globus_thread_getspecific(
    pthread_key_t                       key);

extern
pthread_t
globus_thread_self(void);

extern
int
globus_thread_equal(
    pthread_t                           t1,
    pthread_t                           t2);

extern
int
globus_thread_once(
    pthread_once_t *                    once_control,
    void (*init_routine)(void));

extern
void
globus_thread_yield(void);

extern
globus_bool_t
globus_i_am_only_thread(void);

extern
int
globus_mutexattr_init(
    pthread_mutexattr_t *               attr);

extern
int
globus_mutexattr_destroy(
    pthread_mutexattr_t *               attr);

extern
int
globus_mutex_init(
    pthread_mutex_t *                   mutex,
    globus_mutexattr_t *                attr);

extern
int
globus_mutex_destroy(
    pthread_mutex_t *                   mutex);

extern
int
globus_mutex_lock(
    pthread_mutex_t *                   mutex);

extern
int
globus_mutex_trylock(
    pthread_mutex_t *                   mutex);

extern
int
globus_mutex_unlock(
    pthread_mutex_t *                   mutex);

extern
int
globus_condattr_init(
    globus_condattr_t *                 attr);

extern
int
globus_condattr_destroy(
    globus_condattr_t *                 attr);

extern
int
globus_cond_init(
    globus_cond_t *                     cond,
    globus_condattr_t *                 attr);

extern
int
globus_cond_destroy(
    globus_cond_t *                     cond);

extern
int
globus_cond_wait(
    globus_cond_t *                     cond,
    globus_mutex_t *                    mutex);

extern
int
globus_cond_timedwait(
    globus_cond_t *                     cond,
    globus_mutex_t *                    mutex,
    globus_abstime_t *                  abstime);

extern
int
globus_cond_signal(
    globus_cond_t *                     cond);

extern
int
globus_cond_broadcast(
    globus_cond_t *                     cond);

extern
int
globus_condattr_setspace(
    globus_condattr_t *                 attr,
    int                                 space);

extern
int
globus_condattr_getspace(
    globus_condattr_t *                 attr,
    int *                               space);

extern
int
globus_thread_sigmask(
    int                                 how,
    const sigset_t *                    newmask,
    sigset_t *                          oldmask);

extern
int
globus_thread_cancel(
    globus_thread_t                     thread);

extern
void
globus_thread_testcancel(void);

extern
int
globus_thread_setcancelstate(
    int                                 state,
    int *                               oldstate);


/******************************************************************************
                               Module definition
******************************************************************************/
extern int globus_i_thread_pre_activate();

extern globus_module_descriptor_t       globus_i_thread_module;

#define GLOBUS_THREAD_MODULE (&globus_i_thread_module)

globus_bool_t
globus_thread_preemptive_threads(void);

#ifdef __cplusplus
}
#endif

#endif /* _POSIX_THREADS */

#endif /* GLOBUS_THREAD_PTHREADS_H */
