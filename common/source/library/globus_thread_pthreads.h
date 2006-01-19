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

/*
 * globus_thread_pthreads.h
 *
 * General purpose pthreads module.  Supports:
 *	IBM DCE threads
 *	HP DCE threads
 *	Florida State U. pthreads under SunOS 4.1.3
 *	POSIX threads draft 8 (if such a thing really exists in practice)
 *
 */

/*
 * #defines
 * USE_MACROS      -- Allow globus thread functions to be macros.  If this
 *				is not defined, then all globus thread
 *                              functions must be real functions.
 */

#if !defined GLOBUS_INCLUDE_GLOBUS_THREAD
#define GLOBUS_INCLUDE_GLOBUS_THREAD 1

#ifdef HAVE_PTHREAD_DRAFT_6
#endif

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_time.h"
#include "globus_list.h"
#include "globus_module.h"

#ifdef TARGET_ARCH_AIX
/* Only add the 'extern "C" {' for AIX since doing so for some other platforms
 * (e.g. SunOS 4.1.3 using FSU pthreads and G++) can cause problems.  For
 * FSU pthreads it is necessary to add the 'extern "C" {' to right places
 * within the pthread.h file itself (see the FSU pthreads modified for CC++).
 */
EXTERN_C_BEGIN
#include <pthread.h>
EXTERN_C_END
#else  /* TARGET_ARCH_AIX */
#include <pthread.h>
#endif /* TARGET_ARCH_AIX */

EXTERN_C_BEGIN


typedef pthread_t		globus_thread_t;
typedef pthread_attr_t		globus_threadattr_t;
typedef pthread_mutexattr_t	globus_mutexattr_t;
typedef pthread_key_t		globus_thread_key_t;
typedef pthread_once_t		globus_thread_once_t;
typedef pthread_mutex_t		globus_mutex_t;

typedef struct
{
    pthread_cond_t              cond;
    globus_bool_t               poll_space;
    int                         space;
} globus_cond_t;

typedef struct
{
    pthread_condattr_t          condattr;
    int                         space;
} globus_condattr_t;

typedef void *(*globus_thread_func_t)(void *);

#ifdef PORTS0_ARCH_MPINX
/* Fix up MPI/Nexus problems */
#undef errno
#undef PRI_RR_MIN
#define PRI_RR_MIN PRI_FIFO_MIN
#undef PRI_RR_MAX
#define PRI_RR_MAX PRI_FIFO_MAX
#define MUTEX_FAST_NP MUTEX_FAST
#define MUTEX_RECURSIVE_NP MUTEX_RECURSIVE
#define MUTEX_NONRECURSIVE_NP MUTEX_NONRECURSIVE
#endif

#ifdef HAVE_PTHREAD_DRAFT_4
#define GLOBUS_THREAD_ONCE_INIT	pthread_once_init
#else
#define GLOBUS_THREAD_ONCE_INIT	PTHREAD_ONCE_INIT
#endif

#ifdef HAVE_PTHREAD_DRAFT_4
/* DCE threads missed an underscore */
#define pthread_key_create pthread_keycreate
#endif

#if defined(HAVE_PTHREAD_DRAFT_4) || defined(HAVE_PTHREAD_DRAFT_6)
/* These do not have pthread_key_delete */
#define pthread_key_delete(key) 0
#endif

#if defined(HAVE_PTHREAD_DRAFT_4) || defined(HAVE_PTHREAD_DRAFT_6)
/* Later pthreads return error codes directly, rather than through errno */
#define GLOBUS_THREAD_RETURN_USES_ERRNO
#endif

#define GLOBUS_THREAD_CANCEL_ENABLE PTHREAD_CANCEL_ENABLE
#define GLOBUS_THREAD_CANCEL_DISABLE PTHREAD_CANCEL_DISABLE

typedef void (*globus_thread_key_destructor_func_t)(void *value);

typedef struct globus_i_thread_global_vars_s
{
    globus_thread_key_t		globus_thread_t_pointer;
    globus_threadattr_t		threadattr;
#ifdef HAVE_PTHREAD_DRAFT_4
    globus_mutexattr_t		mutexattr;
    globus_condattr_t		condattr;
#endif    
} globus_i_thread_global_vars_t;

extern globus_i_thread_global_vars_t globus_thread_all_global_vars;

extern void	globus_i_thread_report_bad_rc(int rc, char *message);

extern int	globus_thread_create(globus_thread_t *thread,
				     globus_threadattr_t *attr,
				     globus_thread_func_t func,
				     void *user_arg);
extern void	globus_thread_exit(void *status);

#define globus_macro_i_am_only_thread() GLOBUS_FALSE

#ifdef GLOBUS_THREAD_RETURN_USES_ERRNO

/*
 * These macros are for draft 6 and DCE threads, which
 * use errno to return error values.
 */
#define GLOBUS_I_THREAD_GETSPECIFIC 1
extern void *   globus_i_thread_getspecific(globus_thread_key_t key);

#ifndef HAVE_PTHREAD_DRAFT_4
#define globus_macro_threadattr_init(attr) \
    (pthread_attr_init(attr) ? errno : 0)
#define globus_macro_threadattr_destroy(attr) \
    (pthread_attr_destroy(attr) ? errno : 0)
#define globus_macro_threadattr_setstacksize(attr, stacksize) \
    (pthread_attr_setstacksize(attr, stacksize) ? errno : 0)
#define globus_macro_threadattr_getstacksize(attr, stacksize) \
    (pthread_attr_getstacksize(attr, stacksize) ? errno : 0)
#else
#define globus_macro_threadattr_init(attr) \
    (pthread_attr_create(attr) ? errno : 0)
#define globus_macro_threadattr_destroy(attr) \
    (pthread_attr_delete(attr) ? errno : 0)
#define globus_macro_threadattr_setstacksize(attr, stacksize) \
    (pthread_attr_setstacksize(attr, stacksize) ? errno : 0)
#define globus_macro_threadattr_getstacksize(attr, stacksize) \
    ((*(stacksize) = pthread_attr_getstacksize(*(attr))) ? 0 : 999)
#endif /* HAVE_PTHREAD_DRAFT_4 */

#define globus_macro_thread_key_create(key, func) \
    (pthread_key_create(key, func) ? errno : 0)
#define globus_macro_thread_key_delete(key) \
    (pthread_key_delete(key) ? errno : 0)
#define globus_macro_thread_setspecific(key, value) \
    (pthread_setspecific(key, value) ? errno : 0)
#define globus_macro_thread_getspecific(key) \
    globus_i_thread_getspecific(key)

#define globus_macro_thread_self() \
    pthread_self()
#define globus_macro_thread_equal(t1, t2) \
    pthread_equal(t1, t2)
#define globus_macro_thread_once(once_control, init_routine) \
    (pthread_once(once_control, init_routine) ? errno : 0)
#ifdef HAVE_PTHREAD_DRAFT_6
#define globus_macro_thread_yield() \
    pthread_yield(NULL)
#else
#define globus_macro_thread_yield() \
    pthread_yield()
#endif

#ifdef HAVE_PTHREAD_DRAFT_4
#define globus_macro_mutexattr_init(attr) \
    (pthread_mutexattr_create(attr) ? errno : 0)
#define globus_macro_mutex_init(mut, attr) \
    (pthread_mutex_init(mut, \
	(attr ? *(attr) : globus_thread_all_global_vars.mutexattr)) \
    ? errno : 0)
#define globus_macro_mutexattr_destroy(attr) \
    (pthread_mutexattr_delete(attr) ? errno : 0)
#else /* HAVE_PTHREAD_DRAFT_4 */
#define globus_macro_mutexattr_init(attr) \
    (pthread_mutexattr_init(attr) ? errno : 0)
#define globus_macro_mutex_init(mut, attr) \
    (pthread_mutex_init(mut, attr) ? errno : 0)
#define globus_macro_mutexattr_destroy(attr) \
    (pthread_mutexattr_destroy(attr) ? errno : 0)
#endif
#define globus_macro_mutex_destroy(mut) \
    (pthread_mutex_destroy(mut) ? errno : 0)
#define globus_macro_mutex_lock(mut) \
    (pthread_mutex_lock(mut) ? errno : 0)
#ifndef HAVE_PTHREAD_DRAFT_6
#define globus_macro_mutex_trylock(mut) \
    (pthread_mutex_trylock(mut) ? 0 : EBUSY)
#else
#define globus_macro_mutex_trylock(mut) \
    (pthread_mutex_trylock(mut) ? errno : 0)
#endif
#define globus_macro_mutex_unlock(mut) \
    (pthread_mutex_unlock(mut) ? errno : 0)

#ifdef HAVE_PTHREAD_DRAFT_4
#define globus_macro_condattr_init(attr) \
    (pthread_condattr_create(attr) ? errno : 0)
#define globus_macro_condattr_destroy(attr) \
    (pthread_condattr_delete(attr) ? errno : 0)
#define globus_macro_cond_init(cv, attr) \
    (pthread_cond_init(cv, \
	(attr ? *(attr) : globus_thread_all_global_vars.condattr.condattr)) \
    ? errno : 0)
#else /* HAVE_PTHREAD_DRAFT_4 */
#define globus_macro_condattr_init(attr) \
    (pthread_condattr_init(attr) ? errno : 0)
#define globus_macro_condattr_destroy(attr) \
    (pthread_condattr_destroy(attr) ? errno : 0)
#define globus_macro_cond_init(cv, attr) \
    (pthread_cond_init(cv, attr) ? errno : 0)
#endif
#define globus_macro_cond_destroy(cv) \
    (pthread_cond_destroy(cv) ? errno : 0)
#define globus_macro_cond_wait(cv, mut) \
    (pthread_cond_wait(cv, mut) ? errno : 0)
#define globus_macro_cond_timedwait(cv, mut, abstime) \
    (pthread_cond_timedwait(cv, mut, abstime) ? errno : 0) 
#define globus_macro_cond_signal(cv) \
    (pthread_cond_signal(cv) ? errno : 0)
#define globus_macro_cond_broadcast(cv) \
    (pthread_cond_broadcast(cv) ? errno : 0)

#else /* PORTS0_RETURN_USES_ERRNO */

/*
 * These macros are for draft 8 and draft 10 pthreads, which return values
 * directly rather than using errno.
 */
#define globus_macro_threadattr_init(attr) \
    pthread_attr_init(attr) 
#define globus_macro_threadattr_destroy(attr) \
    pthread_attr_destroy(attr)

#ifdef _POSIX_THREAD_ATTR_STACKSIZE

#define globus_macro_threadattr_setstacksize(attr, stacksize) \
    pthread_attr_setstacksize(attr, stacksize)
#define globus_macro_threadattr_getstacksize(attr, stacksize) \
    pthread_attr_getstacksize(attr, stacksize)

#else /* _POSIX_THREAD_ATTR_STACKSIZE */

#define globus_macro_threadattr_setstacksize(attr, stacksize) \
    -1
#define globus_macro_threadattr_getstacksize(attr, stacksize) \
    -1

#endif /* _POSIX_THREAD_ATTR_STACKSIZE */

#define globus_macro_thread_key_create(key, func) \
    pthread_key_create(key, func)
#define globus_macro_thread_key_delete(key) \
    pthread_key_delete(key)
#define globus_macro_thread_setspecific(key, value) \
    pthread_setspecific(key, value)
#define globus_macro_thread_getspecific(key) \
    pthread_getspecific(key)
#define globus_macro_thread_self() \
    pthread_self()
#define globus_macro_thread_equal(t1, t2) \
    pthread_equal(t1, t2)
#define globus_macro_thread_once(once_control, init_routine) \
    pthread_once(once_control, init_routine)
#ifdef HAVE_PTHREAD_DRAFT_8
#define globus_macro_thread_yield() \
    pthread_yield()
#else
#ifdef HAVE_PTHREAD_PLAIN_YIELD
#define globus_macro_thread_yield() \
    yield()
#else
#define globus_macro_thread_yield() \
    sched_yield()
#endif
#endif

#define globus_macro_mutexattr_init(attr) \
    pthread_mutexattr_init(attr)
#define globus_macro_mutexattr_destroy(attr) \
    pthread_mutexattr_destroy(attr)
#define globus_macro_mutex_init(mut, attr) \
    pthread_mutex_init(mut, attr)
#define globus_macro_mutex_destroy(mut) \
    pthread_mutex_destroy(mut)
#define globus_macro_mutex_lock(mut) \
    pthread_mutex_lock(mut)
#define globus_macro_mutex_trylock(mut) \
    pthread_mutex_trylock(mut)
#define globus_macro_mutex_unlock(mut) \
    pthread_mutex_unlock(mut)

#define globus_macro_condattr_init(attr) \
    pthread_condattr_init(attr)
#define globus_macro_condattr_destroy(attr) \
    pthread_condattr_destroy(attr)
#define globus_macro_cond_init(cv, attr) \
    pthread_cond_init(cv, attr)
#define globus_macro_cond_destroy(cv) \
    pthread_cond_destroy(cv)
#define globus_macro_cond_wait(cv, mut) \
    (pthread_cond_wait(cv, mut))
#define globus_macro_cond_timedwait(cv, mut, abstime) \
    (pthread_cond_timedwait(cv, mut, abstime)) 
#define globus_macro_cond_signal(cv) \
    pthread_cond_signal(cv)
#define globus_macro_cond_broadcast(cv) \
    pthread_cond_broadcast(cv)

#endif /* PORTS0_RETURN_USES_ERRNO */

#define globus_macro_thread_sigmask(how, newmask, oldmask) \
    pthread_sigmask((how), (newmask), (oldmask))
#define globus_macro_thread_cancel(thread) \
    pthread_cancel((thread))
#define globus_macro_thread_cleanup_push(func, arg) \
    pthread_cleanup_push((func), (arg))
#define globus_macro_thread_cleanup_pop(execute) \
    pthread_cleanup_pop((execute))
#define globus_macro_thread_testcancel() \
    pthread_testcancel()
#define globus_macro_thread_setcancelstate(state, oldstate) \
    pthread_setcancelstate((state), (oldstate))
    
/* callback space handling macros */
#define globus_macro_condattr_space_init(attr) \
    (globus_callback_space_reference(GLOBUS_CALLBACK_GLOBAL_SPACE), \
    (attr)->space = GLOBUS_CALLBACK_GLOBAL_SPACE, \
    globus_macro_condattr_init(&(attr)->condattr))
    
#define globus_macro_condattr_space_destroy(attr) \
    (globus_callback_space_destroy((attr)->space), \
    globus_macro_condattr_destroy(&(attr)->condattr))

#define globus_macro_cond_space_init(cv, attr) \
    (((attr) ? \
        ((cv)->space = ((globus_condattr_t *)(attr))->space) : \
        ((cv)->space = GLOBUS_CALLBACK_GLOBAL_SPACE)), \
        globus_callback_space_reference((cv)->space), \
        (cv)->poll_space = globus_callback_space_is_single((cv)->space), \
        globus_macro_cond_init(&(cv)->cond, (attr) ? \
        &((globus_condattr_t *)(attr))->condattr : GLOBUS_NULL))

#define globus_macro_cond_space_destroy(cv) \
    (globus_callback_space_destroy((cv)->space), \
    globus_macro_cond_destroy(&(cv)->cond))

#define globus_macro_cond_space_wait(cv, mut) \
    (globus_thread_blocking_space_will_block((cv)->space), \
    (!((cv)->poll_space) ? \
    (globus_macro_cond_wait(&(cv)->cond, (mut))) : \
    (globus_mutex_unlock((mut)), \
    globus_callback_space_poll(&globus_i_abstime_infinity, (cv)->space), \
    globus_mutex_lock((mut)), 0)))

#define globus_macro_cond_space_timedwait(cv, mut, abstime) \
    (globus_thread_blocking_space_will_block((cv)->space), \
    (!((cv)->poll_space) ? \
    (globus_macro_cond_timedwait(&(cv)->cond, (mut), (abstime))) : \
    (globus_mutex_unlock((mut)), \
    globus_callback_space_poll((abstime), (cv)->space), \
    globus_mutex_lock((mut)), \
    (time(GLOBUS_NULL) >= (abstime)->tv_sec) ? ETIMEDOUT : 0)))
    
#define globus_macro_cond_space_signal(cv) \
    (!((cv)->poll_space) ? \
    (globus_macro_cond_signal(&(cv)->cond)) : \
    (globus_callback_signal_poll(), 0))

#define globus_macro_cond_space_broadcast(cv) \
    (!((cv)->poll_space) ? \
    (globus_macro_cond_broadcast(&(cv)->cond)) : \
    (globus_callback_signal_poll(), 0))

#define globus_macro_condattr_setspace(attr, space) \
    ((globus_callback_space_reference((space)) \
     ? 1 \
     : (globus_callback_space_destroy((attr)->space), \
       ((attr)->space = (space)), 0)))

#define globus_macro_condattr_getspace(attr, space) \
    ((*(space) = (attr)->space), 0)

#ifdef USE_MACROS

#define globus_threadattr_init(attr) \
    globus_macro_threadattr_init(attr)
#define globus_threadattr_destroy(attr) \
    globus_macro_threadattr_destroy(attr)
#define globus_threadattr_setstacksize(attr, stacksize) \
    globus_macro_threadattr_setstacksize(attr, stacksize)
#define globus_threadattr_getstacksize(attr, stacksize) \
    globus_macro_threadattr_getstacksize(attr, stacksize)
#define globus_thread_key_create(key, func) \
    globus_macro_thread_key_create(key, func)
#define globus_thread_key_destroy(key) \
    globus_macro_thread_key_delete(key)
#define globus_thread_setspecific(key, value) \
    globus_macro_thread_setspecific(key, value)
#define globus_thread_getspecific(key) \
    globus_macro_thread_getspecific(key)
#define globus_thread_self() \
    globus_macro_thread_self()
#define globus_thread_equal(t1, t2) \
    globus_macro_thread_equal(t1, t2)
#define globus_thread_once(once_control, init_routine) \
    globus_macro_thread_once(once_control, init_routine)
#define globus_thread_yield() \
    globus_macro_thread_yield()
#define globus_i_am_only_thread() \
    globus_macro_i_am_only_thread()
#define globus_mutexattr_init(attr) \
    globus_macro_mutexattr_init(attr)
#define globus_mutexattr_destroy(attr) \
    globus_macro_mutexattr_destroy(attr)
#define globus_mutex_init(mut, attr) \
    globus_macro_mutex_init(mut, attr)
#define globus_mutex_destroy(mut) \
    globus_macro_mutex_destroy(mut)
#define globus_mutex_lock(mut) \
    globus_macro_mutex_lock(mut)
#define globus_mutex_trylock(mut) \
    globus_macro_mutex_trylock(mut)
#define globus_mutex_unlock(mut) \
    globus_macro_mutex_unlock(mut)
#define globus_condattr_init(attr) \
    globus_macro_condattr_space_init(attr)
#define globus_condattr_destroy(attr) \
    globus_macro_condattr_space_destroy(attr)
#define globus_cond_init(cv, attr) \
    globus_macro_cond_space_init(cv, attr)
#define globus_cond_destroy(cv) \
    globus_macro_cond_space_destroy(cv)
#define globus_cond_wait(cv, mut) \
    globus_macro_cond_space_wait(cv, mut)
#define globus_cond_timedwait(cv, mut, time) \
    globus_macro_cond_space_timedwait(cv, mut, time)
#define globus_cond_signal(cv) \
    globus_macro_cond_space_signal(cv)
#define globus_cond_broadcast(cv) \
    globus_macro_cond_space_broadcast(cv)
#define globus_condattr_setspace(A,S) \
    globus_macro_condattr_setspace(A,S)
#define globus_condattr_getspace(A,S) \
    globus_macro_condattr_getspace(A,S)

#define globus_thread_sigmask(how, newmask, oldmask) \
    globus_macro_thread_sigmask(how, newmask, oldmask)
#define globus_thread_cancel(thread) \
    globus_macro_thread_cancel(thread)
#define globus_thread_testcancel() \
    globus_macro_thread_testcancel()
#define globus_thread_setcancelstate(state, oldstate) \
    globus_macro_thread_setcancelstate(state, oldstate)

#else  /* USE_MACROS */

extern int		globus_threadattr_init(globus_threadattr_t *attr);
extern int		globus_threadattr_destroy(globus_threadattr_t *attr);
extern int		globus_threadattr_setstacksize(
						   globus_threadattr_t *attr,
						   size_t stacksize);
extern int		globus_threadattr_getstacksize(
						   globus_threadattr_t *attr,
						   size_t *stacksize);

extern int		globus_thread_key_create(globus_thread_key_t *key,
				   globus_thread_key_destructor_func_t destructor_func);
extern int		globus_thread_key_delete(globus_thread_key_t key);
extern int		globus_thread_setspecific(globus_thread_key_t key,
						  void *value);
extern void *		globus_thread_getspecific(globus_thread_key_t key);

extern globus_thread_t	globus_thread_self(void);
extern int		globus_thread_equal(globus_thread_t t1,
					    globus_thread_t t2);
extern int		globus_thread_once(globus_thread_once_t *once_control,
#ifdef HAVE_PTHREAD_DRAFT_6
					   void (*init_routing)(void *));
#else
					   void (*init_routine)(void));
#endif
extern void		globus_thread_yield(void);
extern globus_bool_t    globus_i_am_only_thread(void);

extern int		globus_mutexattr_init(globus_mutexattr_t *attr);
extern int		globus_mutexattr_destroy(globus_mutexattr_t *attr);
extern int		globus_mutex_init(globus_mutex_t *mutex,
					  globus_mutexattr_t *attr);
extern int		globus_mutex_destroy(globus_mutex_t *mutex);
extern int		globus_mutex_lock(globus_mutex_t *mutex);
extern int		globus_mutex_trylock(globus_mutex_t *mutex);
extern int		globus_mutex_unlock(globus_mutex_t *mutex);

extern int		globus_condattr_init (globus_condattr_t *attr);
extern int		globus_condattr_destroy (globus_condattr_t *attr);
extern int		globus_cond_init(globus_cond_t *cond,
					 globus_condattr_t *attr);
extern int		globus_cond_destroy(globus_cond_t *cond);
extern int		globus_cond_wait(globus_cond_t *cond,
					 globus_mutex_t *mutex);
extern int		globus_cond_timedwait(globus_cond_t *cond,
					 globus_mutex_t *mutex,
					 globus_abstime_t * abstime);
extern int		globus_cond_signal(globus_cond_t *cond);
extern int		globus_cond_broadcast(globus_cond_t *cond);

extern int
globus_condattr_setspace(
    globus_condattr_t *                 attr,
    int                                 space);

extern int
globus_condattr_getspace(
    globus_condattr_t *                 attr,
    int *                               space);

extern int
globus_thread_sigmask(
    int                                 how,
    const sigset_t *                    newmask,
    sigset_t *                          oldmask);

extern int
globus_thread_cancel(
    globus_thread_t                     thread);

extern void
globus_thread_testcancel(void);

extern int
globus_thread_setcancelstate(
    int                                 state,
    int *                               oldstate);

#endif /* USE_MACROS */

/* these cant be implemented as functions, they're already macros and must be
 * matched (see man pthread_cancel_push)
 */
#define globus_thread_cleanup_push(func, arg) \
    globus_macro_thread_cleanup_push(func, arg)
#define globus_thread_cleanup_pop(execute) \
    globus_macro_thread_cleanup_pop(execute)

/******************************************************************************
			       Module definition
******************************************************************************/
extern int globus_i_thread_pre_activate();

extern globus_module_descriptor_t	globus_i_thread_module;

#define GLOBUS_THREAD_MODULE (&globus_i_thread_module)

EXTERN_C_END

globus_bool_t
globus_thread_preemptive_threads(void);

#endif /* GLOBUS_INCLUDE_GLOBUS_THREAD */
