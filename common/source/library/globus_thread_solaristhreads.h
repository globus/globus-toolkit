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
 * p0_th_sol.h
 *
 * External header for Solaris threads
 *
 * #defines PORTS0_USE_HEADERS   -- allow Ports0 functions to be macros
 *
 * rcsid = "$Header$"
 */

#if !defined(GLOBUS_INCLUDE_GLOBUS_THREAD)
#define GLOBUS_INCLUDE_GLOBUS_THREAD 1


#include "globus_common.h"

#include <thread.h>
#include <synch.h>

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

typedef struct timespec      globus_abstime_t;

typedef mutex_t		                globus_mutex_t;
typedef thread_key_t  	                globus_thread_key_t;
typedef int           	                globus_mutexattr_t;
typedef int                             globus_condattr_t;
typedef thread_t	                globus_thread_t;

typedef struct
{
    cond_t                              cond;
    globus_bool_t                       poll_space;
    int                                 space;
} globus_cond_t;

typedef struct globus_i_threadattr_s
{
    size_t stacksize;
} globus_threadattr_t;

typedef size_t globus_thread_size;
typedef void *(*globus_thread_func_t)(void *);


#define GLOBUS_THREAD_ONCE_INIT 0
typedef int globus_thread_once_t;
extern  int globus_i_thread_actual_thread_once(
    globus_thread_once_t *once_control,
    void (*init_routine)(void));

typedef void (*globus_thread_key_destructor_func_t)(void *value);

typedef struct globus_i_global_vars_s
{
    globus_thread_key_t	thread_t_pointer;
    int		       	general_attribute;  
    int		       	thread_flags;
    globus_threadattr_t	thread_attr;
} globus_i_thread_global_vars_t;

extern globus_i_thread_global_vars_t globus_thread_all_global_vars;

extern void globus_i_thread_report_bad_rc( int, char * );
extern int globus_thread_create(globus_thread_t *thread,
				globus_threadattr_t *attr,
				globus_thread_func_t tar_func,
				void *user_arg );
extern void globus_thread_exit(void *status);

extern int globus_thread_key_create(globus_thread_key_t *key,
				    globus_thread_key_destructor_func_t func);
extern void *globus_thread_getspecific(globus_thread_key_t key);

#define globus_mutexattr_init(attr) 0 /* successful return */
#define globus_mutexattr_destroy(attr) 0 /* successful return */

#define globus_macro_threadattr_init(attr) \
	((attr)->stacksize = globus_thread_all_global_vars.thread_attr.stacksize)
#define globus_macro_threadattr_destroy(attr) 0 /* successful return */
#define globus_macro_threadattr_setstacksize(attr, ss) \
	((attr)->stacksize = (ss), 0)
#define globus_macro_threadattr_getstacksize(attr, ss) \
	(*(ss) = (attr)->stacksize, 0)

#define globus_macro_thread_key_create(key, value) \
    thr_keycreate((key), (value))

#define globus_macro_thread_key_delete(key)	0 /* successful return */

#define globus_macro_thread_setspecific(key, value) \
    thr_setspecific((key), (value))

#define globus_macro_thread_getspecific(key) \
    globus_i_thread_getspecific(key)

#define globus_macro_thread_self() \
    thr_self()
	

#define globus_macro_thread_equal( thr1, thr2 ) (thr1 == thr2)

#define globus_macro_thread_once( once_control, init_routine ) \
     (*once_control ? 0 : globus_i_thread_actual_thread_once( \
				once_control, \
				init_routine))

#define globus_macro_thread_yield() \
    thr_yield()

#define globus_macro_i_am_only_thread() GLOBUS_FALSE

#define globus_macro_mutex_init( mut, attr ) \
     mutex_init( mut, USYNC_THREAD, NULL )

#define globus_macro_mutex_destroy( mut ) \
    mutex_destroy(mut)

#define globus_macro_cond_init( cv, attr ) \
    cond_init( (cv), USYNC_THREAD, NULL)

#define globus_macro_cond_destroy( cv ) \
    cond_destroy( (cv) )

#define globus_macro_mutex_lock( mut ) \
    mutex_lock( (mut) )

#define globus_macro_mutex_trylock( mut ) \
    mutex_trylock( (mut) )

#define globus_macro_mutex_unlock( mut ) \
    mutex_unlock( (mut) )

#define globus_macro_cond_wait( cv, mut ) \
    ( cond_wait((cv), (mut)) )

#define globus_macro_cond_timedwait( cv, mut, time ) \
    ( cond_timedwait((cv), (mut), (time)) )

#define globus_macro_cond_signal( cv ) \
    cond_signal( (cv) ) 

#define globus_macro_cond_broadcast( cv ) \
    cond_broadcast( (cv) )

/* callback space handling macros */
#define globus_macro_condattr_init(attr) \
    (globus_callback_space_reference(GLOBUS_CALLBACK_GLOBAL_SPACE), \
    *(attr) = GLOBUS_CALLBACK_GLOBAL_SPACE)
    
#define globus_macro_condattr_destroy(attr) \
    (globus_callback_space_destroy(*(attr)))

#define globus_macro_cond_space_init(cv, attr) \
    (((attr) ? \
        ((cv)->space = *((int *)(attr))) : \
        ((cv)->space = GLOBUS_CALLBACK_GLOBAL_SPACE)), \
        globus_callback_space_reference((cv)->space), \
        (cv)->poll_space = globus_callback_space_is_single((cv)->space), \
        globus_macro_cond_init(&(cv)->cond, (attr)))

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
     : (globus_callback_space_destroy(*(attr)), \
       (*(attr) = (space)), 0)))

#define globus_macro_condattr_getspace(attr, space) \
    ((*(space) = *(attr)), 0)

#ifdef USE_MACROS

#define globus_condattr_init(attr) \
    globus_macro_condattr_init(attr)
#define globus_condattr_destroy(attr) \
    globus_macro_condattr_destroy(attr)
#define globus_threadattr_init(attr) \
    globus_macro_threadattr_init(attr)
#define globus_threadattr_destroy(attr) \
    globus_macro_threadattr_destroy(attr)
#define globus_threadattr_setstacksize(attr, stacksize) \
    globus_macro_threadattr_setstacksize(attr, stacksize)
#define globus_threadattr_getstacksize(attr, stacksize) \
    globus_macro_threadattr_getstacksize(attr, stacksize) \

#define globus_thread_key_create(key, value) \
    globus_macro_thread_key_create(key, value)
#define globus_thread_key_delete(key) \
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

#define globus_mutex_init( mut, attr ) \
    globus_macro_mutex_init( mut, attr )
#define globus_mutex_destroy( mut ) \
    globus_macro_mutex_destroy( mut )
#define globus_mutex_lock( mut ) \
    globus_macro_mutex_lock( mut )
#define globus_mutex_trylock( mut ) \
    globus_macro_mutex_trylock( mut )
#define globus_mutex_unlock( mut ) \
    globus_macro_mutex_unlock( mut )

#define globus_cond_init( cv, attr ) \
    globus_macro_cond_space_init( cv, attr )
#define globus_cond_destroy( cv ) \
    globus_macro_cond_space_destroy( cv )
#define globus_cond_wait( cv, mut ) \
    globus_macro_cond_space_wait( cv, mut )
#define globus_cond_timedwait( cv, mut, time ) \
    globus_macro_cond_space_timedwait( cv, mut, time )
#define globus_cond_signal( cv ) \
    globus_macro_cond_space_signal( cv )
#define globus_cond_broadcast( cv ) \
    globus_macro_cond_space_broadcast( cv )
#define globus_condattr_setspace(A,S) \
    globus_macro_condattr_setspace(A,S)
#define globus_condattr_getspace(A,S) \
    globus_macro_condattr_getspace(A,S)

#else  /* USE_MACROS */

extern int	globus_threadattr_init(globus_threadattr_t *attr);
extern int	globus_threadattr_destroy(globus_threadattr_t *attr);
extern int	globus_threadattr_setstacksize(globus_threadattr_t *attr,
					       size_t stacksize);
extern int	globus_threadattr_getstacksize(globus_threadattr_t *attr,
					       size_t *stacksize);

extern int	globus_thread_key_create(globus_thread_key_t *key,
				 globus_thread_key_destructor_func_t func);
extern int	globus_thread_key_delete(globus_thread_key_t key);
extern int	globus_thread_setspecific(globus_thread_key_t key,
					  void *value);
extern void *   globus_i_thread_getspecific(globus_thread_key_t key);

extern globus_thread_t	globus_thread_self(void);
extern int	globus_thread_equal(globus_thread_t t1,
				    globus_thread_t t2);
extern int	globus_thread_once(globus_thread_once_t *once_control,
				   void (*init_routine)(void));
extern void	globus_thread_yield(void);
extern globus_bool_t    globus_i_am_only_thread(void);

extern int	globus_mutex_init(globus_mutex_t *mutex,
				  globus_mutexattr_t *attr);
extern int	globus_mutex_destroy(globus_mutex_t *mutex);
extern int	globus_mutex_lock(globus_mutex_t *mutex);
extern int	globus_mutex_trylock(globus_mutex_t *mutex);
extern int	globus_mutex_unlock(globus_mutex_t *mutex);

extern int	globus_cond_init(globus_cond_t *cond,
				 globus_condattr_t *attr);
extern int	globus_cond_destroy(globus_cond_t *cond);
extern int	globus_cond_wait(globus_cond_t *cond,
				 globus_mutex_t *mutex);
extern int	globus_cond_timedwait(globus_cond_t *cond,
				      globus_mutex_t *mutex,
				      globus_abstime_t * abstime);
extern int	globus_cond_signal(globus_cond_t *cond);
extern int	globus_cond_broadcast(globus_cond_t *cond);


extern int
globus_condattr_init(
    globus_condattr_t *                 attr);

extern int
globus_condattr_destroy(
    globus_condattr_t *                 attr);

extern int
globus_condattr_setspace(
    globus_condattr_t *                 attr,
    int                                 space);

extern int
globus_condattr_getspace(
    globus_condattr_t *                 attr,
    int *                               space);

#endif /* USE_MACROS */

globus_bool_t
globus_thread_preemptive_threads(void);
/******************************************************************************
			       Module definition
******************************************************************************/
extern int globus_i_thread_pre_activate();

extern globus_module_descriptor_t	globus_i_thread_module;

#define GLOBUS_THREAD_MODULE (&globus_i_thread_module)

EXTERN_C_END

#endif /* ! defined(GLOBUS_INCLUDE_GLOBUS_THREAD) */
