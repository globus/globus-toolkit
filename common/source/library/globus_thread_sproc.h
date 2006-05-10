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
 *
 * External header for a C-threads based Ports0 threads library.
 * This will be included by user code.
 *
 */

#if !defined(GLOBUS_INCLUDE_GLOBUS_THREAD)
#define GLOBUS_INCLUDE_GLOBUS_THREAD 1

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif


#include "globus_common.h"

#include <sys/types.h>
#include <sys/prctl.h>
#include <ulocks.h>

EXTERN_C_BEGIN

#if defined (GLOBUS_TIMESPEC_EXISTS)
    typedef struct timespec      globus_abstime_t;
#else
    typedef struct globus_abstime_s
    {
        long    tv_sec;
	long    tv_nsec;
    } globus_abstime_t;
#endif 

typedef void *		 		globus_thread_t;

typedef struct
{
    int					stacksize;
}
globus_threadattr_t;

typedef int				globus_mutexattr_t;
typedef int                             globus_condattr_t;
typedef ulock_t				globus_mutex_t;
typedef struct
{
    globus_mutex_t			mutex;
    globus_fifo_t			queue;
    globus_bool_t                       poll_space;
    int                                 space;
}
globus_cond_t;

extern usptr_t *			globus_i_thread_arena;

typedef void *(*globus_thread_func_t)(void *);

#define GLOBUS_THREAD_ONCE_INIT 0
typedef int globus_thread_once_t;
extern  int globus_i_thread_actual_thread_once(
    globus_thread_once_t *once_control,
    void (*init_routine)(void));

typedef int globus_thread_key_t;
typedef void (*globus_thread_key_destructor_func_t)(void *value);


/*
 * Some externs...
 */
extern int		globus_thread_create(globus_thread_t *thread,
					     globus_threadattr_t *attr,
					     globus_thread_func_t func,
					     void *user_arg);
extern void		globus_thread_exit(void *status);

extern int		globus_thread_key_create(globus_thread_key_t *key,
				globus_thread_key_destructor_func_t func);
extern int		globus_thread_setspecific(globus_thread_key_t key,
						  void *value);
extern void *           globus_thread_getspecific(globus_thread_key_t key);

#define globus_threadattr_init(attr)	\
	(attr->stacksize = 0)
#define globus_threadattr_destroy(attr)	0 /* successful return */
#define globus_threadattr_setstacksize(attr, stacksize) \
	(attr->stacksize = stacksize)
#define globus_threadattr_getstacksize(attr, stacksize) \
	(attr->stacksize)
#define globus_thread_key_delete(key)	0 /* successful return */


/*
 * macros and prototypes for thread manipulation routines
 */
#define globus_macro_thread_yield() \
    sginap(0)
#define globus_macro_thread_equal(t1,t2) \
    ((int)(t1) == (int)(t2))
#define globus_macro_thread_once(once_control, init_routine) \
    (*once_control ? 0 : globus_i_thread_actual_thread_once(once_control, init_routine))
#ifndef USE_MACROS
extern void		globus_thread_yield(void);
extern int		globus_thread_equal(globus_thread_t t1,
					   globus_thread_t t2);
extern int		globus_thread_once(globus_thread_once_t *once_control,
					  void (*init_routine)(void));
extern globus_bool_t globus_thread_i_am_only_thread(void);
#else  /* USE_MACROS */
#define globus_thread_yield() \
    globus_macro_thread_yield()
#define globus_thread_equal(t1,t2) \
    globus_macro_thread_equal(t1,t2)
#define globus_thread_once(once_control, init_routine) \
    globus_macro_thread_once(once_control, init_routine)
#define globus_thread_i_am_only_thread() GLOBUS_FALSE
#endif /* USE_MACROS */

extern globus_thread_t	globus_thread_self(void);

/*
 * lock macros and prototypes
 */

#define globus_macro_mutex_init(mut, attr) \
    ((*mut = usnewlock(globus_i_thread_arena)) == NULL ? 1 : 0)
#define globus_macro_mutex_destroy(mut)	\
    (usfreelock(*mut, globus_i_thread_arena), 0)
#define globus_macro_mutex_lock(mut) \
    (ussetlock(*mut), 0)
#define globus_macro_mutex_trylock(mut) \
    (ustestlock(*mut) ? 0 : EBUSY)
#define globus_macro_mutex_unlock(mut) \
    (usunsetlock(*mut), 0)
#define globus_mutexattr_init(attr) 0 /* successful return */
#define globus_mutexattr_destroy(attr) 0 /* successful return */

#ifndef USE_MACROS
extern int		globus_mutex_init(globus_mutex_t *mutex,
					  globus_mutexattr_t *attr);
extern int		globus_mutex_destroy(globus_mutex_t *mutex);
extern int		globus_mutex_lock(globus_mutex_t *mutex);
extern int		globus_mutex_trylock(globus_mutex_t *mutex);
extern int		globus_mutex_unlock(globus_mutex_t *mutex);
#else  /* USE_MACROS */
#define globus_mutex_init(mutex, attr) \
    globus_macro_mutex_init(mutex, attr)
#define globus_mutex_destroy(mutex) \
    globus_macro_mutex_destroy(mutex)
#define globus_mutex_lock(mutex) \
    globus_macro_mutex_lock(mutex)
#define globus_mutex_trylock(mutex) \
    globus_macro_mutex_trylock(mutex)
#define globus_mutex_unlock(mutex) \
    globus_macro_mutex_unlock(mutex)
#endif /* USE_MACROS */


/*
 * condition prototypes
 */
extern int	globus_cond_init(globus_cond_t *cond, globus_condattr_t *attr);
extern int	globus_cond_destroy(globus_cond_t *cond);
extern int	globus_cond_signal(globus_cond_t *cond);
extern int	globus_cond_broadcast(globus_cond_t *cond);
extern int
globus_cond_wait(
    globus_cond_t *cond,
    globus_mutex_t *mutex);
extern int	globus_cond_timedwait(globus_cond_t *cond,
				      globus_mutex_t *mutex,
				      globus_abstime_t *abstime);

extern int
globus_condattr_setspace(
    globus_condattr_t *                 attr,
    int                                 space);

extern int
globus_condattr_getspace(
    globus_condattr_t *                 attr,
    int *                               space);

extern int		globus_condattr_init (globus_condattr_t *attr);
extern int		globus_condattr_destroy (globus_condattr_t *attr);

globus_bool_t
globus_thread_preemptive_threads(void);

/******************************************************************************
                               Module definition
******************************************************************************/
extern int globus_i_thread_pre_activate();

extern globus_module_descriptor_t       globus_i_thread_module;

#define GLOBUS_THREAD_MODULE (&globus_i_thread_module)

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_THREAD */


