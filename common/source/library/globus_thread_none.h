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
globus_thread_none.h

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

#if !defined(GLOBUS_INCLUDE_GLOBUS_THREAD)
#define GLOBUS_INCLUDE_GLOBUS_THREAD 1

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common_include.h"
#include "globus_module.h"
#include "globus_callback.h"
#include "globus_handle_table.h"


/******************************************************************************
				 C/C++ macros
******************************************************************************/


EXTERN_C_BEGIN

/******************************************************************************
			       Type definitions
******************************************************************************/
typedef int globus_thread_t;
typedef int globus_threadattr_t;
typedef void * (*globus_thread_func_t)(void *);
typedef int globus_mutex_t;
typedef int globus_cond_t;
typedef int globus_mutexattr_t;
typedef int globus_condattr_t;
typedef void * globus_thread_key_t;
typedef void (* globus_thread_key_destructor_func_t)(void * value);
typedef int globus_thread_once_t;

/******************************************************************************
			     Thread package macros
******************************************************************************/
#ifndef GLOBUS_THREAD_ONCE_INIT
#define GLOBUS_THREAD_ONCE_INIT 0
#endif
#ifndef GLOBUS_THREAD_ONCE_CALLED
#define GLOBUS_THREAD_ONCE_CALLED 1
#endif

#define globus_macro_mutex_init(M,A)	(*(M) = 0)

#define globus_macro_mutex_destroy(M)	(*(M) = 0)

#if 0
#define globus_macro_mutex_lock(M) \
    ( (*(M)) \
     ? (globus_fatal("globus_mutex_lock(): Deadlock detected in file %s at line %d. The mutex at address 0x%lu is already locked.\n", __FILE__, __LINE__, (unsigned long) (M)), 1) \
     : ( ((*(M)) = 1), 0 ) )
#else
#define globus_macro_mutex_lock(M) \
    ( ((*(M)) = 1), 0 )
#endif

#define globus_macro_mutex_unlock(M) \
    ( ((*(M)) = 0), 0 )

#define globus_macro_mutex_trylock(M) \
    (*(M) ? 1 : globus_macro_mutex_lock(M))

#define globus_macro_cond_init(C,A) \
    (((A) ? (*(C) = *((int *)(A))) \
     : (*(C) = GLOBUS_CALLBACK_GLOBAL_SPACE)), \
    (globus_callback_space_reference(*(C)) ? 1 : 0))
    
#define globus_macro_cond_destroy(C) \
    (globus_callback_space_destroy(*(C)), *(C) = GLOBUS_NULL_HANDLE, 0)
    
#define globus_macro_cond_wait(C,M) \
    ( ((*(M)) = 0), \
        globus_thread_blocking_space_will_block(*(C)), \
        globus_callback_space_poll(&globus_i_abstime_infinity,*(C)), \
        ((*(M)) = 1), 0 )
   
#define globus_macro_cond_timedwait(C,M, T) \
    ( ((*(M)) = 0), \
	globus_thread_blocking_space_will_block(*(C)), \
	globus_callback_space_poll((T),*(C)), \
	((*(M)) = 1), \
	(time(GLOBUS_NULL) >= (T)->tv_sec) ? ETIMEDOUT : 0 )

#define globus_macro_cond_signal(C) \
    (globus_callback_signal_poll(), 0)
    
#define globus_macro_cond_broadcast(C) \
    (globus_callback_signal_poll(), 0)

#define globus_macro_condattr_init(A) \
    (globus_callback_space_reference(GLOBUS_CALLBACK_GLOBAL_SPACE), \
    (*(A) = GLOBUS_CALLBACK_GLOBAL_SPACE), 0)
    
#define globus_macro_condattr_destroy(A) \
    (globus_callback_space_destroy(*(A)), (*(A) = 0))

#define globus_macro_condattr_setspace(A, S) \
    ((globus_callback_space_reference((S)) \
     ? 1 \
     : (globus_callback_space_destroy(*(A)), (*(A) = (S)), 0)))

#define globus_macro_condattr_getspace(A, S) \
    ((*(S) = *(A)), 0)

#define globus_macro_thread_create(T,A,F,U) \
    ((T) ? (*((int *)(T)) = -1) : -1)

#define globus_macro_thread_yield() \
    (globus_poll_nonblocking())

#define globus_macro_thread_key_create(K,D) \
     (*(K) = GLOBUS_NULL, 0)


#define globus_macro_thread_setspecific(K,V) \
    ((K) = (void *) (V), 0)

#define globus_macro_thread_getspecific(K) \
    (K)

#define globus_macro_thread_key_delete(K) \
    ((K) = GLOBUS_NULL, 0)
    
#define globus_macro_thread_once(C, R) \
    (((C) == NULL || (R) == NULL) ? GLOBUS_FAILURE : \
    (*(C) == GLOBUS_THREAD_ONCE_INIT) ? \
    (*(C) = GLOBUS_THREAD_ONCE_CALLED), (R)(), 0 : 0)


#define globus_macro_thread_self() \
    (0)

#define globus_thread_get_threadID_as_long() globus_macro_thread_self()

#define globus_macro_thread_equal(T1, T2) \
    ((T1) == (T2))

#define globus_macro_thread_premptive_threads()   GLOBUS_FALSE

/******************************************************************************
		       Function prototypes / definitions
******************************************************************************/
#ifndef USE_MACROS
#     define __THREAD_NONE_FORCE_MACRO_USE
#     define USE_MACROS
#endif

#if defined(USE_MACROS)

#define globus_mutex_init(M,A) globus_macro_mutex_init(M,A)
#define globus_mutex_destroy(M) globus_macro_mutex_destroy(M)
#define globus_mutex_lock(M) globus_macro_mutex_lock(M)
#define globus_mutex_unlock(M) globus_macro_mutex_unlock(M)
#define globus_mutex_trylock(M) globus_macro_mutex_trylock(M)
#define globus_cond_init(C,A) globus_macro_cond_init(C,A)
#define globus_cond_destroy(C) globus_macro_cond_destroy(C)
#define globus_cond_wait(C,M) globus_macro_cond_wait(C,M)
#define globus_cond_timedwait(C,M,T) globus_macro_cond_timedwait(C,M,T)
#define globus_cond_signal(C) globus_macro_cond_signal(C)
#define globus_cond_broadcast(C) globus_macro_cond_broadcast(C)
#define globus_condattr_init(A) globus_macro_condattr_init(A)
#define globus_condattr_destroy(A) globus_macro_condattr_destroy(A)
#define globus_condattr_setspace(A,S) globus_macro_condattr_setspace(A,S)
#define globus_condattr_getspace(A,S) globus_macro_condattr_getspace(A,S)
#define globus_thread_create(T,A,F,U) globus_macro_thread_create(T,A,F,U)
#define globus_thread_yield() globus_macro_thread_yield()
#define globus_thread_key_create(K,D) globus_macro_thread_key_create(K,D)
#define globus_thread_setspecific(K,V) globus_macro_thread_setspecific(K,V)
#define globus_thread_getspecific(K) globus_macro_thread_getspecific(K)
#define globus_thread_key_delete(K) globus_macro_thread_key_delete(K)
#define globus_thread_once(C,R) globus_macro_thread_once(C,R)
#define globus_thread_self() globus_macro_thread_self()
#define globus_thread_equal(T1,T2) globus_macro_thread_equal(T1,T2)
#define globus_thread_preempitve_threads() globus_macro_thread_preempitive_threads()
    
#else  /* USE_MACROS */

extern int
globus_mutex_init(
    globus_mutex_t *			mutex,
    globus_mutexattr_t *		attr);

extern int
globus_mutex_destroy(
    globus_mutex_t *			mutex);

extern int
globus_mutex_lock(
    globus_mutex_t *			mutex);

extern int
globus_mutex_unlock(
    globus_mutex_t *			mutex);

extern int
globus_mutex_trylock(
    globus_mutex_t *			mutex);

extern int
globus_cond_init(
    globus_cond_t *			cond,
    globus_condattr_t *			attr);

extern int
globus_cond_destroy(
    globus_cond_t *			cond);

extern int
globus_cond_wait(
    globus_cond_t *			cond,
    globus_mutex_t *			mutex);

extern int
globus_cond_signal(
    globus_cond_t *			cond);

extern int
globus_cond_broadcast(
    globus_cond_t *			cond);

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

extern int
globus_thread_create(
    globus_thread_t *			thread,
    globus_threadattr_t *		attr,
    globus_thread_func_t		func,
    void *				user_arg);

void *
globus_thread_getspecific(
    globus_thread_key_t                 key);

int
globus_thread_setspecific(
    globus_thread_key_t                 key,
    void *                              value);

int
globus_thread_key_create(
    globus_thread_key_t *               key,
    globus_thread_key_destructor_func_t func);
    
int
globus_thread_key_delete(
    globus_thread_key_t                 key);

extern void
globus_thread_yield(void);

extern globus_thread_t
globus_thread_self(void);

extern int
globus_thread_equal(
    globus_thread_t			                        thread1,
    globus_thread_t			                        thread2);

extern globus_bool_t
globus_thread_preemptive_threads();

#endif /* USE_MACROS */

#ifdef __THREAD_NONE_FORCE_MACRO_USE
#       undef USE_MACROS 
#       undef __THREAD_NONE_FORCE_MACRO_USE
#endif

/******************************************************************************
			       Module definition
******************************************************************************/
extern int globus_i_thread_pre_activate();

extern globus_module_descriptor_t	                globus_i_thread_module;

#define GLOBUS_THREAD_MODULE (&globus_i_thread_module)

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_THREAD */


