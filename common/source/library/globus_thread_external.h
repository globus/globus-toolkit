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
 * The user must provide a globus_external_threads.h file that implements
 * the thread interface
 */

#include "globus_external_threads.h"

/*
 * The file above should implement/define the following: it's basically
 * a pthreads subset, and with the same semantics.
 *
 * globus_module_descriptor_t	globus_i_thread_module;
 * #define GLOBUS_THREAD_MODULE (&globus_i_thread_module)
 *
 * globus_abstime_t
 *
 * globus_thread_t
 * globus_threadattr_t
 *
 * globus_mutex_t
 * globus_mutexattr_t
 *
 * globus_cond_t
 * globus_condattr_t
 *
 * globus_thread_key_t
 * globus_thread_once_t
 *
 * typedef void *(*globus_thread_func_t)(void *)
 * typedef void (*globus_thread_key_destructor_func_t)(void *value)
 *
 * int
 * globus_thread_create(globus_thread_t *thread,
 *                      globus_threadattr_t *attr,
 *                      globus_thread_func_t func,
 *                      void *user_arg);
 *
 *
 * void
 * globus_thread_exit(void *status);
 *
 * int
 * globus_threadattr_init(globus_threadattr_t *attr);
 * 
 * int		
 * globus_threadattr_destroy(globus_threadattr_t *attr);
 * 
 * int		
 * globus_threadattr_setstacksize(globus_threadattr_t *attr,
 * 			       globus_size_t stacksize);
 * 
 * int		
 * globus_threadattr_getstacksize(globus_threadattr_t *attr,
 * 			       globus_size_t *stacksize);
 * 
 * int		
 * globus_thread_key_create(globus_thread_key_t *key,
 * 			 globus_thread_key_destructor_func_t destructor_func);
 * 
 * int		
 * globus_thread_key_delete(globus_thread_key_t key);
 * 
 * int		
 * globus_thread_setspecific(globus_thread_key_t key,
 * 			  void *value);
 * 
 * void *		
 * globus_thread_getspecific(globus_thread_key_t key);
 * 
 * globus_thread_t
 * globus_thread_self(void);
 * 
 * int		
 * globus_thread_equal(globus_thread_t t1,
 * 		    globus_thread_t t2);
 * 
 * int		
 * globus_thread_once(globus_thread_once_t *once_control,
 * 		   void (*init_routine)(void*));
 * 
 * void		
 * globus_thread_yield(void);
 * 
 * globus_bool_t    
 * globus_i_am_only_thread(void);
 * 
 * globus_bool_t
 * globus_thread_preemptive_threads(void);
 * 
 * int		
 * globus_mutexattr_init(globus_mutexattr_t *attr);
 * 
 * int		
 * globus_mutexattr_destroy(globus_mutexattr_t *attr);
 * 
 * int		
 * globus_mutex_init(globus_mutex_t *mutex,
 * 		  globus_mutexattr_t *attr);
 * 
 * int		
 * globus_mutex_destroy(globus_mutex_t *mutex);
 * 
 * int		
 * globus_mutex_lock(globus_mutex_t *mutex);
 * 
 * int		
 * globus_mutex_trylock(globus_mutex_t *mutex);
 * 
 * int		
 * globus_mutex_unlock(globus_mutex_t *mutex);
 * 
 * int		
 * globus_condattr_init (globus_condattr_t *attr);
 * 
 * int		
 * globus_condattr_destroy (globus_condattr_t *attr);
 * 
 * int		
 * globus_cond_init(globus_cond_t *cond,
 * 		 globus_condattr_t *attr);
 * 
 * int		
 * globus_cond_destroy(globus_cond_t *cond);
 * 
 * int		
 * globus_cond_wait(globus_cond_t *cond,
 * 		 globus_mutex_t *mutex);
 * 
 * int	
 * globus_cond_timedwait(globus_cond_t *cond,
 * 		      globus_mutex_t *mutex,
 * 		      globus_abstime_t * abstime);
 * 
 * int		
 * globus_cond_signal(globus_cond_t *cond);
 * 
 * int		
 * globus_cond_broadcast(globus_cond_t *cond);
 *  
 */


