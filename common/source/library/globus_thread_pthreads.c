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
globus_thread_pthreads.c

Description:

  Bindings for the Globus threads package, to be used when Globus has been
  configured to use POSIX threads.

CVS Information:

  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/
#include "config.h"
#include "globus_common.h"
#include "globus_thread_common.h"
#include "globus_i_thread.h"
#include "version.h"

typedef struct globus_i_thread_s
{
    int					id;
    globus_thread_func_t		user_func;
    void *				user_arg;
    struct globus_i_thread_s *		next_free;
} globus_i_thread_t;



/*
 * globus_l_thread_self()
 *
 * Set *Thread (globus_i_thread_t **) to the calling thread.
 */
#define globus_l_thread_self(Thread) \
    *(Thread) = (globus_i_thread_t *)globus_thread_getspecific(globus_thread_all_global_vars.globus_thread_t_pointer) 



#ifdef HAVE_SYS_CNX_PATTR_H
#include <sys/cnx_pattr.h>
#endif

#define MAX_ERR_SIZE 80
#define GLOBUS_L_THREAD_GRAN 256

#ifdef BUILD_DEBUG
static int hasThreads = 0;
#endif

#ifdef PORTS0_ARCH_MIT_PTHREADS
static struct sched_param ports0_sched_param;

#define pthread_attr_setsched(a, b) pthread_attr_setschedpolicy(a, b)
#define pthread_attr_setprio(attr, p) \
	(ports0_sched_param.prio = p, \
		pthread_attr_setschedparam(attr, &ports0_sched_param))
#define pthread_setscheduler(t, s, p) \
	(ports0_sched_param.prio = p, \
		pthread_setschedparam(t, s, &ports0_sched_param))

#ifndef PTHREAD_DEFAULT_SCHED
#define PTHREAD_DEFAULT_SCHED 0
#endif
#endif /* PORTS0_ARCH_MIT_PTHREADS */

#ifndef PORTS0_DEFAULT_STACK_SIZE
#define PORTS0_DEFAULT_STACK_SIZE -1
#endif

globus_i_thread_global_vars_t globus_thread_all_global_vars;
#ifdef HAVE_PTHREAD_SCHED
static globus_bool_t	arg_got_sched;
static int	 	scheduler;
static int		priority_min;
static int		priority_max;
static int		priority_mid;
#endif

static globus_bool_t	preemptive_threads;
static globus_bool_t	arg_got_stack_size;
static long		stack_size;

static globus_bool_t    globus_l_thread_already_initialized=GLOBUS_FALSE;
/*
 * Free list of globus_i_thread_t structures
 */
static globus_i_thread_t *	thread_freelist;
static globus_mutex_t	thread_mem_mutex;
static int              next_thread_id;

static void *		thread_starter(void *temparg);
static globus_i_thread_t *	new_thread(void);
static void		set_tsd(globus_i_thread_t *);

static int globus_l_thread_activate();
static int globus_l_thread_deactivate();

globus_module_descriptor_t globus_i_thread_module =
{
    "globus_thread_pthreads",
    globus_l_thread_activate,
    globus_l_thread_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/*
 * globus_i_thread_pre_activate()
 *
 * If you need to call a thread package initialization routine, then
 * do it here.  This is called as the very first thing in ports0_init().
 *
 * Note: You should not use ports0 thread stuff until after
 * _p0_thread_init() is called.
 */
int
globus_i_thread_pre_activate( void )
{
  int rc;


#ifdef HAVE_SYS_CNX_PATTR_H
  /* HP Convex requires process attributes set to "parallel"
   * before additional threads are created.  A pthread create
   * without this attribute set will fail with errno EAGAIN,
   * "Out of resources".
   */
  {
    struct cnx_pattributes p0_pattrs;
    p0_pattrs.pattr_parallel = 1;
    cnx_setpattr(getpid(), CNX_PATTR_PARALLEL, &p0_pattrs);
  }
#endif
#ifdef HAVE_PTHREAD_INIT_FUNC
    /*
     * FSU pthreads uses its own read/write/malloc routines, which
     * might get called during the argument handling, before
     * globus_l_thread_activate() is called.
     */
    pthread_init();
#endif /* HAVE_PTHREAD_INIT_FUNC */

    rc = globus_mutex_init(&globus_libc_mutex,
			   (globus_mutexattr_t *) GLOBUS_NULL);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: globus_mutex_init() failed\n"));

    return globus_i_thread_ignore_sigpipe();
} /* globus_i_thread_pre_activate() */

/*
 * globus_l_thread_activate()
 *
 * This should be used to initialize all the thread related things
 * that Globus threads will be using, including things that might be
 * specified by arguments.
 */
static int
globus_l_thread_activate()
{
    int rc;
    globus_i_thread_t *thread;
#if defined(HAVE_PTHREAD_SCHED) && !defined(HAVE_PTHREAD_DRAFT_4) && !defined(HAVE_PTHREAD_DRAFT_6)
    struct sched_param my_sched_param;
#endif

  globus_module_activate(GLOBUS_THREAD_COMMON_MODULE);
  if(globus_l_thread_already_initialized)
  {
      return GLOBUS_SUCCESS;
  }

  globus_l_thread_already_initialized = GLOBUS_TRUE;

#ifdef HAVE_PTHREAD_SCHED
    /* Get the -sched command line argument */
    arg_got_sched = GLOBUS_FALSE;
#   if !defined(HAVE_THREAD_SAFE_STDIO)
        scheduler = SCHED_FIFO;
#   else
        scheduler = SCHED_RR;
#   endif
#endif
    
    /* Get the -stack command line argument */
    stack_size = (long) PORTS0_DEFAULT_STACK_SIZE;
    arg_got_stack_size = GLOBUS_FALSE;

#ifdef HAVE_PTHREAD_DRAFT_4
    /*
     * Set the default attributes for mutex and condition
     */
    rc = pthread_mutexattr_create(&(globus_i_thread_all_global_vars.mutexattr));
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_mutexattr_create() failed\n"));

#ifndef HAVE_NO_PTHREAD_SETKIND
#ifdef BUILD_DEBUG    
    rc = pthread_mutexattr_setkind_np(&(globus_i_thread_all_global_vars.mutexattr),
				      MUTEX_NONRECURSIVE_NP );
#else  /* BUILD_DEBUG */    
    rc = pthread_mutexattr_setkind_np(&(globus_i_thread_all_global_vars.mutexattr),
				      MUTEX_FAST_NP );
#endif /* BUILD_DEBUG */    
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_mutexattr_setkind() failed\n"));
#endif /* HAVE_NO_PTHREAD_SETKIND */
    
#ifdef HAVE_NO_CONDATTR_DEFAULT
    rc = pthread_condattr_create(&(globus_i_thread_all_global_vars.condattr.condattr));
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_condattr_create() failed\n"));
#else  /* HAVE_NO_CONDATTR_DEFAULT */
    globus_i_thread_all_global_vars.condattr.condattr = pthread_condattr_default;
#endif /* HAVE_NO_CONDATTR_DEFAULT */
    
#endif /* HAVE_PTHREAD_DRAFT_4 */

    
    /*
     * Define the parameters for the scheduler being used
     */
#ifdef HAVE_PTHREAD_SCHED
    if (scheduler == SCHED_FIFO)
    {
        preemptive_threads = GLOBUS_FALSE;
#if defined(HAVE_PTHREAD_DRAFT_4) || defined(PORTS0_ARCH_MIT_PTHREADS_1_51_2)
	priority_min = PRI_FIFO_MIN;
	priority_max = PRI_FIFO_MAX;
#elif defined(PORTS0_ARCH_MIT_PTHREADS)
	priority_min = PTHREAD_MIN_PRIORITY;
	priority_max = PTHREAD_MAX_PRIORITY;
#elif defined(HAVE_PTHREAD_PRIO_MINMAX)
	priority_min = PTHREAD_PRIO_MIN;
	priority_max = PTHREAD_PRIO_MAX;
#else
	priority_min = sched_get_priority_min( SCHED_FIFO );
	priority_max = sched_get_priority_max( SCHED_FIFO );
#endif
	priority_mid = (priority_min + priority_max) / 2;
    }
    else /* (scheduler == SCHED_RR) */
    {
	preemptive_threads = GLOBUS_TRUE;
#if defined(HAVE_PTHREAD_DRAFT_4) || defined(PORTS0_ARCH_MIT_PTHREADS_1_51_2)
	priority_min = PRI_RR_MIN;
	priority_max = PRI_RR_MAX;
#elif defined(PORTS0_ARCH_MIT_PTHREADS)
	priority_min = PTHREAD_MIN_PRIORITY;
	priority_max = PTHREAD_MAX_PRIORITY;
#elif defined(HAVE_PTHREAD_PRIO_MINMAX)
	priority_min = PTHREAD_PRIO_MIN;
	priority_max = PTHREAD_PRIO_MAX;
#else
	priority_min = sched_get_priority_min( SCHED_RR );
	priority_max = sched_get_priority_max( SCHED_RR );
#endif
	priority_mid = (priority_min + priority_max) / 2;
    }
#else  /* HAVE_PTHREAD_SCHED */
#ifdef HAVE_PTHREAD_PREEMPTIVE
    preemptive_threads = GLOBUS_TRUE;
#else
    preemptive_threads = GLOBUS_FALSE;
#endif
#endif /* HAVE_PTHREAD_SCHED */

    /*
     * Setup the default thread attributes
     */
#ifdef HAVE_PTHREAD_DRAFT_4
    rc = pthread_attr_create(&(globus_i_thread_all_global_vars.threadattr));
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_attr_create() failed\n" ));
#else
    rc = pthread_attr_init(&(globus_thread_all_global_vars.threadattr));
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_attr_init() failed\n" ));
#endif

#ifdef HAVE_PTHREAD_SCHED
#if defined(HAVE_PTHREAD_DRAFT_4) || defined(HAVE_PTHREAD_DRAFT_6)
    rc = pthread_attr_setinheritsched(&(globus_thread_all_global_vars.threadattr),
				      PTHREAD_DEFAULT_SCHED);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_attr_setinheritsched() failed\n" ));
    rc = pthread_attr_setsched(&(globus_thread_all_global_vars.threadattr),
			       scheduler);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_attr_setsched() failed\n" ));
    rc = pthread_attr_setprio(&(globus_thread_all_global_vars.threadattr),
			      priority_mid);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_attr_setprio() failed\n" ));
#else
    rc = pthread_attr_setinheritsched(&(globus_thread_all_global_vars.threadattr),
				      PTHREAD_EXPLICIT_SCHED);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_attr_setinheritsched() failed\n" ));
    my_sched_param.sched_policy = scheduler;
    my_sched_param.sched_priority = priority_mid;
    rc = pthread_attr_setschedparam(&(globus_thread_all_global_vars.threadattr),
				    &my_sched_param);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_attr_setschedparam() failed\n" ));
#endif
#endif /* HAVE_PTHREAD_SCHED */

#ifndef TARGET_ARCH_LINUX
    if (stack_size > 0)
    {
	rc = pthread_attr_setstacksize(&(globus_thread_all_global_vars.threadattr),
				       stack_size);
	globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_attr_setstacksize() failed\n" ));
    }
#endif /* ! TARGET_ARCH_LINUX */
    
    /*
     * Make this initial thread have the default thread attributes
     */
#ifdef HAVE_PTHREAD_SCHED
#if defined(HAVE_PTHREAD_DRAFT_4) || defined(PORTS0_ARCH_MIT_PTHREADS)
    pthread_setscheduler(pthread_self(), scheduler, priority_mid);
    /*
     * Note: Do not check this return code for 0.  It apparently returns 
     * the old scheduler.
     */
#elif defined(HAVE_PTHREAD_DRAFT_6)
    rc = pthread_setschedattr(pthread_self(),
			      globus_thread_all_global_vars.threadattr);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_setschedattr() failed\n"));
#else
    rc = pthread_setschedparam(pthread_self(),
			       my_sched_param.sched_policy,
			       &my_sched_param);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_setschedparam() failed\n"));
#endif
#endif /* HAVE_PTHREAD_SCHED */

    /*
     * Setup thread specific storage which contains
     * a pointer to the globus_i_thread_t structure for the thread.
     */
    rc = globus_thread_key_create(
			     &(globus_thread_all_global_vars.globus_thread_t_pointer),
			     NULL);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_key_create() failed\n"));
    
    globus_mutex_init(&(thread_mem_mutex),
		      (globus_mutexattr_t *) NULL);
    next_thread_id = 0;

		      
    /*
     * Initialize the globus_i_thread_t structure for this initial thread
     */
    thread = new_thread();
    set_tsd(thread);

    
#ifdef BUILD_DEBUG
    hasThreads = 1;
#endif

    return GLOBUS_SUCCESS;
} /* globus_l_thread_activate() */


/*
 * globus_l_thread_deactivate()
 */
static int
globus_l_thread_deactivate(void)
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

    new_thread->id = next_thread_id++;
    
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
#ifdef BUILD_PROFILE
    /*
    log_thread_destruction(thread->id);
    */
#endif /* BUILD_PROFILE */    

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
void
globus_thread_exit(void *status)
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
    globus_thread_setspecific(
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

#ifdef BUILD_PROFILE
    /*
    log_thread_creation(thread->id);
    */
#endif /* BUILD_PROFILE */    
    
    /* Call the user function */
    status = (*thread->user_func)(thread->user_arg);
    
    /* Terminate the thread */
    terminate_thread(thread, status, GLOBUS_FALSE);
  
    return (NULL);
} /* thread_starter() */


/*
 * globus_thread_create
 */
int
globus_thread_create(globus_thread_t *user_thread,
		     globus_threadattr_t *attr,
		     globus_thread_func_t func,
		     void *user_arg )
{
    int rc;
    globus_i_thread_t *thread;
    pthread_t thread_id;

    thread = new_thread();
  
    /* Initialize the thread data that needs to be passed to the new thread */
    thread->user_func = func;
    thread->user_arg = user_arg;
  
#if defined(HAVE_PTHREAD_DRAFT_8) || defined(HAVE_PTHREAD_DRAFT_10)
    rc = pthread_attr_setdetachstate(attr ? attr : &(globus_thread_all_global_vars.threadattr), PTHREAD_CREATE_DETACHED);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD:pthread_attr_setdetachstate() failed\n"));
#endif

    /* Note: With HP's Convex during port testing we experienced a
     * hang condition on pthread creation.  This case was encountered
     * when using a threaded handler and shutting down nodes before
     * running communication tests on new contexts. (In program
     * test_nx the tests described as USE_THREADED_HANDLER with
     * SHUTDOWN_NODES_BEFORE_CONTEXTS.)  The ultimate cause of the
     * problem was not determined, however it appears to be timing
     * related.  With a lightly loaded machine the hang condition can
     * be avoided by yielding the thread's schedule up to 5000 times.
     * The number of yields can be reduced with increasing loads, and
     * is not necessary at all under moderately loaded machines. 
     * {  int times_to_yield;
     *    for (times_to_yield=0; times_to_yield < 5000; times_to_yield++) 
     *      sched_yield();
     * } */

    rc = pthread_create(&thread_id,
#ifdef HAVE_PTHREAD_DRAFT_4			
			(attr ? *attr : globus_thread_all_global_vars.threadattr),
#else			
			(attr ? attr : &(globus_thread_all_global_vars.threadattr)),
#endif
			thread_starter,
			thread);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_create() failed\n") );

    /*
     * Note: With AIX 3.1.x DCE threads, the pthread_detach(&thread_id)
     * wipes out the thread_id structure.  So we need to assign
     * it to the user thread here, before the detach.
     */
    if (user_thread)
    {
	*user_thread = thread_id;
    }

#if !defined(HAVE_PTHREAD_DRAFT_8) && !defined(HAVE_PTHREAD_DRAFT_10)
#ifdef PORTS0_ARCH_MIT_PTHREADS
    rc = pthread_detach(thread_id);
#else
    rc = pthread_detach(&thread_id);
#endif /* PORTS0_ARCH_MIT_PTHREADS */
#endif /* !HAVE_PTHREAD_DRAFT_8 && !HAVE_PTHREAD_DRAFT_10 */
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_detach() failed\n") );

    return (0);
} /* globus_thread_create() */


/*
 * globus_thread_preemptive_threads
 *
 * Return GLOBUS_TRUE (non-zero) if we are using preemptive threads.
 */
globus_bool_t
globus_thread_preemptive_threads(void)
{
    return (preemptive_threads);
} /* globus_thread_preemptive_threads() */



/*
 * globus_threadattr_init()
 */
#undef globus_threadattr_init
int
globus_threadattr_init(globus_threadattr_t *attr)
{
    return (globus_macro_threadattr_init(attr));
}

/*
 * globus_threadattr_destroy()
 */
#undef globus_threadattr_destroy
int globus_threadattr_destroy(globus_threadattr_t *attr)
{
    return (globus_macro_threadattr_destroy(attr));
}

/*
 * globus_threadattr_setstacksize()
 */
#undef globus_threadattr_setstacksize
int globus_threadattr_setstacksize(globus_threadattr_t *attr,
				   size_t stacksize)
{
    return (globus_macro_threadattr_setstacksize(attr, stacksize));
}

/*
 * globus_threadattr_getstacksize()
 */
#undef globus_threadattr_getstacksize
int globus_threadattr_getstacksize(globus_threadattr_t *attr,
				   size_t *stacksize)
{
    return (globus_macro_threadattr_getstacksize(attr, stacksize));
}

/*
 * globus_thread_key_create()
 */
#undef globus_thread_key_create
int globus_thread_key_create(globus_thread_key_t *key,
			globus_thread_key_destructor_func_t destructor_func)
{
    int rc;
    rc = globus_macro_thread_key_create(key, destructor_func);
    if (rc != 0 && rc != EAGAIN)
    {
	globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: globus_thread_key_create() failed\n"));
    }
    return(rc);
} /* globus_thread_key_create() */


/*
 * globus_thread_key_delete()
 */
#undef globus_thread_key_delete
int globus_thread_key_delete(globus_thread_key_t key)
{
    int rc;
    rc = globus_macro_thread_key_delete(key);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: globus_thread_key_delete() failed\n"));
    return(rc);
} /* globus_thread_key_delete() */


/*
 * globus_thread_setspecific()
 */
#undef globus_thread_setspecific
int globus_thread_setspecific(globus_thread_key_t key,
			      void *value)
{
    int rc;
    rc = globus_macro_thread_setspecific(key, value);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: globus_thread_setspecific() failed\n"));
    return(rc);
} /* globus_thread_setspecific() */


/*
 * globus_thread_getspecific()
 */
#undef globus_thread_getspecific
void *globus_thread_getspecific(globus_thread_key_t key)
{
    void *value;

    value = (void *) globus_macro_thread_getspecific(key);
    return (value);
} /* globus_thread_getspecific() */

#ifdef GLOBUS_I_THREAD_GETSPECIFIC
void *
globus_i_thread_getspecific(globus_thread_key_t key)
{
    void *value;

    pthread_getspecific(key, &value);
    return (value);
} /* globus_i_thread_getspecific() */
#endif /* GLOBUS_I_THREAD_GETSPECIFIC */

/*
 * globus_thread_self()
 */
#undef globus_thread_self
globus_thread_t globus_thread_self(void)
{
    return(globus_macro_thread_self());
} /* globus_thread_self() */


/*
 * globus_thread_equal()
 */
#undef globus_thread_equal
int globus_thread_equal(globus_thread_t t1,
			globus_thread_t t2)
{
    return (globus_macro_thread_equal(t1, t2));
} /* globus_thread_equal() */


/*
 * globus_thread_once()
 */
#undef globus_thread_once
int globus_thread_once(globus_thread_once_t *once_control,
#ifdef HAVE_PTHREAD_DRAFT_6
		       void (*init_routine)(void *))
#else
		       void (*init_routine)(void))
#endif
{
    return (globus_macro_thread_once(once_control, init_routine));
} /* globus_thread_once() */


/*
 * globus_thread_yield
 */
#undef globus_thread_yield
void globus_thread_yield(void)
{
    globus_macro_thread_yield();
} /* globus_thread_yield() */


/*
 * globus_i_am_only_thread()
 */
#undef globus_i_am_only_thread
globus_bool_t globus_i_am_only_thread(void)
{
    return (globus_macro_i_am_only_thread());
}


/*
 * globus_mutexattr_init()
 */
#undef globus_mutexattr_init
int globus_mutexattr_init(globus_mutexattr_t *attr)
{
    int rc;
    rc = globus_macro_mutexattr_init(attr);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_mutexattr_init() failed\n"));
    return (rc);
}

/*
 * globus_mutexattr_destroy()
 */
#undef globus_mutexattr_destroy
int globus_mutexattr_destroy(globus_mutexattr_t *attr)
{
    int rc;
    rc = globus_macro_mutexattr_destroy(attr);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUSTHREAD: pthread_mutexattr_destroy() failed\n"));
    return (rc);
}

/*
 * globus_mutex_init()
 */
#undef globus_mutex_init
int globus_mutex_init(globus_mutex_t *mut, globus_mutexattr_t *attr)
{
    int rc;
    rc = globus_macro_mutex_init(mut, attr);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_init() failed\n" ));
    return(rc);
} /* globus_mutex_init() */


/*
 *  globus_mutex_destroy()
 */
#undef globus_mutex_destroy
int globus_mutex_destroy(globus_mutex_t *mut)
{
    int rc; 
    rc = globus_macro_mutex_destroy(mut);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_destroy() failed\n" ));
    return(rc);
} /* globus_mutex_destroy() */


/* 
 *  globus_mutex_lock()
 */
#undef globus_mutex_lock
int globus_mutex_lock(globus_mutex_t *mut)
{
    int rc;
    rc = globus_macro_mutex_lock(mut);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_lock() failed\n" ));
    return(rc);
} /* globus_mutex_lock() */


/* 
 *  globus_mutex_trylock()
 */
#undef globus_mutex_trylock
int globus_mutex_trylock(globus_mutex_t *mut)
{
    int rc;
    rc = globus_macro_mutex_trylock(mut);
    if (rc != EBUSY)
    {
	globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_trylock() failed\n" ));
    }
    return(rc);
} /* globus_mutex_trylock() */


/*
 *  globus_mutex_unlock()
 */
#undef globus_mutex_unlock
int globus_mutex_unlock(globus_mutex_t *mut)
{
    int rc;
    rc = globus_macro_mutex_unlock(mut);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_mutex_unlock() failed\n" ));
    return(rc);
} /* globus_mutex_unlock() */


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
 * globus_condattr_init()
 */
#undef globus_condattr_init
int globus_condattr_init(globus_condattr_t *attr)
{
    int rc;
    rc = globus_macro_condattr_space_init(attr);
    return (rc);
}

/*
 * globus_condattr_destroy()
 */
#undef globus_condattr_destroy
int globus_condattr_destroy(globus_condattr_t *attr)
{
    int rc;
    rc = globus_macro_condattr_space_destroy(attr);
    return (rc);
}

/*
 * globus_cond_init()
 */
#undef globus_cond_init
int globus_cond_init(globus_cond_t *cv, globus_condattr_t *attr)
{
    int rc;
    rc = globus_macro_cond_space_init(cv, attr);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_cond_init() failed\n" ));
    return(rc);
} /* globus_cond_init() */


/*
 *  globus_cond_destroy()
 */
#undef globus_cond_destroy
int globus_cond_destroy(globus_cond_t *cv)
{
    int rc; 
    rc = globus_macro_cond_space_destroy(cv);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_cond_destroy() failed\n" ));
    return(rc);
} /* globus_cond_destroy() */


/*
 *  globus_cond_wait()
 */
#undef globus_cond_wait
int globus_cond_wait(globus_cond_t *cv, globus_mutex_t *mut)
{
    int rc;

    rc = globus_macro_cond_space_wait(cv, mut);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_cond_wait() failed\n" ));
    return(rc);
} /* globus_cond_wait() */

/*
 *  globus_cond_wait()
 */
#undef globus_cond_timedwait
int 
globus_cond_timedwait(globus_cond_t *cv, 
		      globus_mutex_t *mut,
		      globus_abstime_t *abstime)
{
    int rc;

    rc = globus_macro_cond_space_timedwait(cv, mut, (struct timespec *) abstime);
    if(rc != ETIMEDOUT
#if defined(ETIME)
       && rc != ETIME
#endif
	)
    {
	globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_cond_timedwait() failed\n" ));
    }
#if defined(ETIME)
    if(rc == ETIME)
    {
	rc = ETIMEDOUT;
    }
#endif
    errno=rc;
    return(rc);
} /* globus_cond_timedwait() */

/*
 *  globus_cond_signal()
 */
#undef globus_cond_signal
int globus_cond_signal(globus_cond_t *cv)
{
    int rc; 
    rc = globus_macro_cond_space_signal(cv); 
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_cond_signal() failed\n" ));
    return(rc);
} /* globus_cond_signal () */


/*
 *  globus_cond_broadcast()
 */
#undef globus_cond_broadcast
int globus_cond_broadcast(globus_cond_t *cv)
{
    int rc; 
    rc = globus_macro_cond_space_broadcast(cv); 
    globus_i_thread_test_rc( rc, _GCSL("GLOBUSTHREAD: pthread_cond_broadcast() failed\n" ));
    return(rc);
} /* globus_cond_broadcast() */


#undef globus_thread_sigmask
int
globus_thread_sigmask(
    int                                 how,
    const sigset_t *                    newmask,
    sigset_t *                          oldmask)
{
    int rc; 
    rc = globus_macro_thread_sigmask(how, newmask, oldmask); 
    globus_i_thread_test_rc(rc, "GLOBUSTHREAD: pthread_sigmask() failed\n");
    return(rc);
}

#undef globus_thread_cancel
int
globus_thread_cancel(
    globus_thread_t                     thread)
{
    int rc; 
    rc = globus_macro_thread_cancel(thread);
    globus_i_thread_test_rc(rc, "GLOBUSTHREAD: pthread_cancel() failed\n");
    return(rc);
}

#undef globus_thread_testcancel
void
globus_thread_testcancel(void)
{
    globus_macro_thread_testcancel();
}

#undef globus_thread_setcancelstate
int
globus_thread_setcancelstate(
    int                                 state,
    int *                               oldstate)
{
    int rc; 
    rc = globus_macro_thread_setcancelstate(state, oldstate);
    globus_i_thread_test_rc(rc, "GLOBUSTHREAD: pthread_setcancelstate() failed\n");
    return(rc);
}

void
globus_thread_prefork(void)
{
#ifdef HAVE_PTHREAD_DRAFT_6
    pthread_attr_t new;
    sigset_t set;

/*
 * Currently, all threads run at a default priority, so it is not
 * necessary to save the priority of the thread before temporarily
 * changing it.  However, if the user is given control over thread
 * priorities, this should be saved in a thread specific variable
 */
    pthread_attr_setprio(&new, sched_get_priority_max(SCHED_RR));
    pthread_setschedattr(pthread_self(), new);

    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_BLOCK, &set, NULL);
#endif
}

void
globus_thread_postfork(void)
{
#ifdef JGG
#ifdef HAVE_PTHREAD_DRAFT_6
    pthread_attr_t old;
    sigset_t set;

    pthread_attr_setprio(&old, globus_thread_all_global_vars.threadattr);
    pthread_setschedattr(pthread_self(), old);
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
#endif
#endif
}
