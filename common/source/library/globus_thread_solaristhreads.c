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
globus_thread_solaristhreads.c

Description:

  Bindings for the Globus threads package , to be used when Globus has been
  configured to use native solaris threads.

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

#ifndef GLOBUS_THREAD_DEFAULT_CONCURRENCY_LEVEL
#define GLOBUS_THREAD_DEFAULT_CONCURRENCY_LEVEL 2
#endif

typedef struct globus_i_thread_s
{
    int         		id;
    void                       *context;
    globus_thread_func_t        user_func;
    void                       *user_arg;
    struct globus_i_thread_s   *next_free;
} globus_i_thread_t;

/*
 * globus_l_thread_self()
 *
 * Set *Thread (globus_i_thread_t **) to the calling thread.
 */
static void
globus_l_thread_self(globus_i_thread_t **Thread)
{
    int rc;
    rc = thr_getspecific(globus_thread_all_global_vars.thread_t_pointer, 
			 (void *)(Thread)); 
    globus_i_thread_test_rc(rc,
			    _GCSL("GLOBUSTHREAD: get thread-local data failed\n"));
}

/*
 * globus_i_thread_id()
 *
 * Set *Thread_ID (int *) to be the thread id of the calling thread.
 */
void
globus_i_thread_id(globus_thread_t *Thread_ID)
{ 
    globus_i_thread_t *mythread;

    globus_l_thread_self(&mythread); 
    *(Thread_ID) = mythread->id; 
}



#define MAX_ERR_SIZE	80
#define GLOBUS_L_THREAD_GRAN 256
#define GLOBUS_L_USER_THREAD 0

#ifndef GLOBUS_L_THREAD_DEFAULT_CONCURRENCY_LEVEL
#define GLOBUS_L_THREAD_DEFAULT_CONCURRENCY_LEVEL 5
#endif

#ifndef GLOBUS_L_THREAD_DEFAULT_STACK_SIZE
#define GLOBUS_L_THREAD_DEFAULT_STACK_SIZE 0
#endif

static globus_bool_t	preemptive_threads = GLOBUS_TRUE;
static globus_bool_t	arg_got_sched;
static int		scheduler;
static int		priority_min;
static int		priority_max;
static int		priority_mid;

static globus_bool_t	arg_got_concurrency_level;
static int		arg_concurrency_level;
static globus_bool_t	arg_got_stack_size;
static long		arg_stack_size;
static long     	stack_size;
static int      	concurrency_level;
static globus_bool_t    globus_l_thread_already_initialized = GLOBUS_FALSE;

/*
 * Free list of globus_i_thread_t structures
 */
static globus_i_thread_t       *Thread_Freelist;
static globus_mutex_t		thread_mem_mutex;
static int              	next_thread_id;
static int			number_of_threads;

static void                    *thread_starter(void *temparg);
static globus_i_thread_t       *globus_l_thread_new_thread(void);
static void             	set_tsd(globus_i_thread_t *);

globus_i_thread_global_vars_t globus_thread_all_global_vars;

/* For globus_thread_once() */
static globus_mutex_t		globus_l_thread_once_mutex;

static int globus_l_thread_activate(void);
static int globus_l_thread_deactivate(void);

globus_module_descriptor_t globus_i_thread_module =
{
    "globus_thread_solaris",
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
 * do it here.  
 */
int
globus_i_thread_pre_activate( void )
{
    globus_mutex_init(&globus_libc_mutex, GLOBUS_NULL);
    return globus_i_thread_ignore_sigpipe();
} /* globus_l_thread_pre_activate() */


/*
 * globus_l_thread_activate()
 */
static int
globus_l_thread_activate()
{
    int i;
    int rc=0;
    int arg_num;
    globus_i_thread_t *thread;
    char *concurrency_var;

    globus_module_activate(GLOBUS_THREAD_COMMON_MODULE);

    if(globus_l_thread_already_initialized)
    {
	return GLOBUS_SUCCESS;
    }

    globus_l_thread_already_initialized = GLOBUS_TRUE;

    concurrency_level = GLOBUS_L_THREAD_DEFAULT_CONCURRENCY_LEVEL;
    arg_got_concurrency_level = GLOBUS_FALSE;

    stack_size = (long) GLOBUS_L_THREAD_DEFAULT_STACK_SIZE;
    arg_got_stack_size = GLOBUS_FALSE;

    preemptive_threads = GLOBUS_TRUE;

    concurrency_var = globus_module_getenv("GLOBUS_THREAD_CONCURRENCY");

    if(concurrency_var != GLOBUS_NULL)
    {
	int tmp_concurrency;

	tmp_concurrency = atoi(concurrency_var);

	if(tmp_concurrency > 0)
	{
	    arg_got_concurrency_level = GLOBUS_TRUE;
	    concurrency_level = tmp_concurrency;
	}
    }
    while((rc = thr_setconcurrency( concurrency_level ))==EINTR) ;

    globus_i_thread_test_rc(rc,
			    _GCSL("GLOBUS_THREAD: thr_setconcurrency failed\n"));

    (globus_thread_all_global_vars.general_attribute) = USYNC_THREAD;
    (globus_thread_all_global_vars.thread_flags) = THR_DETACHED;

    globus_threadattr_setstacksize(&globus_thread_all_global_vars.thread_attr,
				   (size_t) stack_size);
    
    
    while((rc =
	   thr_keycreate(
	       &(globus_thread_all_global_vars.thread_t_pointer),
	       GLOBUS_NULL))==EINTR);

    globus_i_thread_test_rc( rc, 
		    	    _GCSL("GLOBUS_THREAD: thr_keycreate failed\n"));
    
    globus_mutex_init(&(thread_mem_mutex),
		      (globus_mutexattr_t *) GLOBUS_NULL );
    
    /* Initialize the globus_l_thread_once_mutex */
    globus_mutex_init(&globus_l_thread_once_mutex,
		      (globus_mutexattr_t *) GLOBUS_NULL);
    next_thread_id = 0;
    
    /* Initialize the globus_i_thread_t structure for this initial thread */
    thread = globus_l_thread_new_thread();
    set_tsd(thread);

    return GLOBUS_SUCCESS;
} /* globus_l_thread_activate() */


/*
 * globus_l_thread_deactivate()
 */
int globus_l_thread_deactivate(void)
{
    int rc;
    
    rc = globus_module_deactivate(GLOBUS_THREAD_COMMON_MODULE);
    return rc;
} /* globus_l_thread_deactivate() */



/*
 * globus_l_thread_new_thread()
 */
static globus_i_thread_t *
globus_l_thread_new_thread(void)
{
    int i;
    globus_i_thread_t *new_thread;
    int mem_req_size;
    
    globus_mutex_lock(&thread_mem_mutex);
    
    if(Thread_Freelist == GLOBUS_NULL)
    {
	mem_req_size = sizeof(globus_i_thread_t) * GLOBUS_L_THREAD_GRAN;
	GlobusThreadMalloc(globus_l_thread_new_thread(),
			   Thread_Freelist,
			   globus_i_thread_t *, 
			   mem_req_size);
	
	for(i=0; i < GLOBUS_L_THREAD_GRAN-1; i++ )
	{
	    Thread_Freelist[i].next_free=&Thread_Freelist[i+1];
	}
	Thread_Freelist[GLOBUS_L_THREAD_GRAN-1].next_free=NULL;
    }
    new_thread = Thread_Freelist;

    if( Thread_Freelist != GLOBUS_NULL ) 
    {
	Thread_Freelist=Thread_Freelist->next_free;
    }
    
    new_thread->id = next_thread_id++;
    
    globus_mutex_unlock(&thread_mem_mutex);
    
    return new_thread;
} /* globus_l_thread_new_thread() */


/*
 * terminate_thread()
 */
static void
terminate_thread(globus_i_thread_t *thread,
		 void *status)
{
    int i;

#ifdef BUILD_PROFILE
    /*
    log_thread_destruction(thread->id);
    */
#endif /* BUILD_PROFILE */    

    /* Free up the thread storage */
    globus_mutex_lock(&thread_mem_mutex);
    thread->next_free = Thread_Freelist;
    Thread_Freelist = thread;
    globus_mutex_unlock(&thread_mem_mutex);

    /* Exit the thread */
    thr_exit(NULL);
} /* terminate_thread() */


/*
 * globus_thread_exit()
 */
void globus_thread_exit( void *status )
{
    globus_i_thread_t *victim;
    globus_l_thread_self(&victim);
    terminate_thread(victim, status);
} /* globus_thread_exit() */


/*
 * set_tsd()
 */
static void
set_tsd(globus_i_thread_t *thread)
{
    int rc=0;
    
    while((rc=thr_setspecific(
	globus_thread_all_global_vars.thread_t_pointer,
	(void *) thread ))==4) ;
    globus_i_thread_test_rc(rc,
			    _GCSL("GLOBUS_THREAD: set thread-local data failed\n"));
} /* set_tsd() */


/*
 * thread_starter()
 */
static void
*thread_starter(void *temparg)
{
    globus_i_thread_t *thread;
    int i;
    void *status;

    thread = (globus_i_thread_t *)temparg;
    
    set_tsd(thread);
    
#ifdef BUILD_PROFILE
    /*
    log_thread_creation(thread->id);
    */
#endif /* BUILD_PROFILE */    
    
    /* Call the user function */
    status = (*thread->user_func)(thread->user_arg);
    
    /* Terminate the thread */
    terminate_thread(thread, status);
    
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
    globus_i_thread_t *thread;
    thread_t thread_id;
    int rc=0;
    size_t stacksize = 0;
    
    thread = globus_l_thread_new_thread();
    
    /* Initialize the thread data that needs to be passed to the new thread */
    thread->user_func = func;
    thread->user_arg = user_arg;
    
    if (attr)
    {
	globus_threadattr_getstacksize(attr, &stacksize);
    }
    else
    {
	globus_threadattr_getstacksize(&globus_thread_all_global_vars.thread_attr,
				       &stacksize);
    }
    
    while((rc = thr_create( GLOBUS_NULL, stacksize, thread_starter,
			   thread, (globus_thread_all_global_vars.thread_flags),
			   &thread_id ))==4);
    globus_i_thread_test_rc( rc, _GCSL("GLOBUS_THREAD: create thread failed\n" ));
    
    if(user_thread)
    {
	*user_thread = thread_id;
    }

    return (0);
} /* globus_thread_create() */


/*
 * globus_preemptive_threads
 *
 * Return GLOBUS_TRUE (non-zero) if we are using preemptive threads.
 */
globus_bool_t
globus_thread_preemptive_threads(void)
{
    return (preemptive_threads);
} /* globus_preemptive_threads() */


/*
 * globus_threadattr_init()
 */
#undef globus_threadattr_init
int
globus_threadattr_init(globus_threadattr_t *attr)
{
    int rc;
    rc = globus_macro_threadattr_init(attr);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUS_THREAD: threadattr_init() failed\n"));
    return (rc);
}

/*
 * globus_threadattr_destroy()
 */
#undef globus_threadattr_destroy
int
globus_thread_destroy(globus_threadattr_t *attr)
{
    int rc;
    rc = globus_macro_threadattr_destroy(attr);
    globus_i_thread_test_rc(rc, _GCSL("GLOBUS_THREAD: threadattr_destroy() failed\n"));
    return (rc);
}

/*
 * globus_threadattr_setstacksize()
 */
#undef globus_threadattr_setstacksize
int
globus_threadattr_setstacksize(globus_threadattr_t *attr, 
			       size_t stacksize)
{
    int rc;
    rc = globus_macro_threadattr_setstacksize(attr, stacksize);
    globus_i_thread_test_rc(rc,
			    _GCSL("GLOBUS_THREAD: threadattr_setstacksize failed\n"));
    return (rc);
}

/*
 * globus_threadattr_getstacksize()
 */
#undef globus_threadattr_getstacksize
int
globus_threadattr_getstacksize(globus_threadattr_t *attr,
			       size_t *stacksize)
{
    int rc;
    rc = globus_macro_threadattr_getstacksize(attr, stacksize);
    globus_i_thread_test_rc(rc,
			    _GCSL("GLOBUS_THREAD: threadattr_getstacksize failed\n"));
    return (rc);
}

/*
 * globus_thread_key_create()
 */
#undef globus_thread_key_create
int
globus_thread_key_create(globus_thread_key_t *key,
			 globus_thread_key_destructor_func_t func)
{
   int rc=0;
   while((rc = globus_macro_thread_key_create(key,func )) == 4);
   globus_i_thread_test_rc( rc, _GCSL("GLOBUS_THREAD: keycreate failed\n" ));
    return(rc);
} /* globus_thrad_key_create() */

/*
 * globus_thread_key_delete()
 */
#undef globus_thread_key_delete
int
globus_thread_key_delete(globus_thread_key_t key)
{
   int rc=0;
   while((rc = globus_macro_thread_key_delete(key)) == 4);
   globus_i_thread_test_rc( rc, _GCSL("GLOBUS_THREAD: keydelete failed\n" ));
    return(rc);
} /* globus_thread_key_delete() */

/*
 * globus_thread_setspecific()
 */
#undef globus_thread_setspecific
int
globus_thread_setspecific(globus_thread_key_t key,
			  void *value)
{
    int rc=0;
    while((rc = globus_macro_thread_setspecific(key, value))==4) ;
    globus_i_thread_test_rc(rc, _GCSL("GLOBUS_THREAD: set specific failed\n"));
    return rc;
} /* globus_thread_setspecific() */

/*
 * globus_thread_getspecific()
 */
#undef globus_thread_getspecific
void *
globus_thread_getspecific(globus_thread_key_t key)
{
    void *value;
    
    value = globus_macro_thread_getspecific(key);
    return (value);
} /* globus_thread_getspecific() */


void *
globus_i_thread_getspecific(globus_thread_key_t key)
{
    int rc;
    void *value;

    while((rc = thr_getspecific(key, &value))==4) ;
    globus_i_thread_test_rc(rc, _GCSL("GLOBUS_THREAD: get specific failed\n"));
    return (value);
} /* globus_i_thread_getspecific() */


/*
 * globus_thread_self
 */
#undef globus_thread_self
globus_thread_t
globus_thread_self( void )
{
    return (globus_macro_thread_self());
}

/*
 * globus_thread_equal()
 */
#undef globus_thread_equal
int
globus_thread_equal(globus_thread_t t1,
		    globus_thread_t t2)
{
    return (globus_macro_thread_equal(t1, t2));
} /* globus_thread_equal() */

/*
 * globus_thread_yield
 */
#undef globus_thread_yield
void
globus_thread_yield( void )
{
    globus_macro_thread_yield();
}

/*
 * globus_i_am_only_thread()
 */
#undef globus_i_am_only_thread
globus_bool_t
globus_i_am_only_thread(void)
{
    return (globus_macro_i_am_only_thread());
}

#undef globus_mutex_init
int
globus_mutex_init(globus_mutex_t *mut,
		  globus_mutexattr_t *attr )
{
    int rc=0;
    while((rc =globus_macro_mutex_init(mut, attr))==4) ;
    globus_i_thread_test_rc(rc, _GCSL("GLOBUS_THREAD: allocate lock failed\n"));
    return rc;
}

/*
 *  globus_mutex_destroy()
 */
#undef globus_mutex_destroy
int
globus_mutex_destroy( globus_mutex_t *mut )
{
    int rc=0;
    while((rc = globus_macro_mutex_destroy(mut))==4) ;
    globus_i_thread_test_rc(rc, _GCSL("GLOBUS_THREAD: free lock failed\n"));
    return rc;
}

/*
 * globus_cond_init()
 */
#undef globus_cond_init
int
globus_cond_init(globus_cond_t *cv,
		 globus_condattr_t *attr )
{
    int rc=0;
    if((rc = globus_macro_cond_space_init(cv, attr))==4)
    {
        while((rc = globus_macro_cond_init(&(cv)->cond, GLOBUS_NULL))==4);
    }
    globus_i_thread_test_rc(
	rc,
	_GCSL("GLOBUS_THREAD: allocate condition variable failed\n"));
    return rc;
}

/*
 *  globus_cond_destroy()
 */
#undef globus_cond_destroy
int
globus_cond_destroy(globus_cond_t *cv)
{
    int rc=0;
    
    if ((rc = globus_macro_cond_space_destroy(cv))==4)
    {
        while((rc = globus_macro_cond_destroy(&(cv)->cond))==4);
    }
    globus_i_thread_test_rc(
	rc,
	_GCSL("GLOBUS_THREAD: free condition variable failed\n"));
    return rc;
}

/* 
 *  globus_mutex_lock()
 */
#undef globus_mutex_lock
int
globus_mutex_lock( globus_mutex_t *mut )
{
    int rc=0;
    while((rc = globus_macro_mutex_lock(mut))==4) ;
    globus_i_thread_test_rc(rc, _GCSL("GLOBUS_THREAD: mutex lock failed\n"));
    return rc;
}


/* 
 *  globus_mutex_trylock()
 */
#undef globus_mutex_trylock
int
globus_mutex_trylock(globus_mutex_t *mut)
{
    int rc;
    rc = globus_macro_mutex_trylock(mut);
    if (rc != EBUSY)
    {
        globus_i_thread_test_rc(rc,
				_GCSL("GLOBUS_THREAD: "
				"globus_mutex_trylock() failed\n" ));
    }
    return(rc);
} /* globus_mutex_trylock() */


/*
 *  globus_mutex_unlock()
 */
#undef globus_mutex_unlock
int
globus_mutex_unlock( globus_mutex_t *mut )
{
    int rc=0;
    while((rc = globus_macro_mutex_unlock(mut))==4) ;
    globus_i_thread_test_rc(rc, _GCSL("GLOBUS_THREAD: mutex unlock failed\n"));
    return rc;
}

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
 *  globus_cond_wait()
 */
#undef globus_cond_wait
int
globus_cond_wait(globus_cond_t *cv,
		 globus_mutex_t *mut )
{
    int rc=0;

    rc=globus_macro_cond_space_wait(cv, mut);
    globus_i_thread_test_rc(
	rc,
	_GCSL("GLOBUS_THREAD: condition variable wait failed\n"));
    return rc;
}

/*
 *  globus_cond_timedwait()
 */
#undef globus_cond_timedwait
int
globus_cond_timedwait(globus_cond_t *cv,
		      globus_mutex_t *mut,
		      globus_abstime_t *abstime)
{
    int rc=0;

    rc=globus_macro_cond_space_timedwait(cv, mut, abstime);
    if(rc != ETIMEDOUT
#   if defined(ETIME)
       && rc != ETIME
#   endif
       )
    globus_i_thread_test_rc(
	rc,
	_GCSL("GLOBUS_THREAD: condition variable wait failed\n"));
#   if defined(ETIME)
    if(rc == ETIME)
    {
	rc = ETIMEDOUT;
    }
#   endif 
    errno = rc;
    return rc;
}

/*
 *  globus_cond_signal()
 */
#undef globus_cond_signal
int
globus_cond_signal( globus_cond_t *cv )
{
    int rc=0;
    while((rc = globus_macro_cond_space_signal(cv))==4) ;
    globus_i_thread_test_rc(
	rc,
	_GCSL("GLOBUS_THREAD: condition variable signal failed\n"));
    return rc;
}

/*
 *  globus_cond_broadcast()
 */
#undef globus_cond_broadcast
int
globus_cond_broadcast( globus_cond_t *cv )
{
    int rc=0;
    while((rc = globus_macro_cond_space_broadcast(cv))==4) ;
    globus_i_thread_test_rc(
	rc,
	_GCSL("GLOBUS_THREAD: condition variable broadcast failed\n"));
    return rc;
}


/*
 * globus_i_thread_actual_thread_once()
 */
int globus_i_thread_actual_thread_once(globus_thread_once_t *once_control,
				       void (*init_routine)(void))
{
    int rc;
    globus_mutex_lock(&globus_l_thread_once_mutex);
    if (*once_control)
    {
	/* Someone beat us to it.  */
	rc = 0;
    }
    else
    {
	/* We're the first one here */
	(*init_routine)();
	*once_control = 1;
	rc = 0;
    }
    globus_mutex_unlock(&globus_l_thread_once_mutex);
    return (rc);
} /* globus_i_thread_actual_thread_once() */

#undef globus_thread_once
int
globus_thread_once(globus_thread_once_t *once_control,
		   void (*init_routine)(void))
{
    return (globus_i_thread_actual_thread_once(once_control, init_routine));
}

void
globus_thread_prefork(void)
{
/* Do nothing */
}

void
globus_thread_postfork(void)
{
/* Do nothing */
}
