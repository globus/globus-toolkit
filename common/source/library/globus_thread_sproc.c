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
Description:

  Implementation of Globus threads using SGI's sproc and shared memory
  interface

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
#include "config.h"
#include "globus_common.h"
#include "globus_thread_common.h"
#include "globus_i_thread.h"
#include "unistd.h"
#include <signal.h>
#include <sys/wait.h>
#include "version.h"


/******************************************************************************
			       Type definitions
******************************************************************************/
typedef struct globus_i_thread_s
{
    void **					key_table_values;

    /* semaphore for globus_cond_wait */
    usema_t *					sema;

    /* poll-type semaphore for timed waits */
    usema_t *					timed_sema;

    /* These are used only during thread startup */
    globus_thread_func_t			user_func;
    void *					user_arg;
    
    /* This is only used when this structure is on the free list */
    struct globus_i_thread_s   *		next_free;
}
globus_i_thread_t;

/******************************************************************************
		Define module specific variables and constants
******************************************************************************/

/*
 * Counter to ensure that we don't exceed the maximum number of simultaneous
 * threads
 */

#define GLOBUS_L_THREAD_MAX_PER_PROC		32
/* #define GLOBUS_THREAD_SPROC_DEBUG		1 */


static globus_mutex_t				globus_l_thread_cnt_mutex;
static int					globus_l_thread_cnt;
static int					globus_l_thread_cnt_max;

/*
 *   This is for the hashtable of globus_i_thread_t structs
 */
static const int GLOBUS_L_THREAD_TABLE_SIZE = 53;
static globus_mutex_t			globus_l_thread_hashtable_mutex;
static globus_hashtable_t               globus_l_thread_hashtable;

#define GLOBUS_I_THREAD_SIZE() \
    (sizeof(globus_i_thread_t) + (key_table_size * sizeof(void *)))


#ifndef GLOBUS_L_THREAD_KEY_TABLE_SIZE
#define GLOBUS_L_THREAD_KEY_TABLE_SIZE 16
#endif

static globus_thread_key_destructor_func_t *key_table_destructor_funcs;

/*
 * Thread specific data key maintenance stuff
 */
static int					key_table_size;
static int					next_key;
static globus_mutex_t				key_mutex;
static globus_bool_t
    globus_l_thread_already_initialized = GLOBUS_FALSE;

/*
 * Free list of globus_i_thread_t structures
 */
static globus_i_thread_t *			free_list;
static globus_mutex_t				free_list_mutex;


/*
 * For globus_thread_once()
 */
static globus_mutex_t				thread_once_mutex;


static globus_bool_t
    preemptive_threads = GLOBUS_TRUE;

usptr_t *
    globus_i_thread_arena = NULL;

/*
 * For SIGCHLD handler
 */
static struct sigaction 			act;

/******************************************************************************
			  Module specific prototypes
******************************************************************************/

static void
thread_startup(
    void *					arg,
    size_t					something);

static void
(*idle_func_save)();

static void
globus_i_sigchld_handler(int);


/*
 * globus_i_thread_pre_activate()
 *
 */
int
globus_i_thread_pre_activate( void )
{
    globus_i_thread_t *thread;
    int i;
    int rc;
    int max_sprocs;
    int max_us_mem;
    void * us_memory_base;
    char *envpointer;

    /*
     *  Set up some things from environment variables.
     *  Three environment variables are looked at:
     *  GLOBUS_THREAD_SPROC_MAX_SPROCS (default: 8 * nprocs)
     *  GLOBUS_THREAD_SPROC_MAX_US_MEMORY (default: 8K * nprocs)
     *  GLOBUS_THREAD_SPROC_US_MEMORY_BASE (default: system defined)
     *  
     */ 

     envpointer=globus_module_getenv("GLOBUS_THREAD_SPROC_MAX_SPROCS");

     if (envpointer!=GLOBUS_NULL)
     {
         sscanf(envpointer,"%u",&max_sprocs);
     }
     else
     {
	 max_sprocs=8*sysconf(_SC_NPROC_ONLN);
     }
     envpointer=globus_module_getenv("GLOBUS_THREAD_SPROC_MAX_US_MEMORY");

     if (envpointer!=GLOBUS_NULL)
     {
	 sscanf(envpointer,"%u",&max_us_mem);
     }
     else
     {
	 max_us_mem=8192*sysconf(_SC_NPROC_ONLN);
     }
     envpointer=globus_module_getenv("GLOBUS_THREAD_SPROC_US_MEMORY_BASE");

     if (envpointer!=GLOBUS_NULL)
     {
	sscanf(envpointer,"%x",&us_memory_base);
     }
     else
     {
        us_memory_base=0;
     }

    /*
     * SIGCHLD stuff
     */
     act.sa_handler = globus_i_sigchld_handler;
     sigemptyset(&act.sa_mask);
     sigaddset(&act.sa_mask, SIGCHLD);
     act.sa_flags = 0;
     sigaction(SIGCHLD, &act, NULL);

    /*
     * This arena will only be accessible by the sprocs created within this
     * thread package.
     */
    usconfig(CONF_ARENATYPE, US_SHAREDONLY);

    /*
     * Set the attach point for the arena if it was specified in env variable
     */
    if (us_memory_base!=0)
    {
        usconfig(CONF_ATTACHADDR, us_memory_base);
    }

    /*
     * Set the maximum number of sprocs which may simultaneously hold a
     * reference to the arena.  If the computed valued exceeds the documented
     * maximum of 10000, then set it to 10000.
     */
    globus_l_thread_cnt_max = max_sprocs;

    if (globus_l_thread_cnt_max > 10000)
    {
	globus_l_thread_cnt_max = 10000;
    }
    usconfig(CONF_INITUSERS, globus_l_thread_cnt_max);

    usconfig(CONF_INITSIZE, max_us_mem);
    
    /*
     * Turn of logging features; no point in wasting time when we can't get the
     * information anyway...
     */
    usconfig(CONF_LOCKTYPE, US_NODEBUG);

    /*
     * Initialize a shared memory arena to be used internally for locks and
     * semaphores
     */
    globus_i_thread_arena = usinit("/dev/zero");
    globus_assert(globus_i_thread_arena != GLOBUS_NULL);
    
    /*
     * Turn of history features too
     */
    usconfig(CONF_HISTOFF, globus_i_thread_arena);

    /*
     * Initialize the libc mutex
     */
    rc = globus_mutex_init(&globus_libc_mutex, (globus_mutexattr_t *) NULL);
    globus_assert(rc == 0);

    /*
     * Initialize count of active threads
     */
    globus_l_thread_cnt = 1;
    rc = globus_mutex_init(&globus_l_thread_cnt_mutex,
			   (globus_mutexattr_t *) NULL);
    globus_assert (rc == 0);
    
    /* Initialize thread specific keys */
    key_table_size = GLOBUS_L_THREAD_KEY_TABLE_SIZE;
    next_key = 0;
    globus_mutex_init(&key_mutex, (globus_mutexattr_t *) NULL);
    
    /* Initialize the free list */
    free_list = (globus_i_thread_t *) NULL;
    rc = globus_mutex_init(&free_list_mutex, (globus_mutexattr_t *) NULL);
    globus_assert (rc == 0);

    /* Initialize the thread_once_mutex */
    rc = globus_mutex_init(&thread_once_mutex, (globus_mutexattr_t *) NULL);
    globus_assert (rc == 0);

    /* Initialize the key_table_destructor_funcs */
    GlobusThreadMalloc(
	globus_l_thread_activate(),
	key_table_destructor_funcs,
	globus_thread_key_destructor_func_t *,
	(key_table_size*sizeof(globus_thread_key_destructor_func_t)));
    
    for (i = 0; i < key_table_size; i++)
    {
	key_table_destructor_funcs[i] = NULL;
    }
    
    /* Initialize the globus_i_thread_t structure for this initial thread */
    GlobusThreadMalloc(globus_l_thread_activate(),
		       thread,
		       globus_i_thread_t *,
		       GLOBUS_I_THREAD_SIZE() );
    thread->key_table_values
	= (void **) (((char *) thread) + sizeof(globus_i_thread_t));
    for (i = 0; i < key_table_size; i++)
    {
	thread->key_table_values[i] = (void *) NULL;
    }

    thread->user_func = GLOBUS_NULL;
    thread->user_arg = GLOBUS_NULL;
    
    thread->sema = usnewsema(globus_i_thread_arena, 0);
    thread->timed_sema = usnewpollsema(globus_i_thread_arena, 0);

    globus_assert(thread->sema != GLOBUS_NULL);
    globus_assert(thread->timed_sema != GLOBUS_NULL);

    /*Insert thread pointer into the hashtable by pid*/
    globus_hashtable_init(&globus_l_thread_hashtable,
                          GLOBUS_L_THREAD_TABLE_SIZE,
                          globus_hashtable_int_hash,
                          globus_hashtable_int_keyeq);

    rc = globus_mutex_init(&globus_l_thread_hashtable_mutex,
			   (globus_mutexattr_t *) GLOBUS_NULL);
    globus_assert (rc == 0);

    globus_mutex_lock(&globus_l_thread_hashtable_mutex);
    {
	globus_hashtable_insert(
            &globus_l_thread_hashtable,
            (void *) getpid(),
            thread);
    }
    globus_mutex_unlock(&globus_l_thread_hashtable_mutex);

    return globus_i_thread_ignore_sigpipe();
}
/* globus_i_thread_pre_activate() */


/*
 * globus_l_thread_activate()
 */
int
globus_l_thread_activate()
{
    globus_module_activate(GLOBUS_THREAD_COMMON_MODULE);
    if(globus_l_thread_already_initialized)
    {
	return GLOBUS_SUCCESS;
    }
    globus_l_thread_already_initialized = GLOBUS_TRUE;

    return GLOBUS_SUCCESS;
} /* globus_l_thread_activate() */


/*
 * globus_l_thread_deactivate()
 */
int
globus_l_thread_deactivate(void)
{
    int rc;
    rc = globus_module_deactivate(GLOBUS_THREAD_COMMON_MODULE);
    return rc;
} /* globus_l_thread_deactivate() */

/*
 * terminate_thread()   FIXME shouldn't this be globus_i_terminate_thread()?
 *
 * Put the thread's data structure onto the free_list, and exit
 * from the thread.
 */
static void
terminate_thread(globus_i_thread_t *thread, void *status)
{
    int i;
    globus_thread_key_destructor_func_t func;
    void *value;
    
#   if defined(GLOBUS_THREAD_SPROC_DEBUG)
    {
	thread_print("freeing sema 0x%08x\n",
	       (unsigned) thread->sema);
    }
#   endif
    usfreesema(thread->sema, globus_i_thread_arena);
    usfreepollsema(thread->timed_sema, globus_i_thread_arena);
    
    /* Call the thread specific data destructors */
    for (i = 0; i < key_table_size; i++)
    {
	func = key_table_destructor_funcs[i];
	value = thread->key_table_values[i];
	if (func && value)
	{
	    (*func)(value);
	}
    }

#ifdef BUILD_PROFILE
    /*
    log_thread_destruction(thread->id);
    */
#endif /* BUILD_PROFILE */    

    /* Free up the thread storage */
    globus_mutex_lock(&free_list_mutex);
    thread->next_free = free_list;
    free_list = thread;
    globus_mutex_unlock(&free_list_mutex);

    globus_mutex_lock(&globus_l_thread_cnt_mutex);
    {
	globus_l_thread_cnt--;
    }
    globus_mutex_unlock(&globus_l_thread_cnt_mutex);

    _exit(0);
} /* terminate_thread() */


/*
 * thread_startup()
 *
 * This is the entry point for a new sproc that is created
 * by globus_thread_create().  It does some bookkeeping and then
 * calls the user function.  If the user function returns, then
 * it terminates the thread.
 */
static void 
thread_startup(void * arg,size_t something)
{
    globus_i_thread_t *thread = (globus_i_thread_t *) arg;
    void *status;

    /*
     * Add this new sproc to the mutex/semaphore arena
     */
    usadd(globus_i_thread_arena);
    
#ifdef BUILD_PROFILE
    /*
    log_thread_creation(thread->id);
    */
#endif /* BUILD_PROFILE */    
    
    /*
     * Wait for parent to inform us that it is ok to proceed
     */
    uspsema( thread->sema );

    /* Call the user function */
    status = (*thread->user_func)(thread->user_arg);

    /* Terminate the thread */
    terminate_thread(thread, status);
}
/* thread_startup() */


/*
 * get_new_thread()
 *
 * Return a globus_i_thread_t for a new thread.
 */
static globus_i_thread_t *
get_new_thread(void)
{
    globus_i_thread_t *thread;
    
    globus_mutex_lock(&free_list_mutex);
    if (free_list != (globus_i_thread_t *) NULL)
    {
	thread = free_list;
	free_list = free_list->next_free;
    }
    else
    {
	GlobusThreadMalloc(globus_thread_create(),
			   thread,
			   globus_i_thread_t *,
			   GLOBUS_I_THREAD_SIZE() );
    }
    globus_mutex_unlock(&free_list_mutex);

    return (thread);
} /* get_new_thread() */


/*
 * globus_thread_create()
 */
int
globus_thread_create(globus_thread_t *user_thread,
		     globus_threadattr_t *attr,
		     globus_thread_func_t func,
		     void *user_arg)
{
    int						i;
    int						stacksize;
    globus_i_thread_t *				thread;
    pid_t					sproc_id;
    int						num_threads;

    thread = get_new_thread();

    globus_mutex_lock(&globus_l_thread_cnt_mutex);
    {
	num_threads = ++globus_l_thread_cnt;
    }
    globus_mutex_unlock(&globus_l_thread_cnt_mutex);

    if (num_threads > globus_l_thread_cnt_max)
    {
	return -2;
    }
    
    /* Initialize the thread data */
    thread->key_table_values
	= (void **) (((char *) thread) + sizeof(globus_i_thread_t));
    
    /* Initialize the thread specific key table */
    for (i = 0; i < key_table_size; i++)
    {
	thread->key_table_values[i] = (void *) NULL;
    }

    /* Initialize the thread data that needs to be passed to the new thread */
    thread->user_func = func;
    thread->user_arg = user_arg;

    thread->sema = usnewsema(globus_i_thread_arena, 0);
    thread->timed_sema = usnewpollsema(globus_i_thread_arena, 0);
    if (thread->sema == GLOBUS_NULL)
    {
	return -1;
    }

    if (attr != NULL && attr->stacksize > 0)
    {
	stacksize = attr->stacksize;
    }
    else
    {
	stacksize = 16384;
    }
    
    sproc_id =
	sprocsp(
	    thread_startup,
	    PR_SALL,
	    thread,
	    NULL,
	    (size_t) stacksize);

    globus_mutex_lock(&globus_l_thread_hashtable_mutex);
    {
	/* Setup pointers so we can find the thread data again */
	globus_hashtable_insert(
            &globus_l_thread_hashtable,
            (void *) sproc_id,
            thread);
    }
    globus_mutex_unlock(&globus_l_thread_hashtable_mutex);

    /*
     * Inform the child process that it is ok to proceed
     */
    usvsema(thread->sema);

    if (user_thread)
    {
	*user_thread = (globus_thread_t) thread;
    }
    
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
 * globus_thread_exit()
 */
void
globus_thread_exit(void *status)
{
    globus_i_thread_t *thread;
    thread = (globus_i_thread_t *) globus_thread_self();
    terminate_thread(thread, status);
} /* globus_thread_exit() */


/*
 * globus_thread_key_create()
 */
int
globus_thread_key_create(globus_thread_key_t *key,
			 globus_thread_key_destructor_func_t func)
{
    int rc;
    
    globus_mutex_lock(&key_mutex);
    if (next_key >= key_table_size)
    {
	/* Attempt to allocate a key when the key name space is exhausted */
	rc = EAGAIN;
    }
    else
    {
	*key = next_key++;
	key_table_destructor_funcs[*key] = func;
	rc = 0;
    }
    globus_mutex_unlock(&key_mutex);
    return(rc);
} /* globus_thread_key_create() */


/*
 * globus_thread_setspecific()
 */
int
globus_thread_setspecific(globus_thread_key_t key,
			  void *value)
{
    globus_i_thread_t *thread;

    if(key < 0 || key >= key_table_size)
    {
	return GLOBUS_FAILURE;
    }

    thread = (globus_i_thread_t *) globus_thread_self();
    thread->key_table_values[key] = value;
    return 0;
} /* globus_thread_setspecific() */


/*
 * globus_thread_getspecific()
 */
void *
globus_thread_getspecific(globus_thread_key_t key)
{
    void *value;
    globus_i_thread_t *thread;
    
    if(key < 0 || key >= key_table_size)
    {
	return GLOBUS_NULL;
    }

    thread = (globus_i_thread_t *) globus_thread_self();
    value = thread->key_table_values[key];
    return (value);
} /* globus_thread_getspecific() */


/*
 * globus_i_thread_actual_thread_once()
 */
int
globus_i_thread_actual_thread_once(globus_thread_once_t *once_control,
		       void (*init_routine)(void))
{
    int rc=-1;
    globus_mutex_lock(&thread_once_mutex);
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
    globus_mutex_unlock(&thread_once_mutex);
    return (rc);
} /* globus_i_thread_actual_thread_once() */



/*
 * Now provide the function versions of each of the macros
 * for when USE_MACROS is not defined.
 */
#undef globus_thread_yield
void
globus_thread_yield(void)
{
    globus_macro_thread_yield();
} /* globus_thread_yield() */

#undef globus_thread_self
globus_thread_t
globus_thread_self(void)
{
    globus_thread_t				thread;
    
    globus_mutex_lock(&globus_l_thread_hashtable_mutex);
    {
	thread = globus_hashtable_lookup(&globus_l_thread_hashtable,
					 (void *) getpid());
    }
    globus_mutex_unlock(&globus_l_thread_hashtable_mutex);

    return (thread);
}

#undef globus_thread_equal
int
globus_thread_equal(globus_thread_t t1,
			globus_thread_t t2)
{
    return (globus_macro_thread_equal(t1,t2));
}
		       
#undef globus_thread_once
int
globus_thread_once(globus_thread_once_t *once_control,
		       void (*init_routine)(void))
{
    return (globus_macro_thread_once(once_control, init_routine));
}

#undef globus_i_am_only_thread
globus_bool_t
globus_i_am_only_thread(void)
{
    /*
     * return FALSE always because we never know what the number of
     * running threads is, so we can never assume this is the only
     * thread.
     */
    return GLOBUS_FALSE;
}


#undef globus_mutex_init
int
globus_mutex_init(globus_mutex_t *mutex, globus_mutexattr_t *attr)
{
    int rc;
    
    rc = globus_macro_mutex_init(mutex, attr);
    
    return rc;
}
#undef globus_mutex_destroy
int
globus_mutex_destroy(globus_mutex_t *mutex)
{
    int rc;
    
    rc = globus_macro_mutex_destroy(mutex);
    
    return rc;
}

#undef globus_mutex_lock
int
globus_mutex_lock(globus_mutex_t *mutex)
{
    int rc;
    
    rc = globus_macro_mutex_lock(mutex);

    return rc;
}

#undef globus_mutex_trylock
int
globus_mutex_trylock(globus_mutex_t *mutex)
{
    int rc;
    
    rc = globus_macro_mutex_trylock(mutex);
    
    return rc;
}

#undef globus_mutex_unlock
int
globus_mutex_unlock(globus_mutex_t *mutex)
{
    int rc;
    
    rc = globus_macro_mutex_unlock(mutex);
    
    return rc;
}


/*
 * globus_condattr_setspace()
 */
#undef globus_condattr_setspace
int globus_condattr_setspace(
    globus_condattr_t *                 attr,
    int                                 space)
{
    return globus_callback_space_reference(space)
        ? 1
        : globus_callback_space_destroy(*attr),
          *attr = space, 0;
}

/*
 * globus_condattr_getspace()
 */
#undef globus_condattr_getspace
int globus_condattr_getspace(
    globus_condattr_t *                 attr,
    int *                               space)
{
    *space = *attr;
    return (0);
}

/*
 * globus_condattr_init()
 */
#undef globus_condattr_init
int globus_condattr_init(globus_condattr_t *attr)
{
    globus_callback_space_reference(GLOBUS_CALLBACK_GLOBAL_SPACE);
    *attr = GLOBUS_CALLBACK_GLOBAL_SPACE;
    
    return 0;
}

/*
 * globus_condattr_destroy()
 */
#undef globus_condattr_destroy
int globus_condattr_destroy(globus_condattr_t *attr)
{
    globus_callback_space_destroy(*attr);
    return (0);
}

#undef globus_cond_init
int
globus_cond_init(globus_cond_t *cond, globus_condattr_t *attr)
{
    int						rc = 0;

    globus_mutex_init(&cond->mutex, (globus_mutexattr_t *) GLOBUS_NULL);
    globus_fifo_init(&cond->queue);
    
    cond->space = attr ? *attr : GLOBUS_CALLBACK_GLOBAL_SPACE;
    globus_callback_space_reference(cond->space);
    
    cond->poll_space = globus_callback_space_is_single(cond->space);
    
    return (rc);
}

#undef globus_cond_destroy
int
globus_cond_destroy(globus_cond_t *cond)
{
    int						rc = 0;

    globus_mutex_destroy(&cond->mutex);
    globus_fifo_destroy(&cond->queue);
    globus_callback_space_destroy(cond->space);
    
    return (rc);
}

#undef globus_cond_signal
int
globus_cond_signal(globus_cond_t *cond)
{
    int						rc = 0;

    usema_t *					sema;
    
    if(cond->poll_space)
    {
        globus_callback_signal_poll();
        
        return 0;
    }
    
    globus_mutex_lock(&cond->mutex);
    {
	sema = globus_fifo_dequeue(&cond->queue);
    }
    globus_mutex_unlock(&cond->mutex);

    if (sema != GLOBUS_NULL)
    {
#	if defined(GLOBUS_THREAD_SPROC_DEBUG)
	{
	    thread_print("cond_signal: waking up 0x%08x\n",
		   (unsigned) sema);
	}
#	endif

	usvsema(sema);
    }
#   if defined(GLOBUS_THREAD_SPROC_DEBUG)
    else
    {
	    thread_print("cond_signal: no one to wake up\n");
    }
#   endif

    return (rc);
}

#undef globus_cond_broadcast
int
globus_cond_broadcast(globus_cond_t *cond)
{
    int						rc = 0;

    globus_fifo_t				queue;
    usema_t *					sema;
    
    if(cond->poll_space)
    {
        globus_callback_signal_poll();
        
        return 0;
    }
    
    globus_mutex_lock(&cond->mutex);
    {
	globus_fifo_move(&queue, &cond->queue);
    }
    globus_mutex_unlock(&cond->mutex);

    while(!globus_fifo_empty(&queue))
    {
	sema = globus_fifo_dequeue(&queue);
	
#	if defined(GLOBUS_THREAD_SPROC_DEBUG)
	{
	    thread_print("waking up 0x%08x\n",
		   (unsigned) sema);
	}
#	endif
	
	usvsema(sema);
    }	
    
    return (rc);
}

#undef globus_cond_wait
int
globus_cond_wait(globus_cond_t *cond,
		 globus_mutex_t *mutex)
{
    int						rc = 0;

    usema_t *					sema;
    globus_i_thread_t *				thread;

    /* added by JB */
    globus_thread_blocking_space_will_block(cond->space);

    if(!cond->poll_space)
    {
    thread = (globus_i_thread_t *) globus_thread_self();
    sema = thread->sema;

    globus_mutex_lock(&cond->mutex);
    {
	globus_fifo_enqueue(&cond->queue, sema);
    }
    globus_mutex_unlock(&cond->mutex);

    globus_mutex_unlock(mutex);
    {
#	if defined(GLOBUS_THREAD_SPROC_DEBUG)
	{
	    thread_print("sleeping on 0x%08x\n",
		   (unsigned) sema);
	}
#	endif

	
	uspsema ( sema );
	
#	if defined(GLOBUS_THREAD_SPROC_DEBUG)
	{
	    thread_print("cond wait: woken up using 0x%08x\n",
		   (unsigned) sema);
	}
#	endif
    }
    globus_mutex_lock(mutex);
    }
    else
    {
        globus_mutex_unlock(mutex);
        globus_callback_space_poll(&globus_i_abstime_infinity, cond->space);
        globus_mutex_lock(mutex);
    }
    
    return (rc);
}

#undef globus_cond_timedwait
int 
globus_cond_timedwait(globus_cond_t *cond, 
		      globus_mutex_t *mutex,
		      globus_abstime_t *abstime)
{
    int						rc = 0;
    usema_t *					sema;
    globus_i_thread_t *				thread;
    int						save_errno = 0;
    int						fd;
    
    globus_thread_blocking_space_will_block(cond->space);
    
    if(!cond->poll_space)
    {
    thread = (globus_i_thread_t *) globus_thread_self();

    sema = thread->timed_sema;

    fd = usopenpollsema ( sema, S_IRWXU);

    globus_assert(fd >= 0);
	
    globus_mutex_lock(&cond->mutex);
    {
        /*
         * Insert our semaphore in the queue to be woken a cond_signal
         * or cond_broadcast
         */
	globus_fifo_enqueue(&cond->queue, sema);
    }
    globus_mutex_unlock(&cond->mutex);

    globus_mutex_unlock(mutex);
    {
        /* If we yield here, we may avoid blocking */
        globus_thread_yield();

	/* returns 1 if semaphore is acquired */
	rc = uspsema(sema);
	globus_assert(rc != -1);
	
#	if defined(GLOBUS_THREAD_SPROC_DEBUG)
	{
	    thread_print("timedwait: %s 0x%08x\n",
		   rc == 1 ? "acquired semaphore"
		           : "didn't acquire semaphore",
		   (unsigned) sema);
	}
#	endif

	/*
	 * Failed to acquire semaphore, to the timed select
	 * to simulate a timed wait.
	 */
	if(rc == 0)
	{
	    fd_set			semaphore_set;
	    struct timeval		timeout;
	    
	    errno = 0;
	    do
	    {
	       /*
		* we need to recompute the timeout each time through
		* this loop, to preserve the absolute time in the waiting.
		* So much for the nsec precision of a timedwait.
		*/
	        gettimeofday(&timeout, GLOBUS_NULL);
	    
	        timeout.tv_sec = abstime->tv_sec - timeout.tv_sec;
	        if(timeout.tv_sec < 0)
		{
		    timeout.tv_sec = 0;
		}
	      
	        timeout.tv_usec = (abstime->tv_nsec/1000) - timeout.tv_usec;
	        if(timeout.tv_usec < 0)
		{
		    timeout.tv_usec = 0;
		}
		
		FD_ZERO(&semaphore_set);
		FD_SET(fd, &semaphore_set); 

		errno = 0;
		globus_thread_yield();
	        rc = select(fd + 1, 
			    &semaphore_set,
			    GLOBUS_NULL,
			    GLOBUS_NULL,
			    &timeout);
		save_errno = errno;
#	        if defined(GLOBUS_THREAD_SPROC_DEBUG)
	        {
	            thread_print("timedwait: select on 0x%08x returned %d:%d (%s)\n",
		           (unsigned) sema,
			   rc,
			   save_errno,
			   strerror(save_errno));
	        }
#	        endif
	    }  while(rc < 0 && errno == EINTR);

            /* We woke up from the select without getting a signal */
	    if(rc == 0)
	    {
                globus_bool_t		signalled = GLOBUS_FALSE;

#	        if defined(GLOBUS_THREAD_SPROC_DEBUG)
	        {
	            thread_print("timedwait: woke up without a signal on 0x%08x\n",
		           (unsigned) sema);
	        }
#	        endif

	        /* remove ourselves from the waiting list. */
	        globus_mutex_lock(&cond->mutex);
		{
		    if(globus_fifo_remove(&cond->queue, sema) != sema)
		    {
		        /*
			 * We've been signalled after we woke up, but we
			 * still need to select to acquire the semaphore
			 */
		        signalled = GLOBUS_TRUE;
#	                if defined(GLOBUS_THREAD_SPROC_DEBUG)
	                {
	                    thread_print("timedwait: we were already removed from the wait list (0x%08x)\n",
		                   (unsigned) sema);
	                }
#	                endif
		    }
		}
		globus_mutex_unlock(&cond->mutex);

		if(!signalled)
		{
		    /*
		     * We can not "P" the semaphore again until we've
		     * been signalled, so we signal ourselves
		     */
#	            if defined(GLOBUS_THREAD_SPROC_DEBUG)
	            {
	                thread_print("timedwait: signalling myself (0x%08x)\n",
		            (unsigned) sema);
	            }
#	            endif
		    rc = usvsema(sema);
		    globus_assert(rc >= 0);
		}
		
		do
		{
		    FD_ZERO(&semaphore_set);
		    FD_SET(fd, &semaphore_set); 

		    /*
		     * we've been signalled, one way or another,
		     * so we should be able to acquire the semaphore
		     * easily now
		     */
		    errno=0;
		    globus_thread_yield();
		    rc = select(fd + 1, 
				&semaphore_set,
				GLOBUS_NULL,
				GLOBUS_NULL,
				GLOBUS_NULL);
		    save_errno = errno;
#	            if defined(GLOBUS_THREAD_SPROC_DEBUG)
	            {
	                thread_print("timedwait: select on 0x%08x returned %d:%d (%s)\n",
		               (unsigned) sema,
			       rc,
			       save_errno,
			       sys_errlist[save_errno]);
	            }
#	            endif
		} while(rc < 1 && save_errno == EINTR);

		globus_assert(rc == 1);

		save_errno = ETIMEDOUT;
	    }
	    else
	    {
	        globus_assert(rc == 1);
	    }
	}
	else
	{
	    /* We have the semaphore */
	    save_errno = 0;
	}

#	if defined(GLOBUS_THREAD_SPROC_DEBUG)
	{
	    thread_print("timedwait: condition %s 0x%08x\n",
		   save_errno == ETIMEDOUT ? "timed out"
		           : "was signalled",
		   (unsigned) sema);
	}
#	endif
	
	usclosepollsema ( sema );

    }
    globus_mutex_lock(mutex);
    errno = save_errno;
    }
    else
    {
        globus_mutex_unlock(mutex);
        globus_callback_space_poll(abstime, cond->space);
        globus_mutex_lock(mutex);
        
        save_errno = (time(GLOBUS_NULL) >= abstime->tv_sec) ? ETIMEDOUT : 0;
    }
    
    
    return save_errno;
} /* globus_cond_timedwait() */

void
globus_thread_prefork(void)
{
/* Do Nothing */
}

void
globus_thread_postfork(void)
{
/* Do Nothing */
}

globus_module_descriptor_t globus_i_thread_module =
{
    "globus_thread_sproc",
    globus_l_thread_activate,
    globus_l_thread_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static void globus_i_sigchld_handler (int sig)
{
    pid_t pid;
    int status;

    pid = waitpid(0, &status, WNOHANG);
    while (pid > 0) 
    {
      pid = waitpid(0, &status, WNOHANG);
    }
}


