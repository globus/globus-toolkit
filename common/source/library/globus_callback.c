/******************************************************************************
globus_callback.c

Description:

  A general polling infrastructure

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
#include "globus_thread_pool.h"
#include <assert.h>
#include "version.h"

/******************************************************************************
		             Type definitions
******************************************************************************/
#define GLOBUS_L_CALLBACK_HASH_TABLE_SIZE         32768
#define GLOBUS_L_CALLBACK_INIT_STRUCT_COUNT       256
/******************************************************************************
                           local data structures
******************************************************************************/
typedef struct  globus_l_callback_monitor_s
{
    globus_mutex_t           mutex;
    globus_cond_t            cond;
    globus_bool_t            done;
} globus_l_callback_monitor_t;

typedef struct globus_l_callback_info_s
{
    globus_callback_handle_t                       handle;
    globus_thread_t                                handler_thread_id;

    globus_callback_func_t                         callback_func;
    void *                                         callback_args;

    globus_wakeup_func_t                           wakeup_func;
    void *                                         wakeup_args;

    globus_abstime_t                               start_time;
    globus_reltime_t                               period;

    globus_bool_t                                  running;
    int                                            call_depth;
    
    globus_unregister_callback_func_t              unregister_callback;
    void *                                         unreg_args;
} globus_l_callback_info_t;

typedef struct globus_l_callback_handle_entry_s
{
    int                                        ref;
    globus_callback_handle_t                   handle;
    globus_l_callback_info_t *                 callback_info;
}  globus_l_callback_handle_entry_t;

typedef struct globus_l_thread_restart_info_s
{
    globus_bool_t                              restarted;
    int                                        callback_index;
    globus_abstime_t                           start_time;
    globus_abstime_t                           end_time;
    globus_l_callback_info_t *                 callback_info;
} globus_l_thread_restart_info_t;

/*****************************************************************************
                           local function prototypes
******************************************************************************/
static int
globus_l_callback_activate(void);

static int
globus_l_callback_deactivate(void);

static void
globus_l_callback_requeue( 
    globus_l_callback_info_t *                 info);

static void
globus_l_callback_free(
    globus_l_callback_info_t *                 info);

int
globus_l_callback_register(
    globus_callback_handle_t *                 callback_handle,
    globus_reltime_t *                         start_time,
    globus_reltime_t *                         period,
    globus_callback_func_t                     callback_func,
    void *                                     callback_user_args,
    globus_wakeup_func_t                       wakeup_func,
    void *                                     wakeup_user_args);

/*
 *  if threaded 
 */
#if  !defined(BUILD_LITE)

static void *
globus_l_callback_timeq_run(
    void *                                     user_args);

static void *
globus_l_callback_func_run( 
    void *                                     user_args);

static void
globus_l_thread_count_dec();

#else

int                                            globus_l_callback_index;
globus_l_thread_restart_info_t                 global_l_callback_nonthread_restart;

#endif /* end if threaded */

static void *
globus_l_callback_func_restart(
    globus_thread_callback_index_t             blocking_func_ndx,
    void *                                     user_args);

static globus_bool_t
globus_l_callback_queue_get_next(
    globus_l_callback_info_t **                in_info,
    globus_abstime_t *                         next_time);

/******************************************************************************
		       Define module specific variables
******************************************************************************/
static globus_timeq_t                          globus_l_callback_q;
static globus_mutex_t                          globus_l_q_lock;


static globus_bool_t                           globus_l_callback_module_is_active = GLOBUS_FALSE;
static globus_handle_table_t                   globus_l_callback_handle_table;
static globus_thread_key_t                     globus_l_restart_thread_key;

#if  !defined(BUILD_LITE)

static globus_list_t *                         globus_l_wakeup_list;
static volatile int                            globus_l_thread_count;
static globus_mutex_t                          globus_l_thread_create_lock;
static globus_cond_t                           globus_l_thread_cond;
static volatile globus_bool_t                  globus_l_time_q_thread_running;
static globus_cond_t                           globus_l_callback_run_cond;

static volatile globus_bool_t                  globus_l_callback_shutting_down;

#endif

/*#define _GLOBUS_CALLBACK_USE_THREAD_POOL 1
*/#define _CALLBACK_USE_INTERNAL_MEM 1

#ifdef  _CALLBACK_USE_INTERNAL_MEM
    static globus_memory_t                              globus_l_memory_callback_info;
    static globus_memory_t                              globus_l_memory_restart_info;

#   define MALLOC_CALLBACK_T() \
        ((globus_l_callback_info_t *) globus_memory_pop_node(&globus_l_memory_callback_info))
#   define MALLOC_RESTART_T() \
        ((globus_l_thread_restart_info_t *)globus_memory_pop_node(&globus_l_memory_restart_info))
#   define FREE_CALLBACK_T(ptr) \
        (globus_memory_push_node( \
				  &globus_l_memory_callback_info, \
			          (globus_byte_t *)ptr))
#   define FREE_RESTART_T(ptr) \
        (globus_memory_push_node(&globus_l_memory_restart_info, \
			          (globus_byte_t *)ptr))
#else
#   define MALLOC_CALLBACK_T() \
        ((globus_l_callback_info_t *) globus_malloc(sizeof(globus_l_callback_info_t)))
#   define MALLOC_RESTART_T() \
        ((globus_l_thread_restart_info_t *) globus_malloc(sizeof(globus_l_thread_restart_info_t)))
#   define FREE_CALLBACK_T(ptr) \
        (globus_free(ptr))
#   define FREE_RESTART_T(ptr) \
        (globus_free(ptr))
#endif

/******************************************************************************
			   Module Definition
******************************************************************************/

globus_module_descriptor_t		globus_i_callback_module =
{
    "globus_callback",
    globus_l_callback_activate,
    globus_l_callback_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


/******************************************************************************
		       globus_callback function definitions
******************************************************************************/

/*
 * globus_callback_activate()
 */
static int
globus_l_callback_activate(void)
{
    int rc;

    rc = globus_module_activate(GLOBUS_THREAD_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    rc = globus_module_activate(GLOBUS_THREAD_POOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    globus_handle_table_init(&globus_l_callback_handle_table);

    globus_timeq_init(&globus_l_callback_q);
    globus_mutex_init(&globus_l_q_lock,
		      (globus_mutexattr_t *) GLOBUS_NULL);
   
#   if !defined(_GLOBUS_CALLBACK_USE_THREAD_POOL)
    {
        globus_thread_key_create(&globus_l_restart_thread_key, 
		                  GLOBUS_NULL);
    }
#   else
    {
        globus_thread_pool_key_create(&globus_l_restart_thread_key, 
		                  GLOBUS_NULL);
    }
#   endif

#   if  defined(_CALLBACK_USE_INTERNAL_MEM)
    {
        globus_memory_init(&globus_l_memory_callback_info,
                         sizeof(globus_l_callback_info_t),
			 GLOBUS_L_CALLBACK_INIT_STRUCT_COUNT);
        globus_memory_init(&globus_l_memory_restart_info,
                         sizeof(globus_l_thread_restart_info_t),
			 GLOBUS_L_CALLBACK_INIT_STRUCT_COUNT);
    }
#   endif

#   if !defined(BUILD_LITE)
    {
	globus_l_thread_count = 0;
        globus_l_callback_shutting_down = GLOBUS_FALSE;
        globus_l_time_q_thread_running = GLOBUS_FALSE;    

        globus_cond_init(&globus_l_thread_cond,
		         (globus_condattr_t *) GLOBUS_NULL);
        globus_cond_init(&globus_l_callback_run_cond,
		         (globus_condattr_t *) GLOBUS_NULL);

        globus_mutex_init(&globus_l_thread_create_lock,
  		          (globus_mutexattr_t *) GLOBUS_NULL);
	globus_l_wakeup_list = GLOBUS_NULL;
        
	globus_mutex_lock(&globus_l_thread_create_lock);
        {
    	    /*  if thread not running and library isn't shut down */
            if(!globus_l_time_q_thread_running)
	    {
	        int tc_rc;;
                globus_l_time_q_thread_running = GLOBUS_TRUE;
	        globus_l_thread_count++;
#               if !defined(_GLOBUS_CALLBACK_USE_THREAD_POOL)
		{
                    tc_rc = globus_thread_create(
                            GLOBUS_NULL,
	                    (globus_threadattr_t *) GLOBUS_NULL,
			    globus_l_callback_timeq_run,
			    (void *) GLOBUS_NULL);
                    assert (tc_rc==0);
                }
#               else
		{
                    globus_i_thread_start(
                        globus_l_callback_timeq_run,
                        (void *) GLOBUS_NULL);
                }
#               endif
            }
        }
        globus_mutex_unlock(&globus_l_thread_create_lock);
    }
#   else
    {
        globus_thread_setspecific(
            globus_l_restart_thread_key,
	    (void *) GLOBUS_NULL);
        globus_thread_blocking_callback_push(globus_l_callback_func_restart,
					     (void *) GLOBUS_NULL,
                                             &(globus_l_callback_index));
       globus_thread_blocking_callback_disable(&(globus_l_callback_index));
    }
#   endif

    globus_l_callback_module_is_active = GLOBUS_TRUE;

    return GLOBUS_SUCCESS;
}
/* globus_callback_activate() */

/*
 * globus_callback_deactivate()
 */
static int
globus_l_callback_deactivate(void)
{
    int rc;
    /*  clean up for threaded build */
#   if   !defined(BUILD_LITE)
    {
	globus_list_t *                    i;
	globus_l_callback_info_t *         callback_info;

        /* lock thread create will hold all new threads from starting
           and hold all adds to the wakeup list.  Once the lock is released
           globus_l_callback_shuting_down is set to true.  All operations that
           were waiting for the lock must check globus_l_callback_shuting_down
           to see if they can proceed. */
        globus_mutex_lock(&globus_l_thread_create_lock);
        {
   	    /* wake up all threads */
	    i = globus_l_wakeup_list;
	    while(!globus_list_empty(i))
	    {
                callback_info = (globus_l_callback_info_t *)
			           globus_list_first(i);

	        callback_info->wakeup_func(callback_info->wakeup_args);

                i = globus_list_rest(i);
	    }
            globus_list_free(globus_l_wakeup_list);
    
            globus_l_callback_shutting_down = GLOBUS_TRUE;

            globus_cond_signal(&globus_l_callback_run_cond);
   
            /* wait for all threads to complete */
            while(globus_l_thread_count > 0)
            {
                globus_cond_wait(&globus_l_thread_cond,
  		                 &globus_l_thread_create_lock);
            }
        }
        globus_mutex_unlock(&globus_l_thread_create_lock);

        /* destroy threaded mutexes. */

        globus_mutex_destroy(&globus_l_thread_create_lock);
        globus_cond_destroy(&globus_l_thread_cond);
        globus_cond_destroy(&globus_l_callback_run_cond);

     }
#    endif

    /* destroy non-threaded mutexes */
    /* at this ppint locking is probably unneeded
     * since all threads should be ended, but is good form
     */
    globus_mutex_lock(&globus_l_q_lock);
    {  
        globus_l_callback_info_t *        callback_info;
        while(globus_timeq_size(&globus_l_callback_q) > 0)
        {
	    callback_info = (globus_l_callback_info_t *)
                globus_timeq_dequeue(&globus_l_callback_q);
            globus_l_callback_free(callback_info);
        }
    }
    globus_mutex_unlock(&globus_l_q_lock);

    globus_timeq_destroy(&globus_l_callback_q);
    globus_mutex_destroy(&globus_l_q_lock);
    globus_handle_table_destroy(&globus_l_callback_handle_table);

    rc = globus_module_deactivate(GLOBUS_THREAD_POOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    globus_module_deactivate(GLOBUS_THREAD_MODULE);

#   if defined(_CALLBACK_USE_INTERNAL_MEM)
    {
        globus_memory_destroy(&globus_l_memory_callback_info);
        globus_memory_destroy(&globus_l_memory_restart_info);
    }
#   endif
    globus_l_callback_module_is_active = GLOBUS_FALSE;

    return GLOBUS_SUCCESS;
}
/* globus_callback_deactivate() */

/*
 *   globus_callback_poll()
 */
void
globus_callback_poll(
    globus_abstime_t *                            timeout)
{

    if(globus_l_callback_module_is_active == GLOBUS_FALSE)
    {
        return;
    }

#   if !defined(BUILD_LITE)
    {
        globus_thread_yield();
    }
#   else
    {
	globus_abstime_t                         time_now;
	globus_abstime_t *                       tmp_time;
	globus_abstime_t *                       time_stop;
	globus_abstime_t                         time_next;
        globus_bool_t                            done = GLOBUS_FALSE;
        globus_bool_t                            rc;
        globus_bool_t                            first_call = GLOBUS_TRUE;
        globus_l_thread_restart_info_t *         restart_info;
        globus_l_thread_restart_info_t *         last_restart_info;
        globus_abstime_t                         l_timeout;
        globus_l_callback_info_t *               callback_info;

        if(timeout == GLOBUS_NULL)
        {
            GlobusTimeAbstimeCopy(l_timeout, globus_i_abstime_zero);
            timeout = &l_timeout;
        }
        
        restart_info = MALLOC_RESTART_T();
        last_restart_info = (globus_l_thread_restart_info_t *)
                                globus_thread_getspecific(globus_l_restart_thread_key);

        while(!done &&
	      !globus_timeq_empty(&globus_l_callback_q))
	{
            GlobusTimeAbstimeGetCurrent(time_now);

            if(globus_abstime_cmp(&time_now, (globus_abstime_t *)timeout) > 0 &&
               !first_call) 
	    {
                done = GLOBUS_TRUE;
	    }
	    else
	    {
		first_call = GLOBUS_FALSE;
                globus_l_callback_queue_get_next(
                                &callback_info,
                                &time_next);
	        if(callback_info != GLOBUS_NULL) 
	        {
                    time_stop = timeout;
		    if(globus_timeq_size(&globus_l_callback_q) > 0)
		    {
			tmp_time = globus_timeq_first_time(
				       &globus_l_callback_q);
			if(globus_abstime_cmp(
			       tmp_time, 
                               (globus_abstime_t *)time_stop) < 0)
			{
                            time_stop = tmp_time;
			}
		    }

	            restart_info->callback_info = callback_info;
	            restart_info->callback_index = globus_l_callback_index;

		    GlobusTimeAbstimeCopy(restart_info->end_time, *time_stop);
		    GlobusTimeAbstimeCopy(restart_info->start_time, time_now);
                    
                    restart_info->restarted = GLOBUS_FALSE;

                    globus_thread_blocking_callback_enable(&(globus_l_callback_index)); 

		    /*
		     * call the users function
		     */
	            globus_thread_setspecific(
			globus_l_restart_thread_key,
		        (void *) restart_info);
		    callback_info->call_depth++;

                    callback_info->handler_thread_id = globus_thread_self();
                    rc = callback_info->callback_func(time_stop,
				             callback_info->callback_args);


		    callback_info->call_depth--;
	            globus_thread_setspecific(
			globus_l_restart_thread_key,
		        (void *) last_restart_info);

		    /* rest global structures to current call stack values */
		    GlobusTimeAbstimeCopy(restart_info->end_time, *time_stop);
		    GlobusTimeAbstimeCopy(restart_info->start_time, time_now);
	            restart_info->callback_info = callback_info;

		    /* 
		     *  if one shot or canceled free it 
		     *  else put it back in the queue  
		     */
		    if(globus_time_reltime_is_infinity(&callback_info->period) &&
		       callback_info->call_depth == 0)
		    {
			if(callback_info->unregister_callback != GLOBUS_NULL)
			{
			    callback_info->unregister_callback(
                                callback_info->unreg_args);
			}
			globus_l_callback_free(callback_info);
		    }
		    else if(!globus_time_reltime_is_infinity(
                                 &callback_info->period) &&
                           !restart_info->restarted)
		    {
			globus_l_callback_requeue(callback_info);
		    }

		    /* end loop if callback changed something */
		    if(rc)
		    {
                        done = GLOBUS_TRUE;
		    }
	        }
		/* sleep until next one is ready or timeout expires */
	        else if(globus_abstime_cmp(timeout, 
                                           &time_next) > 0)
	        {
                    globus_reltime_t    sleep_time;
                    long tm;

                    GlobusTimeAbstimeDiff(sleep_time, time_next, time_now);
                    GlobusTimeReltimeToUSec(tm, sleep_time);

		    if(tm > 0)
		    {
                        globus_libc_usleep(tm);
		    }
	        }
		else if(!globus_time_abstime_is_infinity(
                             (globus_abstime_t *)timeout))
		{
                    done = GLOBUS_TRUE;
		}
            }
	}
	FREE_RESTART_T(restart_info);
    }

#   endif
}

int
globus_callback_register_oneshot(
    globus_callback_handle_t *                 callback_handle,
    globus_reltime_t *                         start_time,
    globus_callback_func_t                     callback_func,
    void *                                     callback_user_args,
    globus_wakeup_func_t                       wakeup_func,
    void *                                     wakeup_user_args)
{
    int rc;
    globus_reltime_t                           period;

    GlobusTimeReltimeCopy(period, globus_i_reltime_infinity);
    rc = globus_l_callback_register(
            callback_handle,
            start_time,
            &period,
            callback_func,
            callback_user_args,
            wakeup_func,
            wakeup_user_args);

   return rc;
}

int
globus_callback_register_periodic(
    globus_callback_handle_t *                 callback_handle,
    globus_reltime_t *                         start_time,
    globus_reltime_t *                         period,
    globus_callback_func_t                     callback_func,
    void *                                     callback_user_args,
    globus_wakeup_func_t                       wakeup_func,
    void *                                     wakeup_user_args)
{
    return globus_l_callback_register(
               callback_handle,
               start_time,
               period,
               callback_func,
               callback_user_args,
               wakeup_func,
               wakeup_user_args);
}

int
globus_l_callback_register(
    globus_callback_handle_t *                 callback_handle,
    globus_reltime_t *                         start_time,
    globus_reltime_t *                         period,
    globus_callback_func_t                     callback_func,
    void *                                     callback_user_args,
    globus_wakeup_func_t                       wakeup_func,
    void *                                     wakeup_user_args)
{
    globus_l_callback_info_t *            callback_info;

    if(globus_l_callback_module_is_active == GLOBUS_FALSE)
    {
        return GLOBUS_FAILURE;
    }

    assert(period != GLOBUS_NULL);
    assert(start_time != GLOBUS_NULL);

#   if  defined(BUILD_LITE)
    {
	/* if not threaded wakeup function is illegal */
        if(wakeup_func != GLOBUS_NULL)
	{
	    wakeup_func = GLOBUS_NULL;
        }
    }
#   endif

  
    /* create and populate info structure */
    callback_info = MALLOC_CALLBACK_T();

    if(callback_handle != NULL)
    {
        callback_info->handle = 
              globus_handle_table_insert(
                  &globus_l_callback_handle_table,
		  (void*)callback_info,
		  2);

        *callback_handle = callback_info->handle;
    }
    else
    {
        callback_info->handle = 
              globus_handle_table_insert(
                  &globus_l_callback_handle_table,
		  (void*)callback_info,
		  1);
    }

    callback_info->callback_func = callback_func;
    callback_info->callback_args = callback_user_args;
    callback_info->wakeup_func = wakeup_func;
    callback_info->wakeup_args = wakeup_user_args;
    callback_info->running = GLOBUS_FALSE;
    callback_info->call_depth = 0;
    callback_info->unregister_callback = GLOBUS_NULL;
    callback_info->unreg_args = GLOBUS_NULL;

    GlobusTimeAbstimeGetCurrent((callback_info->start_time));
    GlobusTimeAbstimeInc((callback_info->start_time), *start_time); 
    GlobusTimeReltimeCopy((callback_info->period), *period);

    /* add it to the queue */
    globus_mutex_lock(&globus_l_q_lock);
    {
        globus_timeq_enqueue(&globus_l_callback_q,
  			     (void *) callback_info,
			     &callback_info->start_time);
    }
    globus_mutex_unlock(&globus_l_q_lock);


#   if !defined(BUILD_LITE)
    {
        globus_mutex_lock(&globus_l_thread_create_lock);
	{
            if(
               !globus_l_callback_shutting_down)
            {
                globus_cond_signal(&globus_l_callback_run_cond);
	    }
        }
        globus_mutex_unlock(&globus_l_thread_create_lock);
    }
#   endif
    return GLOBUS_SUCCESS;
}

/*
 *  globus_l_callback_free()
 *  ------------------------
 *  called from unregister and when one shots are finished
 */
static void
globus_l_callback_free(
    globus_l_callback_info_t *                  info)
{
    /* may not be in queue if threaded and finished running */

    globus_timeq_remove(
        &globus_l_callback_q,
         info);
    info->running = GLOBUS_FALSE;
    if(!globus_handle_table_decrement_reference(
           &globus_l_callback_handle_table,
           info->handle)
      )
    {
        FREE_CALLBACK_T(info);
    }
}

int
globus_i_callback_blocking_cancel(
    globus_callback_handle_t *          callback_handle)
{
    globus_l_callback_monitor_t   monitor;
    
    globus_cond_init(&monitor.cond,
                     (globus_condattr_t *) GLOBUS_NULL);
    globus_mutex_init(&monitor.mutex,
                     (globus_mutexattr_t *) GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;

   
    globus_i_callback_register_cancel(
        callback_handle,
        globus_i_unregister_callback,
        (void *)&monitor);

    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond,
                             &monitor.mutex);
        }   
    }
    globus_mutex_unlock(&monitor.mutex);


    globus_cond_destroy(&monitor.cond);
    globus_mutex_destroy(&monitor.mutex);

    return GLOBUS_TRUE;
}

void
globus_i_unregister_callback(
    void *                              user_args)
{

    globus_l_callback_monitor_t *   monitor;

    monitor = (globus_l_callback_monitor_t *) user_args;

    globus_mutex_lock(&monitor->mutex);
    {
        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);

}

globus_result_t
globus_callback_handle_destroy(
   globus_callback_handle_t *          calback_handle)
{
    return GLOBUS_SUCCESS;
}

int
globus_i_callback_register_cancel(
    globus_callback_handle_t *          callback_handle,
    globus_unregister_callback_func_t   unregister_callback,
    void *                              unreg_args)
{
    globus_l_callback_info_t *            callback_info;
    int                                   rc = GLOBUS_FAILURE;

    if(globus_l_callback_module_is_active == GLOBUS_FALSE)
    {
        return GLOBUS_FAILURE;
    }

    callback_info = (globus_l_callback_info_t *) 
        globus_handle_table_lookup(
            &globus_l_callback_handle_table,
            *callback_handle);

    /* test to see if the handle is registered */
    if(callback_info == GLOBUS_NULL)
    {
        rc = GLOBUS_FAILURE;
	if(unregister_callback != GLOBUS_NULL)
	{
            unregister_callback(unreg_args);
	}
    }
    else
    {
        globus_mutex_lock(&globus_l_q_lock);
        {
            globus_handle_table_decrement_reference(
                &globus_l_callback_handle_table,
                callback_info->handle);
	  /* if registerd set so it is not requeued */
            if(callback_info->running == GLOBUS_FALSE)
	    {
		if(unregister_callback != GLOBUS_NULL)
		{
                    unregister_callback(unreg_args);
		}
                globus_l_callback_free(callback_info);
	    }
            else
	    {
                /* set to infinite so it is removed after it returns */
                GlobusTimeReltimeCopy((callback_info->period), 
                                       globus_i_reltime_infinity);
                callback_info->unregister_callback = unregister_callback;
                callback_info->unreg_args = unreg_args;
	    }
        }
        globus_mutex_unlock(&globus_l_q_lock);

        rc = GLOBUS_SUCCESS;
    }

    return rc;
}

/*
 *  queue must be locked before this is called
 */
static void
globus_l_callback_requeue(
    globus_l_callback_info_t *                 callback_info)
{
    globus_abstime_t                 time_now;

    GlobusTimeAbstimeGetCurrent(time_now);
    GlobusTimeAbstimeInc((callback_info->start_time), (callback_info->period));
    
    callback_info->running = GLOBUS_FALSE;

    if(globus_abstime_cmp(&callback_info->start_time, &time_now) < 0)
    {
        GlobusTimeAbstimeCopy((callback_info->start_time), time_now);
    }

    globus_timeq_enqueue(&globus_l_callback_q,
                         (void *) callback_info,
			 &callback_info->start_time);
#   if !defined(BUILD_LITE)
    {
        globus_mutex_lock(&globus_l_thread_create_lock);
        {
            if(
               !globus_l_callback_shutting_down)
            {
                globus_cond_signal(&globus_l_callback_run_cond);
            }
        }
        globus_mutex_unlock(&globus_l_thread_create_lock);
    }
#   endif

}

#if  !defined(BUILD_LITE)

/*
 *
 */
static void *
globus_l_callback_timeq_run(
    void *                                     user_args)
{
    globus_l_callback_info_t *         callback_info;
    globus_abstime_t                   time_now;
    globus_abstime_t                   next_time;
    globus_abstime_t                   time_stop;
    int                                done = 0;
    globus_l_thread_restart_info_t *   restart_info = GLOBUS_NULL;
    globus_bool_t                      rc;

    /*  loop until the queue is empty, or shutdown */
    restart_info = MALLOC_RESTART_T();
    restart_info->restarted = GLOBUS_FALSE;
    globus_thread_setspecific(globus_l_restart_thread_key,
	                      (void *) restart_info);

    globus_thread_blocking_callback_push(globus_l_callback_func_restart,
					 (void *) globus_l_callback_timeq_run,
                                          &(restart_info->callback_index));

    /* Make sure the the list hasn't emptied and deactivate 
     * hasn't been called in inbetween the start of the thread
     * and now.  */

    while(!done)
    {
        globus_mutex_lock(&globus_l_thread_create_lock);
        {
            if(globus_l_callback_shutting_down)
            {
                done = GLOBUS_TRUE;
                globus_l_time_q_thread_running = GLOBUS_FALSE;
            }
            else if(globus_timeq_empty(&globus_l_callback_q))
	    {
		globus_thread_blocking_callback_disable(&(restart_info->callback_index));
                globus_cond_wait(&globus_l_callback_run_cond,
				 &globus_l_thread_create_lock);
		globus_thread_blocking_callback_enable(&(restart_info->callback_index));
	    }
        }
        globus_mutex_unlock(&globus_l_thread_create_lock);

	/* get next element if wait time expired */
        globus_l_callback_queue_get_next(
            &callback_info,
            &next_time);
	if(callback_info != GLOBUS_NULL)
        {
            /* if function does not have its own thread */
	    if(callback_info->wakeup_func == NULL)
	    {
		/* by calling the registered function it is possible 
		 * that the thread could be restarted
		 */
                restart_info->callback_info = callback_info;
                GlobusTimeAbstimeGetCurrent((restart_info->start_time));

		if(globus_timeq_size(&globus_l_callback_q) > 0)
		{
                    globus_abstime_t *           tmp_time;

		    tmp_time = globus_timeq_first_time(&globus_l_callback_q);
                    GlobusTimeAbstimeCopy(time_stop,
                                          (*tmp_time));
                    GlobusTimeAbstimeCopy(restart_info->end_time,
                                          (time_stop));
                }
		else
		{
                    GlobusTimeAbstimeCopy((time_stop), 
                                          globus_i_abstime_infinity);
                    GlobusTimeAbstimeCopy(restart_info->end_time,
					  (time_stop));
      		}

                callback_info->handler_thread_id = globus_thread_self();
                rc = callback_info->callback_func(
				       &time_stop,
				       callback_info->callback_args);

		globus_thread_yield();

                /* if restarted logic */
		restart_info = (globus_l_thread_restart_info_t *)
				 globus_thread_getspecific(globus_l_restart_thread_key);
		/*  
		 *  The queue must be locked before the test to reenqueue is made
		 *  otherwise unregister may be called after the test but 
		 *  before the requeue.
		 */
                globus_mutex_lock(&globus_l_q_lock);
		{
		    callback_info->running = GLOBUS_FALSE;
                    if(restart_info->restarted)
		    {
                        done = GLOBUS_TRUE;
		    }
	            else if(globus_time_reltime_is_infinity(&callback_info->period) &&
			    !callback_info->running)
	            {
			if(callback_info->unregister_callback != GLOBUS_NULL)
			{
		            callback_info->unregister_callback(callback_info->unreg_args);
			}
			globus_l_callback_free(callback_info);
                    }
		    else
		    {
  	                globus_l_callback_requeue(callback_info);
		    }
                }
                globus_mutex_unlock(&globus_l_q_lock);
            }
	    else
	    {
		globus_mutex_lock(&globus_l_thread_create_lock);
		{
	            if(!globus_l_callback_shutting_down)
		    {
		 	globus_list_insert(&globus_l_wakeup_list,
					    (void *) callback_info);

	                globus_l_thread_count++;
#                       if !defined(_GLOBUS_CALLBACK_USE_THREAD_POOL)
			{
                            globus_thread_create(
                                GLOBUS_NULL,
			        (globus_threadattr_t *) GLOBUS_NULL,
			        globus_l_callback_func_run,
			        (void *) callback_info);
                        }
#                       else 
			{
                            globus_i_thread_start(
                                globus_l_callback_func_run,
		                (void *) callback_info);
                        }
#                       endif
                    }
	        } 
		globus_mutex_unlock(&globus_l_thread_create_lock);
	    }
	}
        /* callback == NULL */
	else
        {
            globus_mutex_lock(&globus_l_thread_create_lock);
            {
                if(globus_l_callback_shutting_down)
                {
                    done = GLOBUS_TRUE;
                    globus_l_time_q_thread_running = GLOBUS_FALSE;
                }
		else
		{
	   	    globus_thread_blocking_callback_disable(
                        &(restart_info->callback_index));

                    if(globus_time_abstime_is_infinity(&next_time))
                    {
                        globus_cond_wait(
		            &globus_l_callback_run_cond,
		            &globus_l_thread_create_lock);
                    }
                    else
                    {
                        globus_cond_timedwait(
		            &globus_l_callback_run_cond,
		            &globus_l_thread_create_lock,
			    &next_time);
                    }
		    globus_thread_blocking_callback_enable(
                        &(restart_info->callback_index));
	        }
            }
            globus_mutex_unlock(&globus_l_thread_create_lock);
	}
    }
    FREE_RESTART_T(restart_info);
    globus_l_thread_count_dec();

    return GLOBUS_NULL;
}

static void
globus_l_thread_count_dec()
{
    globus_mutex_lock(&globus_l_thread_create_lock);
    {
	 globus_l_thread_count--;
	 if(globus_l_thread_count <= 0)
	 {
             globus_l_callback_shutting_down = GLOBUS_TRUE;
             globus_cond_signal(&globus_l_thread_cond);
	 }
    }
    globus_mutex_unlock(&globus_l_thread_create_lock);
}

/*
 *
 */
static void *
globus_l_callback_func_run(
    void *                                     user_args)
{
    globus_l_thread_restart_info_t *      restart_info;
    globus_l_callback_info_t *            callback_info;
    globus_bool_t                         done = GLOBUS_FALSE;
    globus_bool_t                         freeit = GLOBUS_FALSE;
    globus_bool_t                         rc;
    globus_abstime_t                      time_now;
    globus_abstime_t                      timeout;

    callback_info = (globus_l_callback_info_t *) user_args;

    restart_info = MALLOC_RESTART_T();
    restart_info->restarted = GLOBUS_FALSE;

    GlobusTimeAbstimeCopy(restart_info->end_time, globus_i_abstime_infinity);

    restart_info->callback_info = callback_info;
    globus_thread_setspecific(globus_l_restart_thread_key,
			      (void *) restart_info);

    globus_thread_blocking_callback_push(globus_l_callback_func_restart,
					 (void *) GLOBUS_NULL,
                                          &(restart_info->callback_index));

    while(!done &&
	  !globus_l_callback_shutting_down)
    {
	callback_info->running = GLOBUS_TRUE;
        GlobusTimeAbstimeGetCurrent(restart_info->start_time);
        GlobusTimeAbstimeCopy(timeout, globus_i_abstime_infinity);

        callback_info->handler_thread_id = globus_thread_self();
        rc = callback_info->callback_func(
                 &timeout,
		 callback_info->callback_args);

	globus_thread_yield();

        globus_mutex_lock(&globus_l_q_lock);
        {
	    if(restart_info->restarted)
	    {
	        done = GLOBUS_TRUE;
            }
	    else if(globus_time_reltime_is_infinity(&callback_info->period))
	    {
	         callback_info->running = GLOBUS_FALSE;
                 done = GLOBUS_TRUE;
		 freeit = GLOBUS_TRUE;
	    }
	    else
	    {
                globus_abstime_t   tmp_time;

                GlobusTimeAbstimeGetCurrent(time_now);
                GlobusTimeAbstimeCopy(tmp_time, callback_info->start_time);
                GlobusTimeAbstimeInc(tmp_time, callback_info->period);
                /*
                 * might be a good idea to put in some kind of delta
                 * with a sleep for efficientcy
                 */
                if(globus_abstime_cmp(&tmp_time, &time_now) > 0)
	        {
		    callback_info->running = GLOBUS_FALSE;
	            globus_l_callback_requeue(restart_info->callback_info);
                    done = GLOBUS_TRUE;
                }
		else
		{
                    GlobusTimeAbstimeCopy(callback_info->start_time, tmp_time);
		}
	    }
        }
        globus_mutex_unlock(&globus_l_q_lock);
    }
 
    /* if the thread was not restarted remove from wakeup list */
    if(!restart_info->restarted)
    {
        globus_mutex_lock(&globus_l_thread_create_lock);
	{
	    if(!globus_l_callback_shutting_down)
	    {
	        globus_list_t * entry;

	        entry = globus_list_search(globus_l_wakeup_list,
			                   callback_info);

                globus_list_remove(&globus_l_wakeup_list,
			           entry);
	    }
	}
        globus_mutex_unlock(&globus_l_thread_create_lock);
	if(freeit)
	{
	    if(callback_info->unregister_callback != GLOBUS_NULL)
	    {
                callback_info->unregister_callback(callback_info->unreg_args);
	    }
            globus_mutex_lock(&globus_l_q_lock);
            {
                globus_l_callback_free(callback_info);
            }
            globus_mutex_unlock(&globus_l_q_lock);
	}
    }
    FREE_RESTART_T(restart_info);
    globus_l_thread_count_dec();

    return GLOBUS_NULL;
}
#endif /* BUILD_LITE */

/*
 *
 */
static void *
globus_l_callback_func_restart(
    globus_thread_callback_index_t             blocking_func_ndx,
    void *                                     user_args)
{
    globus_l_thread_restart_info_t *      restart_info;
    globus_l_callback_info_t *            callback_info;

    restart_info = (globus_l_thread_restart_info_t *)
		     globus_thread_getspecific(globus_l_restart_thread_key);

    if(restart_info == GLOBUS_NULL 
	  || restart_info->callback_info == GLOBUS_NULL)
    {
	return GLOBUS_NULL;
    }
    callback_info = restart_info->callback_info;
      
    /* 
     *  if not one shot, 
     *  not already rentered at this depth
     *  and not in its own thread
     */
    /* 
     *  lock queue before testing to see if it should be inserted.  It is 
     *  possible for another thread to unregister it after passing if.
     */
    globus_mutex_lock(&globus_l_q_lock);
    {
        if(!restart_info->restarted &&
           !globus_time_reltime_is_infinity(&callback_info->period))
        /* &&  callback_info->wakeup_func == GLOBUS_NULL)*/
        {
  	    globus_l_callback_requeue(callback_info);
        }
        restart_info->restarted = GLOBUS_TRUE;
    }
    globus_mutex_unlock(&globus_l_q_lock);
    globus_thread_blocking_callback_disable(&(blocking_func_ndx));

#   if !defined(BUILD_LITE)
    {
	globus_thread_func_t    func;

        /*  set func to the entry point of the new thread */
        func = (globus_thread_func_t) user_args;   

        if(func != GLOBUS_NULL)
        {
            globus_mutex_lock(&globus_l_thread_create_lock);
            {
                if(!globus_l_callback_shutting_down)
                {
                    globus_l_thread_count++;
#                   if !defined(_GLOBUS_CALLBACK_USE_THREAD_POOL)
                    {
                        globus_thread_create(
                            GLOBUS_NULL,
	                    (globus_threadattr_t *) GLOBUS_NULL,
		            func,
   		           (void *) callback_info);
                    }
#                   else
		    {
                        globus_i_thread_start(
                            func,
                            (void *) callback_info);
                    }
#                   endif
                }
            }
            globus_mutex_unlock(&globus_l_thread_create_lock);
        }
    }
#   endif

    return user_args;
}

static globus_bool_t
globus_l_callback_queue_get_next(
    globus_l_callback_info_t **                in_info,
    globus_abstime_t *                         next_time)
{
    globus_abstime_t                  time_can_block;
    globus_abstime_t                  time_now;
    globus_abstime_t *                tmp_time;
    globus_l_callback_info_t *        callback_info = GLOBUS_NULL;

    GlobusTimeAbstimeCopy(*next_time, globus_i_abstime_infinity);
    globus_mutex_lock(&globus_l_q_lock);
    {
        if(!globus_timeq_empty(&globus_l_callback_q))
        {
            tmp_time = globus_timeq_first_time(&globus_l_callback_q);
            GlobusTimeAbstimeCopy(*next_time, *tmp_time);
            GlobusTimeAbstimeGetCurrent(time_now);

    	    if(globus_abstime_cmp(next_time, &time_now) < 0)
    	    {
	        callback_info = (globus_l_callback_info_t *)
                                  globus_timeq_dequeue(&globus_l_callback_q);
                callback_info->running = GLOBUS_TRUE;
	    }
        }
    }
    globus_mutex_unlock(&globus_l_q_lock);

    *in_info = callback_info;
    return GLOBUS_TRUE;
}

/*
 *  returns a bool indicating wheather or not time has expired
 */
globus_bool_t
globus_callback_get_timeout(
    globus_reltime_t *                time_left)
{
    globus_abstime_t               time_now;
    globus_abstime_t               time_stop;
    globus_bool_t                  rc;

    if(!globus_callback_get_timestop(&time_stop))
    {
        GlobusTimeReltimeSet(*time_left, 0, 0);
        return GLOBUS_TRUE;
    }    

    if(globus_abstime_cmp(&time_stop, (globus_abstime_t *)&globus_i_abstime_infinity) == 0)
    {
        GlobusTimeReltimeCopy(*time_left, globus_i_reltime_infinity);
	rc = GLOBUS_FALSE;
    }
    else
    {
        GlobusTimeAbstimeGetCurrent(time_now);
	if(globus_abstime_cmp(&time_stop, &time_now) < 0)
  	{
            GlobusTimeReltimeCopy(*time_left, globus_i_reltime_zero);
	    rc = GLOBUS_TRUE;
	}
	else
	{
            GlobusTimeAbstimeDiff(*time_left, time_now, time_stop);
	    rc = GLOBUS_FALSE;
        }
    }
    return rc;
}

globus_bool_t
globus_callback_get_timestop(
    globus_abstime_t *                    time_stop)
{
    globus_l_thread_restart_info_t *	  restart_info;

    restart_info = (globus_l_thread_restart_info_t *)
                        globus_thread_getspecific(globus_l_restart_thread_key);

    if(restart_info == GLOBUS_NULL)
    {
        GlobusTimeAbstimeSet(*time_stop, 0, 0);

        return GLOBUS_FALSE;
    }
    GlobusTimeAbstimeCopy(*time_stop,  restart_info->end_time);

    return GLOBUS_TRUE;
}

globus_bool_t
globus_callback_has_time_expired()
{
    globus_abstime_t     time_now;
    globus_abstime_t     time_stop;
    globus_reltime_t     dummy_time;
  
    return globus_callback_get_timeout(&dummy_time);
/*

    globus_callback_get_timestop(&time_stop);

    if(globus_abstime_cmp(&time_stop, 
			  (globus_abstime_t *)&globus_i_abstime_infinity) != 0)
    {
        GlobusTimeAbstimeGetCurrent(time_now); 
        if(globus_abstime_cmp(&time_now, &time_stop) > 0)
        {
            return GLOBUS_TRUE;
        }
        else
        {
            return GLOBUS_FALSE;
        }
   }
   else
   {
       return GLOBUS_FALSE;
   }
   */
}

globus_bool_t
globus_callback_adjust_period(
    globus_callback_handle_t *                   handle,
    globus_reltime_t *                           period)
{
    globus_l_callback_info_t *                   callback_info;
    globus_thread_t                              thread_id;

    callback_info = (globus_l_callback_info_t *)
        globus_handle_table_lookup(
            &globus_l_callback_handle_table,
            *handle);

    thread_id = globus_thread_self();
    if(callback_info == GLOBUS_NULL || 
       globus_callback_was_restarted() ||
       !globus_thread_equal(callback_info->handler_thread_id, thread_id) ||
       !callback_info->running)
    {
        return GLOBUS_FALSE;
    }

    GlobusTimeReltimeCopy(callback_info->period, *period);

    return GLOBUS_TRUE;
}
/******************************************************************************
		       handle creation functions
******************************************************************************/
globus_bool_t
globus_callback_was_restarted()
{
    globus_l_thread_restart_info_t *      restart_info;

    restart_info = (globus_l_thread_restart_info_t *)
			 globus_thread_getspecific(globus_l_restart_thread_key);

    if(restart_info == GLOBUS_NULL)
    {
        return GLOBUS_FALSE;
    }
    return restart_info->restarted;
}

void print_inside_info(int type)
{
    globus_libc_printf("q size = %d", globus_timeq_size(&globus_l_callback_q));
}
