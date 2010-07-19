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

#include "globus_common_include.h"
#include "globus_thread_pool.h"
#include "version.h"
#include "globus_fifo.h"
#include "globus_time.h"
#include "globus_libc.h"
#include "globus_callback.h"
#include "globus_thread_common.h"

/* Number of idle threads we're willing to have waiting for tasks. Any more
 * idle threads than this will expire after TOO_MANY_IDLE_TIMEOUT seconds of
 * inactivity
 */
#define MAX_IDLE_THREADS                     32
#define TOO_MANY_IDLE_TIMEOUT		     30


/* Task Queue Management. Threads execute tasks from the task queue, waiting
 * on the task queue condition variable when there's nothing for them to do.
 */
globus_mutex_t                            globus_l_thread_pool_q_mutex;
globus_cond_t				              globus_l_thread_pool_q_cond;
globus_fifo_t                             globus_l_thread_pool_q;
volatile int                              globus_l_thread_pool_pending_tasks;

/* Thread Counts. We count threads so that we don't destroy the task queue until
 * everything's completed. Each thread shows up in one of these lists. Idle threads
 * are in their condition wait loop, and active threads are executing tasks.
 */
volatile int                              globus_l_thread_pool_idle_threads;
volatile int                              globus_l_thread_pool_active_threads;

/* Condition variable to indicate to deactivation function that all threads are
 * done.
 */
globus_cond_t				  globus_l_thread_pool_shutdown_cond;
volatile int				  globus_l_thread_pool_done;

/* Thread starter function */
void *
globus_l_thread_pool_thread_start(
    void *                                      user_arg);

void
globus_l_thread_pool_key_clean();

typedef struct
{
    globus_thread_func_t                func; 
    void *                              func_user_arg;
} globus_l_thread_pool_task_t;

typedef struct 
{
    globus_thread_key_destructor_func_t  dest_func;
    globus_thread_key_t                  key;
} globus_l_thread_pool_key_t;

#define KEY_NODE_FREE(ptr)                                 \
    (globus_free(ptr))

#define KEY_NODE_MALLOC()                                  \
    ((globus_l_thread_pool_key_t *)                          \
	globus_malloc(sizeof(globus_l_thread_pool_key_t)))

globus_list_t *                          globus_l_thread_pool_key_list;
globus_mutex_t                           globus_l_thread_pool_key_mutex;
/******************************************************************************
                           Module Definition
******************************************************************************/

globus_module_descriptor_t              globus_i_thread_pool_module = 
{
    "globus_thread_pool",
    globus_i_thread_pool_activate,
    globus_i_thread_pool_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

int
globus_i_thread_pool_activate(void)
{
    int                        rc;

    rc = globus_module_activate(GLOBUS_THREAD_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }

    globus_l_thread_pool_key_list = GLOBUS_NULL;
    globus_fifo_init(&globus_l_thread_pool_q);
    globus_mutex_init(&globus_l_thread_pool_q_mutex, GLOBUS_NULL);
    globus_mutex_lock(&globus_l_thread_pool_q_mutex);
    globus_mutex_init(&globus_l_thread_pool_key_mutex, GLOBUS_NULL);
    globus_cond_init(&globus_l_thread_pool_q_cond, GLOBUS_NULL);
    globus_cond_init(&globus_l_thread_pool_shutdown_cond, GLOBUS_NULL);
    globus_l_thread_pool_idle_threads = 0;
    globus_l_thread_pool_active_threads = 0;
    globus_l_thread_pool_done = GLOBUS_FALSE;
    globus_l_thread_pool_pending_tasks = 0;
    globus_mutex_unlock(&globus_l_thread_pool_q_mutex);

    return GLOBUS_SUCCESS;
}

int
globus_thread_pool_key_create( 
    globus_thread_key_t *                 key, 
    globus_thread_key_destructor_func_t   func) 
{
    int                                 rc;
    globus_l_thread_pool_key_t *	key_node;

    rc = globus_thread_key_create(key, GLOBUS_NULL);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }

    key_node = KEY_NODE_MALLOC();
    key_node->key =  *key;
    key_node->dest_func = func;

    globus_mutex_lock(&globus_l_thread_pool_key_mutex);
    {
        globus_list_insert(&globus_l_thread_pool_key_list, (void *)key_node);
    }
    globus_mutex_unlock(&globus_l_thread_pool_key_mutex);

    return rc;
}

void
globus_l_thread_pool_key_clean()
{
    globus_list_t *                     list;
    globus_l_thread_pool_key_t *        key_node;
    void *                              user_arg;

    globus_mutex_lock(&globus_l_thread_pool_key_mutex);
    {
        for(list = globus_l_thread_pool_key_list;
            !globus_list_empty(list);
	    list = globus_list_rest(list))
        {
            key_node = globus_list_first(list);
            user_arg = globus_thread_getspecific(key_node->key);
            
	    if(user_arg)
	    {
	        globus_thread_setspecific(key_node->key, GLOBUS_NULL);
	        
	        if(key_node->dest_func != GLOBUS_NULL)
    	        {
                    key_node->dest_func(user_arg);
                }
            }
        }
    }
    globus_mutex_unlock(&globus_l_thread_pool_key_mutex);
}

int
globus_i_thread_pool_deactivate(void)
{
    globus_mutex_lock(&globus_l_thread_pool_q_mutex);
    {
        globus_l_thread_pool_done = GLOBUS_TRUE;
	globus_cond_broadcast(&globus_l_thread_pool_q_cond);

        while(globus_l_thread_pool_idle_threads ||
	      globus_l_thread_pool_active_threads)
	{
	    globus_cond_wait(&globus_l_thread_pool_shutdown_cond,
	                     &globus_l_thread_pool_q_mutex);
	}
    }
    globus_mutex_unlock(&globus_l_thread_pool_q_mutex);


    globus_fifo_destroy(&globus_l_thread_pool_q);
    globus_mutex_destroy(&globus_l_thread_pool_q_mutex);
    globus_mutex_destroy(&globus_l_thread_pool_key_mutex);
    globus_cond_destroy(&globus_l_thread_pool_q_cond);

    return GLOBUS_SUCCESS;
}

/*
 * This is the code that the threads in the thread pool execute.
 * User thread functions are dispatched here.
 */
void *
globus_l_thread_pool_thread_start(
    void *                                      user_arg)
{
    globus_l_thread_pool_task_t *               task;
    globus_abstime_t                            timeout;
    globus_bool_t                               first = GLOBUS_TRUE;
   
    /* Handle the task we were created to do */
    task = (globus_l_thread_pool_task_t *) user_arg;
    task->func(task->func_user_arg);
    globus_thread_blocking_reset();
    globus_l_thread_pool_key_clean();
    globus_libc_free(task);
    task = GLOBUS_NULL;

    /* Now enter the thread pool */
    globus_mutex_lock(&globus_l_thread_pool_q_mutex);

    globus_l_thread_pool_active_threads--;
    globus_l_thread_pool_idle_threads++;

    while(!globus_l_thread_pool_done)
    {

        /* If there is nothing to do, and there are plenty of idle threads
         * then we'll give up this thread after a timeout if nothing new
         * shows up.
         */
        if(globus_fifo_empty(&globus_l_thread_pool_q) &&
           globus_l_thread_pool_idle_threads > MAX_IDLE_THREADS &&
           !first)
        {
            GlobusTimeAbstimeSet(timeout, TOO_MANY_IDLE_TIMEOUT, 0);
        }
        else
        {
            timeout = globus_i_abstime_infinity;
            first = GLOBUS_FALSE;
        }
    
        errno = 0;

        /* Wait for a task to become available, or timeout, or a shutdown */
        while(errno != ETIMEDOUT &&
              globus_fifo_empty(&globus_l_thread_pool_q) &&
              !globus_l_thread_pool_done)
        {
            if(globus_time_abstime_is_infinity(&timeout))
            {

		globus_cond_wait(&globus_l_thread_pool_q_cond,
                                 &globus_l_thread_pool_q_mutex);
            }
	    else
	    {

	    	globus_cond_timedwait(&globus_l_thread_pool_q_cond,
		                      &globus_l_thread_pool_q_mutex,
				      &timeout);
	    }
	}
	if(! globus_fifo_empty(&globus_l_thread_pool_q))
	{
            /* Execute task */
	    globus_l_thread_pool_active_threads++;
	    globus_l_thread_pool_idle_threads--;
	    task = globus_fifo_dequeue(&globus_l_thread_pool_q);
            globus_l_thread_pool_pending_tasks--;

	    globus_mutex_unlock(&globus_l_thread_pool_q_mutex);
	    {
		task->func(task->func_user_arg);
                globus_thread_blocking_reset();
                globus_l_thread_pool_key_clean();
		globus_libc_free(task);
	    }
	    globus_mutex_lock(&globus_l_thread_pool_q_mutex);

	    globus_l_thread_pool_idle_threads++;
	    globus_l_thread_pool_active_threads--;
	    timeout = globus_i_abstime_infinity;
	}
	else if(errno == ETIMEDOUT &&
		globus_l_thread_pool_idle_threads > MAX_IDLE_THREADS)
	{
            /* No task, and we timed out */
	    break;
	}
    }

    /* This thread is terminating. If it is the last one, then signal
     * the deactivate() thread
     */
    globus_l_thread_pool_idle_threads--;
    if(globus_l_thread_pool_done &&
       globus_l_thread_pool_idle_threads == 0 &&
       globus_l_thread_pool_active_threads == 0)
    {
        globus_cond_signal(&globus_l_thread_pool_shutdown_cond);
    }
    globus_mutex_unlock(&globus_l_thread_pool_q_mutex);

    return NULL;
}

/* Simple thread pool replacement to thread create. No fancy attribute
 * stuff, just have the function/argument pair execute in another
 * thread.
 */
void
globus_i_thread_start(
    globus_thread_func_t                func,
    void *                              user_arg)
{
    globus_l_thread_pool_task_t *      task;

    task = (globus_l_thread_pool_task_t *)
        globus_libc_malloc(sizeof(globus_l_thread_pool_task_t));
    task->func = func;
    task->func_user_arg = user_arg;

    globus_mutex_lock(&globus_l_thread_pool_q_mutex);
    {
        if(globus_l_thread_pool_idle_threads > globus_l_thread_pool_pending_tasks+1)
	{
            globus_l_thread_pool_pending_tasks++;
	    globus_fifo_enqueue(&globus_l_thread_pool_q,
	                        task);
	    globus_cond_signal(&globus_l_thread_pool_q_cond);
	}
	else
	{
		int rc;

		globus_l_thread_pool_active_threads++;

	    rc= globus_thread_create(GLOBUS_NULL,
	                         GLOBUS_NULL,
				 globus_l_thread_pool_thread_start,
				 task);
		globus_assert( rc == 0 );
	}
    }
    globus_mutex_unlock(&globus_l_thread_pool_q_mutex);
}

