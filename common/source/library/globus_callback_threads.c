#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

#include "globus_common_include.h"
#include "globus_i_callback.h"
#include "globus_thread_common.h"
#include "globus_thread_pool.h"
#include "globus_priority_q.h"
#include "globus_callback.h"
#include "globus_handle_table.h"

#define GLOBUS_CALLBACK_POLLING_THREADS 1
#define GLOBUS_L_CALLBACK_INFO_BLOCK_SIZE 32
#define GLOBUS_L_CALLBACK_SPACE_BLOCK_SIZE 16

/* any periodic with period (in the global space) smaller than this is 
 * going to get its own thread
 */
#define GLOBUS_L_CALLBACK_OWN_THREAD_PERIOD 5000  /* 5ms */

/* this is the number of ready oneshots that will be fired after time has
 * expired in globus_callback_space_poll()
 */
#define GLOBUS_L_CALLBACK_POST_STOP_ONESHOTS 10

#ifndef TARGET_ARCH_WIN32
extern pid_t                        globus_l_callback_main_thread;
#endif

static
int
globus_l_callback_activate(void);

static
int
globus_l_callback_deactivate(void);

#include "version.h"

globus_module_descriptor_t              globus_i_callback_module =
{
    "globus_callback_threaded",
    globus_l_callback_activate,
    globus_l_callback_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef enum
{
    GLOBUS_L_CALLBACK_QUEUE_NONE,
    GLOBUS_L_CALLBACK_QUEUE_TIMED,
    GLOBUS_L_CALLBACK_QUEUE_READY
} globus_l_callback_queue_state;

typedef struct globus_l_callback_info_s
{
    globus_callback_handle_t            handle;

    globus_callback_func_t              callback_func;
    void *                              callback_args;
    
    /* start_time only filled in for oneshots with delay and periodics */ 
    globus_abstime_t                    start_time;
    /* period only filled in for periodics */ 
    globus_reltime_t                    period;
    globus_bool_t                       is_periodic;
    globus_l_callback_queue_state       in_queue;

    int                                 running_count;

    globus_callback_func_t              unregister_callback;
    void *                              unreg_args;

    struct globus_l_callback_space_s *  my_space;
    
    /* used by ready queue macros */
    struct globus_l_callback_info_s *   next;
} globus_l_callback_info_t;

typedef struct
{
    globus_l_callback_info_t *          head;
    globus_l_callback_info_t **         tail;
} globus_l_callback_ready_queue_t;

typedef struct globus_l_callback_space_s
{
    globus_callback_space_t             handle;
    globus_callback_space_behavior_t    behavior;
    globus_priority_q_t                 timed_queue;
    globus_l_callback_ready_queue_t     ready_queue;
    globus_mutex_t                      lock;
    globus_cond_t                       cond;
    globus_bool_t                       shutdown;
    int                                 idle_count;
    /* only for serialized space shutdowns and single depth */
    int                                 thread_count; 
} globus_l_callback_space_t;

typedef struct globus_l_callback_space_attr_s
{
    globus_callback_space_behavior_t    behavior;
} globus_l_callback_space_attr_t;

typedef struct
{
    globus_bool_t                       restarted;
    const globus_abstime_t *            time_stop;
    globus_bool_t                       signaled;
    globus_l_callback_info_t *          callback_info;
    globus_bool_t                       create_thread;
    globus_bool_t                       own_thread;
} globus_l_callback_restart_info_t;

static globus_mutex_t                   globus_l_callback_handle_lock;
static globus_handle_table_t            globus_l_callback_handle_table;
static globus_memory_t                  globus_l_callback_info_memory;

static globus_mutex_t                   globus_l_callback_space_lock;
static globus_handle_table_t            globus_l_callback_space_table;
static globus_memory_t                  globus_l_callback_space_memory;
static globus_memory_t                  globus_l_callback_space_attr_memory;

static globus_l_callback_space_t        globus_l_callback_global_space;
static globus_bool_t                    globus_l_callback_shutting_down;

static globus_list_t *                  globus_l_callback_threaded_spaces;

static globus_thread_key_t              globus_l_callback_restart_info_key;

static globus_mutex_t                   globus_l_callback_thread_lock;
static globus_cond_t                    globus_l_callback_thread_cond;
static int                              globus_l_callback_max_polling_threads;
static int                              globus_l_callback_thread_count;
static globus_reltime_t                 globus_l_callback_own_thread_period;

static
void
globus_l_callback_info_dec_ref(
    globus_callback_handle_t            handle)
{
    globus_mutex_lock(&globus_l_callback_handle_lock);
    {
        globus_handle_table_decrement_reference(
            &globus_l_callback_handle_table, handle);
    }
    globus_mutex_unlock(&globus_l_callback_handle_lock);
}

static
void
globus_l_callback_space_dec_ref(
    globus_callback_space_t             space)
{
    globus_mutex_lock(&globus_l_callback_space_lock);
    {
        globus_handle_table_decrement_reference(
            &globus_l_callback_space_table, space);
    }
    globus_mutex_unlock(&globus_l_callback_space_lock);
}

/*
 * destructor for globus_handle_table.  called whenever the reference for
 * a callback_info goes to zero.
 *
 * the globus_l_callback_handle_lock should be locked before any accesses to
 * the callback info handle table
 */
static
void
globus_l_callback_info_destructor(
    void *                              datum)
{
    globus_l_callback_info_t *          callback_info;
    
    callback_info = (globus_l_callback_info_t *) datum;
    
    /* global space is local storage, is not managed */
    if(callback_info->my_space->handle != GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        globus_l_callback_space_dec_ref(callback_info->my_space->handle);
    }

    globus_memory_push_node(
        &globus_l_callback_info_memory, callback_info);
}

/* 
 * destructor for globus_handle_table.  called whenever the reference for
 * a space goes to zero.
 *
 * the globus_l_callback_space_lock should be locked before any accesses to
 * the space handle table
 */
static
void
globus_l_callback_space_destructor(
    void *                              datum)
{
    globus_l_callback_space_t *         i_space;
    globus_bool_t                       clean_up;
    
    i_space = (globus_l_callback_space_t *) datum;
    
    clean_up = GLOBUS_TRUE;
    
    if(i_space->behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED)
    {
        globus_mutex_lock(&globus_l_callback_thread_lock);
        {
            if(!globus_l_callback_shutting_down)
            {
                globus_mutex_lock(&i_space->lock);
                {
                    i_space->shutdown = GLOBUS_TRUE;
                    globus_cond_broadcast(&i_space->cond);
                }
                globus_mutex_unlock(&i_space->lock);
                
                globus_list_remove(
                    &globus_l_callback_threaded_spaces,
                    globus_list_search(
                        globus_l_callback_threaded_spaces, i_space));
                
                /* clean up will be done by exiting thread */
                clean_up = GLOBUS_FALSE;
            }
        }
        globus_mutex_unlock(&globus_l_callback_thread_lock);
    }
    
    if(clean_up)
    {
        globus_priority_q_destroy(&i_space->timed_queue);
        globus_mutex_destroy(&i_space->lock);
        globus_cond_destroy(&i_space->cond);
        
        globus_memory_push_node(
            &globus_l_callback_space_memory, i_space);
    }
}

static
void *
globus_l_callback_thread_poll(
    void *                              user_args);

static
int
globus_l_callback_activate()
{
    int                                 rc;
    int                                 i;
    char *                              tmp_string;

#ifndef TARGET_ARCH_WIN32
    if(!globus_l_callback_main_thread)
    {
        /* this is used by globus_dump_stack because linux threads have
         * different pids (and gdb can only attach to the main thread
         */
        globus_l_callback_main_thread = getpid();
    }
#endif
    
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
    
    GlobusTimeReltimeSet(
        globus_l_callback_own_thread_period,
        0,
        GLOBUS_L_CALLBACK_OWN_THREAD_PERIOD);
    
    globus_handle_table_init(
        &globus_l_callback_handle_table,
        globus_l_callback_info_destructor);
    
    globus_handle_table_init(
        &globus_l_callback_space_table,
        globus_l_callback_space_destructor);

    globus_memory_init(
        &globus_l_callback_info_memory,
        sizeof(globus_l_callback_info_t),
        GLOBUS_L_CALLBACK_INFO_BLOCK_SIZE);

    globus_memory_init(
        &globus_l_callback_space_memory,
        sizeof(globus_l_callback_space_t),
        GLOBUS_L_CALLBACK_SPACE_BLOCK_SIZE);
    
    globus_memory_init(
        &globus_l_callback_space_attr_memory,
        sizeof(globus_l_callback_space_attr_t),
        GLOBUS_L_CALLBACK_SPACE_BLOCK_SIZE);

    globus_l_callback_threaded_spaces = GLOBUS_NULL;
    
    /* init global 'space' */
    globus_l_callback_global_space.handle = GLOBUS_CALLBACK_GLOBAL_SPACE;
    globus_l_callback_global_space.behavior = 
        GLOBUS_CALLBACK_SPACE_BEHAVIOR_THREADED;
    GlobusICallbackReadyInit(&globus_l_callback_global_space.ready_queue);
    globus_priority_q_init(
        &globus_l_callback_global_space.timed_queue,
        (globus_priority_q_cmp_func_t) globus_abstime_cmp);
    globus_mutex_init(&globus_l_callback_global_space.lock, GLOBUS_NULL);
    globus_cond_init(&globus_l_callback_global_space.cond, GLOBUS_NULL);
    globus_l_callback_global_space.idle_count = 0;
    globus_l_callback_global_space.shutdown = GLOBUS_FALSE;
    
    globus_list_insert(
        &globus_l_callback_threaded_spaces, &globus_l_callback_global_space);
    
    globus_mutex_init(&globus_l_callback_handle_lock, GLOBUS_NULL);
    globus_mutex_init(&globus_l_callback_space_lock, GLOBUS_NULL);

    globus_mutex_init(&globus_l_callback_thread_lock, GLOBUS_NULL);
    globus_cond_init(&globus_l_callback_thread_cond, GLOBUS_NULL);
    
    globus_thread_key_create(
        &globus_l_callback_restart_info_key, GLOBUS_NULL);
    
    globus_l_callback_max_polling_threads = GLOBUS_CALLBACK_POLLING_THREADS;
    tmp_string = globus_module_getenv("GLOBUS_CALLBACK_POLLING_THREADS");
    if(tmp_string)
    {
        rc = atoi(tmp_string);

        if(rc > 0)
        {
            globus_l_callback_max_polling_threads = rc;
        }
    }
    
    globus_l_callback_thread_count = globus_l_callback_max_polling_threads;
    globus_l_callback_shutting_down = GLOBUS_FALSE;
    
    /* create pollers for the global space */
    for(i = 0; i < globus_l_callback_max_polling_threads; i++)
    {
        globus_i_thread_start(
            globus_l_callback_thread_poll,
            &globus_l_callback_global_space);
    }
    
    return GLOBUS_SUCCESS;
}

static
int
globus_l_callback_deactivate()
{
    int                                 rc;
    globus_list_t *                     tmp_list;
    globus_l_callback_space_t *         i_space;
    
    globus_mutex_lock(&globus_l_callback_thread_lock);
    {
        globus_l_callback_shutting_down = GLOBUS_TRUE;
        
        /* wake up any sleeping on queue */
        tmp_list = globus_l_callback_threaded_spaces;
        
        while(!globus_list_empty(tmp_list))
        {
            i_space = (globus_l_callback_space_t *)
                globus_list_first(tmp_list);
            
            globus_mutex_lock(&i_space->lock);
            {
                i_space->shutdown = GLOBUS_TRUE;
                globus_cond_broadcast(&i_space->cond);
            }
            globus_mutex_unlock(&i_space->lock);
            
            tmp_list = globus_list_rest(tmp_list);
        }
        
        globus_list_free(globus_l_callback_threaded_spaces);
        
        while(globus_l_callback_thread_count > 0)
        {
            globus_cond_wait(
                &globus_l_callback_thread_cond,
                &globus_l_callback_thread_lock);
        }
    }
    globus_mutex_unlock(&globus_l_callback_thread_lock);
    
    globus_thread_key_delete(globus_l_callback_restart_info_key);

    globus_cond_destroy(&globus_l_callback_global_space.cond);
    globus_mutex_destroy(&globus_l_callback_global_space.lock);
    globus_priority_q_destroy(&globus_l_callback_global_space.timed_queue);
    
    /* any handles left here will be destroyed by destructor.
     * important that globus_l_callback_handle_table be destroyed
     * BEFORE globus_l_callback_space_table since destructor for the former
     * accesses the latter
     */
    globus_handle_table_destroy(&globus_l_callback_handle_table);
    globus_handle_table_destroy(&globus_l_callback_space_table);
    
    globus_memory_destroy(&globus_l_callback_info_memory);
    globus_memory_destroy(&globus_l_callback_space_memory);
    globus_memory_destroy(&globus_l_callback_space_attr_memory);
    
    globus_mutex_destroy(&globus_l_callback_handle_lock);
    globus_mutex_destroy(&globus_l_callback_space_lock);
    
    globus_cond_destroy(&globus_l_callback_thread_cond);
    globus_mutex_destroy(&globus_l_callback_thread_lock);
    
    rc = globus_module_deactivate(GLOBUS_THREAD_POOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    
    return globus_module_deactivate(GLOBUS_THREAD_MODULE);
}

/**
 * globus_l_callback_register
 *
 * called by the external register functions.
 * -- populate a callback_info structure.
 */

static
globus_result_t
globus_l_callback_register(
    globus_callback_handle_t *          callback_handle,
    const globus_abstime_t *            start_time,
    const globus_reltime_t *            period,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_callback_space_t             space)
{
    globus_l_callback_info_t *          callback_info;
    globus_l_callback_space_t *         i_space;
    int                                 initial_refs;

    if(!callback_func)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_register_oneshot", "callback_func");
    }

    globus_mutex_lock(&globus_l_callback_handle_lock);
    {
        callback_info = (globus_l_callback_info_t *)
            globus_memory_pop_node(&globus_l_callback_info_memory);
        
        if(callback_info)
        {
            if(callback_handle)
            {
                /* if user passed callback_handle, there are two refs to this
                 * info, me and user.  User had better unregister this handle
                 * to free up the memory
                 */
                initial_refs = 2;
                callback_info->handle = globus_handle_table_insert(
                    &globus_l_callback_handle_table,
                    callback_info,
                    initial_refs);
        
                *callback_handle = callback_info->handle;
            }
            else
            {
                initial_refs = 1;
                callback_info->handle = globus_handle_table_insert(
                    &globus_l_callback_handle_table,
                    callback_info,
                    initial_refs);
            }
        }
    }
    globus_mutex_unlock(&globus_l_callback_handle_lock);
    
    if(!callback_info)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_MEMORY_ALLOC(
            "globus_l_callback_register", "callback_info");
    }

    if(space == GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        i_space = &globus_l_callback_global_space;
    }
    else
    {
        /* get internal space structure and increment its ref count */
        globus_mutex_lock(&globus_l_callback_space_lock);
        {
            i_space = (globus_l_callback_space_t *)
                globus_handle_table_lookup(
                    &globus_l_callback_space_table, space);
        
            if(i_space)
            {
                globus_handle_table_increment_reference(
                    &globus_l_callback_space_table, space);
            }
        }
        globus_mutex_unlock(&globus_l_callback_space_lock);
        
        if(!i_space)
        {
            /* just point at global space so destructor doesnt do
             * anything with it
             */
            callback_info->my_space = &globus_l_callback_global_space;
            
            globus_mutex_lock(&globus_l_callback_handle_lock);
            {
                globus_handle_table_decrement_reference(
                    &globus_l_callback_handle_table, callback_info->handle);
                if(initial_refs == 2)
                {
                    globus_handle_table_decrement_reference(
                       &globus_l_callback_handle_table, callback_info->handle);
                }
            }
            globus_mutex_unlock(&globus_l_callback_handle_lock);
    
            return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_SPACE(
                "globus_l_callback_register");
        }
    }
    
    callback_info->my_space = i_space;
    callback_info->callback_func = callback_func;
    callback_info->callback_args = callback_user_args;
    callback_info->running_count = 0;
    callback_info->unregister_callback = GLOBUS_NULL;

    if(period)
    {
        /* periodics need valid start times */
        if(!start_time)
        {
            GlobusTimeAbstimeGetCurrent(callback_info->start_time);
        }
        GlobusTimeReltimeCopy(callback_info->period, *period);
        callback_info->is_periodic = GLOBUS_TRUE;
    }
    else
    {
        callback_info->is_periodic = GLOBUS_FALSE;
    }
    
    globus_mutex_lock(&i_space->lock);
    {
        if(start_time)
        {
            if(globus_time_abstime_is_infinity(start_time))
            {
                /* this will never run... must be a periodic that will be
                 * restarted with globus_callback_adjust_period()
                 */
                callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_NONE;
                
                globus_mutex_lock(&globus_l_callback_handle_lock);
                {
                    /* if the user didnt pass a handle in for this, then
                     * this will cause the callback_info to be freed
                     * -- user doesnt know what they're doing, but no harm
                     * done
                     */
                    globus_handle_table_decrement_reference(
                       &globus_l_callback_handle_table, callback_info->handle);
                }
                globus_mutex_unlock(&globus_l_callback_handle_lock);
            }
            else
            {
                GlobusTimeAbstimeCopy(callback_info->start_time, *start_time);
                callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_TIMED;
                
                globus_priority_q_enqueue(
                    &i_space->timed_queue,
                    callback_info,
                    &callback_info->start_time);
            }
        }
        else
        {
            callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_READY;
            
            GlobusICallbackReadyEnqueue(&i_space->ready_queue, callback_info);
        }
        
        if(i_space->idle_count > 0)
        {
            globus_cond_signal(&i_space->cond);
        }
    }
    globus_mutex_unlock(&i_space->lock);
    
    return GLOBUS_SUCCESS;
}

/**
 * globus_callback_space_register_oneshot
 *
 * external function that registers a one shot some delay from now.
 *
 */

globus_result_t
globus_callback_space_register_oneshot(
    globus_callback_handle_t *          callback_handle,
    const globus_reltime_t *            delay_time,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_callback_space_t             space)
{
    globus_abstime_t                    start_time;

    if(delay_time)
    {
        if(globus_reltime_cmp(delay_time, &globus_i_reltime_zero) <= 0)
        {
            delay_time = GLOBUS_NULL;
        }
        else if(globus_time_reltime_is_infinity(delay_time))
        {
            /* user is being goofy here, but I'll allow it */
            GlobusTimeAbstimeCopy(start_time, globus_i_abstime_infinity);
        }
        else
        {
            GlobusTimeAbstimeGetCurrent(start_time);
            GlobusTimeAbstimeInc(start_time, *delay_time);
        }
    }

    return globus_l_callback_register(
        callback_handle,
        delay_time
            ? &start_time
            : GLOBUS_NULL,
        GLOBUS_NULL,
        callback_func,
        callback_user_args,
        space);
}

/**
 * globus_callback_space_register_periodic
 *
 * external function that registers a periodic to start some delay from now.
 */

globus_result_t
globus_callback_space_register_periodic(
    globus_callback_handle_t *          callback_handle,
    const globus_reltime_t *            delay_time,
    const globus_reltime_t *            period,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_callback_space_t             space)
{
    globus_abstime_t                    start_time;

    if(!period)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_register_periodic", "period");
    }

    if(delay_time)
    {
        if(globus_reltime_cmp(delay_time, &globus_i_reltime_zero) <= 0)
        {
            delay_time = GLOBUS_NULL;
        }
        else if(globus_time_reltime_is_infinity(delay_time))
        {
            GlobusTimeAbstimeCopy(start_time, globus_i_abstime_infinity);
        }
        else
        {
            GlobusTimeAbstimeGetCurrent(start_time);
            GlobusTimeAbstimeInc(start_time, *delay_time);
        }
    }
    
    if(globus_time_reltime_is_infinity(period))
    {
        /* infinite periods start life out as a oneshot,
         * globus_callback_adjust_period() is used to revive them
         */
        period = GLOBUS_NULL;
    }
    
    return globus_l_callback_register(
        callback_handle,
        delay_time
            ? &start_time
            : GLOBUS_NULL,
        period,
        callback_func,
        callback_user_args,
        space);
}

/**
 * globus_l_callback_cancel_kickout
 *
 * driver callback to kickout unregister callback.
 */

static
void
globus_l_callback_cancel_kickout_cb(
    void *                              user_args)
{
    globus_l_callback_info_t *          callback_info;

    callback_info = (globus_l_callback_info_t *) user_args;

    callback_info->unregister_callback(callback_info->unreg_args);
    
    /* this will cause the callback_info to be freed */
    globus_l_callback_info_dec_ref(callback_info->handle);
}

/**
 * globus_callback_unregister
 *
 * external function that cancels a previously registered callback.  will not
 * interrupt an already running callback.  also handles case where callback has
 * already completed.  it is safe to call this within the callback
 * that is being cancelled.
 *
 * the combination of this func and adjust period may cause some confusion in
 * understanding the operation.  remember that adjust period can make a
 * callback appear to be a oneshot (if adjust period is passed a null period,
 * is_periodic will become false)... 
 */

globus_result_t
globus_callback_unregister(
    globus_callback_handle_t            callback_handle,
    globus_callback_func_t              unregister_callback,
    void *                              unreg_args,
    globus_bool_t *                     active)
{
    globus_l_callback_info_t *          callback_info;
    
    globus_mutex_lock(&globus_l_callback_handle_lock);
    {
        callback_info = (globus_l_callback_info_t *)
            globus_handle_table_lookup(
                &globus_l_callback_handle_table, callback_handle);
    }
    globus_mutex_unlock(&globus_l_callback_handle_lock);

    if(!callback_info)
    {
        /* this is definitely an error,
         * if user had the handle and didnt destroy it (or cancel it),
         * it has to exist
         */
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_CALLBACK_HANDLE(
            "globus_callback_unregister");
    }
    
    globus_mutex_lock(&callback_info->my_space->lock);
   
    /* this doesnt catch a previously unregistered callback that passed a
     * NULL unregister -- bad things may happen in that case
     */
    if(callback_info->unregister_callback)
    {
        globus_mutex_unlock(&callback_info->my_space->lock);
        
        return GLOBUS_L_CALLBACK_CONSTRUCT_ALREADY_CANCELED(
            "globus_callback_unregister");
    }
    
    callback_info->unregister_callback = unregister_callback;
    callback_info->unreg_args = unreg_args;

    if(callback_info->running_count > 0)
    {
        if(callback_info->is_periodic)
        {
            /* would only be in queue if it was restarted */
            if(callback_info->in_queue == GLOBUS_L_CALLBACK_QUEUE_TIMED)
            {
                globus_priority_q_remove(
                    &callback_info->my_space->timed_queue, callback_info);
            }
            else if(callback_info->in_queue == GLOBUS_L_CALLBACK_QUEUE_READY)
            {
                GlobusICallbackReadyRemove(
                    &callback_info->my_space->ready_queue, callback_info);
            }
            
            callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_NONE;
            callback_info->is_periodic = GLOBUS_FALSE;
        }
        
        globus_mutex_unlock(&callback_info->my_space->lock);
    
        /* unregister callback will get called when running_count == 0 */
        
        /* this decrements the user's reference */
        globus_l_callback_info_dec_ref(callback_handle);
        
        if(active)
        {
            *active = GLOBUS_TRUE;
        }
        
        return GLOBUS_SUCCESS;
    }
    else
    {
        /*
         * if the callback_info is not in the queue, it can only mean
         * that it has been suspended (by adjust_period) or it was a oneshot.
         * In this case, I would have already decremented the ref once.  I'll
         * let the globus_l_callback_cancel_kickout_cb decr the last ref
         */
        if(callback_info->in_queue)
        {
            if(callback_info->in_queue == GLOBUS_L_CALLBACK_QUEUE_TIMED)
            {
                globus_priority_q_remove(
                    &callback_info->my_space->timed_queue, callback_info);
            }
            else if(callback_info->in_queue == GLOBUS_L_CALLBACK_QUEUE_READY)
            {
                GlobusICallbackReadyRemove(
                    &callback_info->my_space->ready_queue, callback_info);
            }
            
            callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_NONE;
            
            /* it is safe to do this with space's lock because there must be
             * at least two refs left
             */
            globus_l_callback_info_dec_ref(callback_handle);
        }
        
        globus_mutex_unlock(&callback_info->my_space->lock);
        
        if(unregister_callback)
        {
            globus_callback_space_register_oneshot(
                GLOBUS_NULL,
                GLOBUS_NULL,
                globus_l_callback_cancel_kickout_cb,
                callback_info,
                callback_info->my_space->handle);
        }
        else
        {
            /* not kicking one out, so decr last ref */
            globus_l_callback_info_dec_ref(callback_handle);
        }
        
        if(active)
        {
            *active = GLOBUS_FALSE;
        }
        
        return GLOBUS_SUCCESS;
    }
}

/**
 * globus_callback_adjust_period
 *
 * external function to allow a user to adjust the period of a previously
 * registered callback.  it is safe to call this within or outside of
 * the callback that is being modified.
 *
 * this func also allows a user to 'suspend' a periodic callback till another
 * time by passing a period of globus_i_reltime_infinity.  the callback can
 * be resumed by passing in a new period at some other time.
 *
 * this function could cause confusion in understanding this code.  When a
 * periodic is suspended, it 'becomes' non-periodic (ie, is_periodic is set to
 * false)
 */

globus_result_t
globus_callback_adjust_period(
    globus_callback_handle_t            callback_handle,
    const globus_reltime_t *            new_period)
{
    globus_l_callback_info_t *          callback_info;

    globus_mutex_lock(&globus_l_callback_handle_lock);
    {
        callback_info = (globus_l_callback_info_t *)
            globus_handle_table_lookup(
                &globus_l_callback_handle_table, callback_handle);
    }
    globus_mutex_unlock(&globus_l_callback_handle_lock);

    if(!callback_info)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_CALLBACK_HANDLE(
            "globus_callback_adjust_period");
    }
    
    globus_mutex_lock(&callback_info->my_space->lock);
    
    /* this doesnt catch a previously unregistered callback that passed a
     * NULL unregister -- bad things may happen in that case
     */
    if(callback_info->unregister_callback)
    {
        globus_mutex_unlock(&callback_info->my_space->lock);
        
        return GLOBUS_L_CALLBACK_CONSTRUCT_ALREADY_CANCELED(
            "globus_callback_adjust_period");
    }
    
    if(!new_period || globus_time_reltime_is_infinity(new_period))
    {
        /* doing this will cause this not to be requeued if currently running
         */
        callback_info->is_periodic = GLOBUS_FALSE;

        /* may or may not be in queue depending on if its not running or its
         * been restarted.  if its not in queue, no problem... it wont get
         * queued again
         */
        if(callback_info->in_queue)
        {
            if(callback_info->in_queue == GLOBUS_L_CALLBACK_QUEUE_TIMED)
            {
                globus_priority_q_remove(
                    &callback_info->my_space->timed_queue, callback_info);
            }
            else if(callback_info->in_queue == GLOBUS_L_CALLBACK_QUEUE_READY)
            {
                GlobusICallbackReadyRemove(
                    &callback_info->my_space->ready_queue, callback_info);
            }
            
            if(callback_info->running_count == 0)
            {
                /* decr my reference to this since I dont 
                 * have control of it anymore  -- this is safe to do within space's
                 * lock since user still holds one ref
                 */
                globus_l_callback_info_dec_ref(callback_handle);
            }
                    
            callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_NONE;
        }
    }
    else
    {
        callback_info->is_periodic = GLOBUS_TRUE;
        GlobusTimeReltimeCopy(callback_info->period, *new_period);
        
        if(globus_reltime_cmp(new_period, &globus_i_reltime_zero) > 0)
        {
            if(callback_info->in_queue || callback_info->running_count == 0)
            {
                GlobusTimeAbstimeGetCurrent(callback_info->start_time);
                GlobusTimeAbstimeInc(callback_info->start_time, *new_period);
            }
            
           /* may or may not be in queue depending on if its not running or its
            * been restarted.  if its not in queue and its running, no problem...
            * when it gets requeued it will be with the new priority
            */
            if(callback_info->in_queue == GLOBUS_L_CALLBACK_QUEUE_TIMED)
            {
                globus_priority_q_modify(
                    &callback_info->my_space->timed_queue,
                    callback_info,
                    &callback_info->start_time);
            }
            else if(callback_info->in_queue == GLOBUS_L_CALLBACK_QUEUE_READY)
            {
                GlobusICallbackReadyRemove(
                    &callback_info->my_space->ready_queue, callback_info);
                
                callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_TIMED;
                
                globus_priority_q_enqueue(
                    &callback_info->my_space->timed_queue,
                    callback_info,
                    &callback_info->start_time);
            }
            else if(callback_info->running_count == 0)
            {
                /* it wasnt in the queue and its not running...  we must have
                 * previously set this non-periodic... I need to requeue it
                 * and take my ref to it back
                 */
                callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_TIMED;
                
                globus_priority_q_enqueue(
                    &callback_info->my_space->timed_queue,
                    callback_info,
                    &callback_info->start_time);
            
                globus_mutex_lock(&globus_l_callback_handle_lock);
                {
                    globus_handle_table_increment_reference(
                        &globus_l_callback_handle_table, callback_handle);
                }
                globus_mutex_unlock(&globus_l_callback_handle_lock);
            }
        }
        else if(callback_info->in_queue != GLOBUS_L_CALLBACK_QUEUE_READY)
        {
            /* may or may not be in queue depending on if its not running or its
             * been restarted.  if its not in queue and its running, no problem...
             * when it gets requeued it will be with the new priority
             */
            if(callback_info->in_queue == GLOBUS_L_CALLBACK_QUEUE_TIMED)
            {
                globus_priority_q_remove(
                    &callback_info->my_space->timed_queue, callback_info);
                
                callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_READY;
                
                GlobusICallbackReadyEnqueue(
                    &callback_info->my_space->ready_queue, callback_info);
            }
            else if(callback_info->running_count == 0)
            {
                /* it wasnt in the queue and its not running...  we must have
                 * previously set this non-periodic... I need to requeue it
                 * and take my ref to it back
                 */
                callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_READY;
                
                GlobusICallbackReadyEnqueue(
                    &callback_info->my_space->ready_queue, callback_info);
                    
                globus_mutex_lock(&globus_l_callback_handle_lock);
                {
                    globus_handle_table_increment_reference(
                        &globus_l_callback_handle_table, callback_handle);
                }
                globus_mutex_unlock(&globus_l_callback_handle_lock);
            }
        }
        
        /* wake up any sleeping threads to let them know about new work */
        if(callback_info->in_queue && callback_info->my_space->idle_count > 0)
        {
            globus_cond_signal(&callback_info->my_space->cond);
        }
    }
    
    globus_mutex_unlock(&callback_info->my_space->lock);

    return GLOBUS_SUCCESS;
}

/**
 * globus_callback_space_init
 *
 * -- attrs with a behavior of threaded simply use the global space
 *
 */

globus_result_t
globus_callback_space_init(
    globus_callback_space_t *           space,
    globus_callback_space_attr_t        attr)
{
    globus_l_callback_space_t *         i_space;
    globus_callback_space_behavior_t    behavior;

    if(!space)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_init", "space");
    }

    if(attr)
    {
        behavior = attr->behavior;
    }
    else
    {
        behavior = GLOBUS_CALLBACK_SPACE_BEHAVIOR_SINGLE;
    }
    
    if(behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_THREADED)
    {
        /* all threaded spaces use the global queue */
        *space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    }
    else
    {
        globus_mutex_lock(&globus_l_callback_space_lock);
        {
            i_space = (globus_l_callback_space_t *)
                globus_memory_pop_node(&globus_l_callback_space_memory);
            
            if(i_space)
            {
                i_space->handle = globus_handle_table_insert(
                    &globus_l_callback_space_table, i_space, 1);
            }
        }
        globus_mutex_unlock(&globus_l_callback_space_lock);
        
        if(!i_space)
        {
            return GLOBUS_L_CALLBACK_CONSTRUCT_MEMORY_ALLOC(
                "globus_callback_space_init", "i_space");
        }
        
        GlobusICallbackReadyInit(&i_space->ready_queue);
        globus_priority_q_init(
            &i_space->timed_queue,
            (globus_priority_q_cmp_func_t) globus_abstime_cmp);
        globus_mutex_init(&i_space->lock, GLOBUS_NULL);
        globus_cond_init(&i_space->cond, GLOBUS_NULL);
        i_space->behavior = behavior;
        i_space->shutdown = GLOBUS_FALSE;
        i_space->idle_count = 0;
        
        if(behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED)
        {
            i_space->thread_count = 1;
            
            globus_mutex_lock(&globus_l_callback_thread_lock);
            {
                if(!globus_l_callback_shutting_down)
                {
                    globus_l_callback_thread_count++;
                    globus_i_thread_start(
                        globus_l_callback_thread_poll,
                        i_space);
                
                    globus_list_insert(
                        &globus_l_callback_threaded_spaces, i_space);
                }
            }
            globus_mutex_unlock(&globus_l_callback_thread_lock);
        }
        else
        {
            /* this is used as a depth indicator for single spaces */
            i_space->thread_count = 0;
        }
        
        *space = i_space->handle;
    }
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_callback_space_reference(
    globus_callback_space_t             space)
{
    globus_bool_t                       in_table;
    
    if(space == GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        return GLOBUS_SUCCESS;
    }
    
    globus_mutex_lock(&globus_l_callback_space_lock);
    {
        in_table = globus_handle_table_increment_reference(
            &globus_l_callback_space_table, space);
    }
    globus_mutex_unlock(&globus_l_callback_space_lock);

    if(!in_table)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_SPACE(
            "globus_callback_space_reference");
    }

    return GLOBUS_SUCCESS;
}

/**
 * globus_callback_space_destroy
 *
 * while it does not make sense to do so, this can be called while there are
 * still pending callbacks within this space.  The space will not really be
 * destroyed untill all callbacks referencing it are destroyed.
 */

globus_result_t
globus_callback_space_destroy(
    globus_callback_space_t             space)
{
    globus_l_callback_space_t *         i_space;
    
    if(space == GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        return GLOBUS_SUCCESS;
    }
    
    globus_mutex_lock(&globus_l_callback_space_lock);
    {
        i_space = (globus_l_callback_space_t *)
            globus_handle_table_lookup(
                &globus_l_callback_space_table, space);
        
        if(i_space)
        {
            globus_handle_table_decrement_reference(
                &globus_l_callback_space_table, space);
        }
    }
    globus_mutex_unlock(&globus_l_callback_space_lock);

    if(!i_space)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_SPACE(
            "globus_callback_space_destroy");
    }
    
    return GLOBUS_SUCCESS;
}

/**
 * initialze and attr with default of single threaded behavior
 */
globus_result_t
globus_callback_space_attr_init(
    globus_callback_space_attr_t *      attr)
{
    globus_l_callback_space_attr_t *    i_attr;
    
    if(!attr)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_attr_init", "attr");
    }
    
    globus_mutex_lock(&globus_l_callback_space_lock);
    {
        i_attr = (globus_l_callback_space_attr_t *)
            globus_memory_pop_node(&globus_l_callback_space_attr_memory);
    }
    globus_mutex_unlock(&globus_l_callback_space_lock);
    
    if(!i_attr)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_MEMORY_ALLOC(
            "globus_callback_space_attr_init", "i_attr");
    }
    
    i_attr->behavior = GLOBUS_CALLBACK_SPACE_BEHAVIOR_SINGLE;
    
    *attr = i_attr;
        
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_callback_space_attr_destroy(
    globus_callback_space_attr_t        attr)
{
    if(!attr)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_attr_destroy", "attr");
    }
    
    globus_mutex_lock(&globus_l_callback_space_lock);
    {
        globus_memory_push_node(&globus_l_callback_space_attr_memory, attr);
    }
    globus_mutex_unlock(&globus_l_callback_space_lock);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_callback_space_attr_set_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t    behavior)
{
    if(!attr)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_attr_set_behavior", "attr");
    }
    
    if(!(behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SINGLE ||
        behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED ||
        behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_THREADED))
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_attr_set_behavior", "behavior");
    }
    
    attr->behavior = behavior;
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_callback_space_attr_get_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t *  behavior)
{
    if(!attr)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_attr_get_behavior", "attr");
    }
    
    if(!behavior)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_attr_get_behavior", "behavior");
    }
    
    *behavior = attr->behavior;
    
    return GLOBUS_SUCCESS;
}

/**
 * globus_l_callback_get_next
 *
 * check queue for ready entry, pass back next ready time if no callback ready
 * else return callback info.
 *
 * space should be locked before this call
 */

static
globus_l_callback_info_t *
globus_l_callback_get_next(
    globus_l_callback_space_t *         i_space,
    const globus_abstime_t *            time_now,
    globus_abstime_t *                  ready_time)
{
    const globus_abstime_t *            tmp_time;
    globus_l_callback_info_t *          callback_info;

    /* first check to see if anything in the timed queue is ready */
    tmp_time = (globus_abstime_t *)
        globus_priority_q_first_priority(&i_space->timed_queue);
    if(tmp_time)
    {
        globus_abstime_t                    l_time_now;
        
        if(!time_now)
        {
            GlobusTimeAbstimeGetCurrent(l_time_now);
            time_now = &l_time_now;
        }
        
        while(tmp_time && globus_abstime_cmp(tmp_time, time_now) <= 0)
        {
            callback_info = (globus_l_callback_info_t *)
                globus_priority_q_dequeue(&i_space->timed_queue);
            
            callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_READY;
            
            GlobusICallbackReadyEnqueue(&i_space->ready_queue, callback_info);
                    
            tmp_time = (globus_abstime_t *)
                globus_priority_q_first_priority(&i_space->timed_queue);
        }
    }

    GlobusICallbackReadyDequeue(&i_space->ready_queue, callback_info);

    if(callback_info)
    {
        callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_NONE;
    }
    else if(tmp_time)
    {
        GlobusTimeAbstimeCopy(*ready_time, *tmp_time);
    }
    else
    {
        GlobusTimeAbstimeCopy(*ready_time, globus_i_abstime_infinity);
    }
            
    return callback_info;
}

/**
 * globus_l_callback_requeue
 *
 * Called by globus_l_callback_blocked_cb, globus_callback_space_poll, and
 * globus_callback_adjust_period. Used to requeue a periodic callback after it
 * has blocked or completed
 *
 * space should be locked before this call
 */

static
void
globus_l_callback_requeue(
    globus_l_callback_info_t *          callback_info,
    const globus_abstime_t *            time_now)
{
    globus_bool_t                       ready;
    globus_l_callback_space_t *         i_space;
    const globus_abstime_t *            tmp_time;
    globus_abstime_t                    l_time_now;
    
    ready = GLOBUS_TRUE;
    i_space = callback_info->my_space;
    
    /* first check to see if anything in the timed queue is ready */
    tmp_time = (globus_abstime_t *)
        globus_priority_q_first_priority(&i_space->timed_queue);
    if(tmp_time)
    {
        if(!time_now)
        {
            GlobusTimeAbstimeGetCurrent(l_time_now);
            time_now = &l_time_now;
        }
        
        while(tmp_time && globus_abstime_cmp(tmp_time, time_now) <= 0)
        {
            globus_l_callback_info_t *          ready_info;
            
            ready_info = (globus_l_callback_info_t *)
                globus_priority_q_dequeue(&i_space->timed_queue);
            
            ready_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_READY;
            
            GlobusICallbackReadyEnqueue(&i_space->ready_queue, ready_info);
                    
            tmp_time = (globus_abstime_t *)
                globus_priority_q_first_priority(&i_space->timed_queue);
        }
    }
    
    /* see if this is going in the priority q */
    if(globus_reltime_cmp(&callback_info->period, &globus_i_reltime_zero) > 0)
    {
        if(!time_now)
        {
            GlobusTimeAbstimeGetCurrent(l_time_now);
            time_now = &l_time_now;
        }
        
        GlobusTimeAbstimeInc(callback_info->start_time, callback_info->period);
    
        if(globus_abstime_cmp(time_now, &callback_info->start_time) < 0)
        {
            ready = GLOBUS_FALSE;
            callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_TIMED;
            
            globus_priority_q_enqueue(
                &i_space->timed_queue,
                callback_info,
                &callback_info->start_time);
        }
    }
    
    if(ready)
    {
        callback_info->in_queue = GLOBUS_L_CALLBACK_QUEUE_READY;
        
        GlobusICallbackReadyEnqueue(&i_space->ready_queue, callback_info);
    }
    
    if(i_space->idle_count > 0)
    {
        globus_cond_signal(&i_space->cond);
    }
}

/**
 * globus_l_callback_blocked_cb
 *
 * This call is registered with globus_thread_blocking_callback_push.  It is
 * called when a user calls globus_thread_blocking_will_block/globus_cond_wait
 *
 * When called, this function will requeue a periodic callback iff .
 * globus_thread_blocking_will_block/globus_cond_wait was called on that
 * callbacks 'space' or if that callback belongs to the global space
 */

static
void
globus_l_callback_blocked_cb(
    globus_thread_callback_index_t      index,
    globus_callback_space_t             space,
    void *                              user_args)
{
    globus_l_callback_restart_info_t *  restart_info;
    
    restart_info = (globus_l_callback_restart_info_t *) user_args;
    
    if(restart_info && !restart_info->restarted)
    {
        globus_l_callback_info_t *      callback_info;

        callback_info = restart_info->callback_info;

        if(callback_info->my_space->handle == GLOBUS_CALLBACK_GLOBAL_SPACE ||
            callback_info->my_space->handle == space)
        {
            globus_mutex_lock(&callback_info->my_space->lock);
            {
                if(callback_info->is_periodic)
                {
                    globus_l_callback_requeue(callback_info, GLOBUS_NULL);
                }
            }
            globus_mutex_unlock(&callback_info->my_space->lock);

            restart_info->restarted = GLOBUS_TRUE;
            
            if(restart_info->create_thread)
            {
                globus_mutex_lock(&globus_l_callback_thread_lock);
                {
                    if(!globus_l_callback_shutting_down)
                    {
                        callback_info->my_space->thread_count++;
                        globus_l_callback_thread_count++;
                        
                        globus_i_thread_start(
                            globus_l_callback_thread_poll,
                            callback_info->my_space);
                    }
                } 
                globus_mutex_unlock(&globus_l_callback_thread_lock);
            }
        }
    }
}

static
void
globus_l_callback_finish_callback(
    globus_l_callback_info_t *          callback_info,
    globus_bool_t                       restarted,
    const globus_abstime_t *            time_now,
    globus_bool_t *                     ready_oneshot)
{
    globus_l_callback_space_t *         i_space;
    globus_bool_t                       unregister;
    globus_callback_func_t              unregister_callback;
    
    i_space = callback_info->my_space;
    unregister = GLOBUS_FALSE;
    
    globus_mutex_lock(&i_space->lock);
    {
        /* this was incremented after the 'get_next' call */
        callback_info->running_count--;

        /* a periodic that was canceled has is_periodic == false */
        if(!callback_info->is_periodic &&
            callback_info->running_count == 0)
        {
            unregister_callback = callback_info->unregister_callback;
            unregister = GLOBUS_TRUE;
        }
        else if(callback_info->is_periodic && !restarted)
        {
            globus_l_callback_requeue(callback_info, time_now);
        }
        
        if(ready_oneshot)
        {
            globus_l_callback_info_t *  peek;
            
            GlobusICallbackReadyPeak(&i_space->ready_queue, peek);
            if(peek && !peek->is_periodic)
            {
                *ready_oneshot = GLOBUS_TRUE;
            }
            else
            {
                *ready_oneshot = GLOBUS_FALSE;
            }
        }
    }
    globus_mutex_unlock(&i_space->lock);
    
    if(unregister)
    {
        if(unregister_callback)
        {
            globus_callback_space_register_oneshot(
                GLOBUS_NULL,
                &globus_i_reltime_zero,
                globus_l_callback_cancel_kickout_cb,
                callback_info,
                i_space->handle);
        }
        else
        {
            /* no unreg callback so I'll decrement my ref */
            globus_l_callback_info_dec_ref(callback_info->handle);
        }
    }
}

/**
 * globus_callback_space_poll
 *
 * external function to poll for callbacks.  will poll at least the passed
 * space.  may also poll global 'space'
 *
 */

void
globus_callback_space_poll(
    const globus_abstime_t *            timestop,
    globus_callback_space_t             space)
{
    globus_bool_t                       done;
    globus_abstime_t                    time_now;
    globus_l_callback_restart_info_t *  last_restart_info;
    globus_l_callback_restart_info_t    restart_info;
    globus_abstime_t                    l_timestop;
    globus_l_callback_space_t *         i_space;
    globus_thread_callback_index_t      restart_index;
    globus_bool_t                       yield;
    int                                 post_stop_counter;
    
    if(space == GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        globus_thread_yield();
        return;
    }
    
    globus_mutex_lock(&globus_l_callback_space_lock);
    {
        i_space = (globus_l_callback_space_t *)
            globus_handle_table_lookup(
                &globus_l_callback_space_table, space);
    }
    globus_mutex_unlock(&globus_l_callback_space_lock);
    
    if(!i_space || i_space->behavior != GLOBUS_CALLBACK_SPACE_BEHAVIOR_SINGLE)
    {
        globus_thread_yield();
        return;
    }        
        
    last_restart_info = (globus_l_callback_restart_info_t *)
        globus_thread_getspecific(globus_l_callback_restart_info_key);
    globus_thread_setspecific(
        globus_l_callback_restart_info_key, &restart_info);
    
    globus_thread_blocking_callback_push(
        globus_l_callback_blocked_cb,
        &restart_info,
        &restart_index);
    
    globus_thread_blocking_callback_disable(&restart_index);
    
    if(!timestop)
    {
        GlobusTimeAbstimeCopy(l_timestop, globus_i_abstime_zero);
        timestop = &l_timestop;
    }
    
    /*
     * If we get signaled, we will jump out of this function asap
     */
    restart_info.signaled = GLOBUS_FALSE;
    restart_info.create_thread = GLOBUS_FALSE;
    restart_info.own_thread = GLOBUS_FALSE;
    restart_info.time_stop = timestop;

    GlobusTimeAbstimeGetCurrent(time_now);
    
    done = GLOBUS_FALSE;
    yield = GLOBUS_TRUE;
    post_stop_counter = GLOBUS_L_CALLBACK_POST_STOP_ONESHOTS;
    
    globus_mutex_lock(&i_space->lock);
    i_space->thread_count++;
    
    do
    {
        globus_l_callback_info_t *      callback_info;
        globus_abstime_t                next_ready_time;
        globus_bool_t                   ready_oneshot;
        
        callback_info = globus_l_callback_get_next(
            i_space, &time_now, &next_ready_time);
        
        if(callback_info)
        {
            yield = GLOBUS_FALSE;
            callback_info->running_count++;
            
            globus_mutex_unlock(&i_space->lock);
            
            restart_info.restarted = GLOBUS_FALSE;
            restart_info.callback_info = callback_info;
            
            globus_thread_blocking_callback_enable(&restart_index);
            
            callback_info->callback_func(callback_info->callback_args);
            
            globus_thread_blocking_callback_disable(&restart_index);
            
            GlobusTimeAbstimeGetCurrent(time_now);
            
            globus_l_callback_finish_callback(
                callback_info,
                restart_info.restarted, 
                &time_now,
                &ready_oneshot);
            
            done = restart_info.signaled;
            if(!done && globus_abstime_cmp(timestop, &time_now) <= 0)
            {
                /* time has expired, but we'll call up to 
                 * GLOBUS_L_CALLBACK_POST_STOP_ONESHOTS oneshots
                 * that are ready to go
                 */
                if(!ready_oneshot || post_stop_counter-- == 0)
                {
                    done = GLOBUS_TRUE;
                }
            }
            
            globus_mutex_lock(&i_space->lock);
        }
        else
        {
            /* no callbacks were ready */
            if(globus_abstime_cmp(timestop, &next_ready_time) > 0)
            {
                /* I dont think it matters that I dont check the shutdown
                 * after sleeping... the poll is either called from
                 * one of my threads (blocking it) or it is called from
                 * the main threadm in which case, he shouldnt be calling
                 * for a shutdown
                 */
                i_space->idle_count++;
                globus_cond_timedwait(
                    &i_space->cond, &i_space->lock, &next_ready_time);
                i_space->idle_count--;
                yield = GLOBUS_FALSE;
            }
            else if(globus_time_abstime_is_infinity(timestop))
            {
                /* we can only get here if queue is empty
                 * and we are blocking forever. 
                 */
                i_space->idle_count++;
                globus_cond_wait(&i_space->cond, &i_space->lock);
                i_space->idle_count--;
                yield = GLOBUS_FALSE;
            }
            else
            {
                /* wont be any ready before our time is up */
                done = GLOBUS_TRUE;
            }
                
            if(!done)
            {
                GlobusTimeAbstimeGetCurrent(time_now);
                if(globus_abstime_cmp(timestop, &time_now) <= 0)
                {
                    done = GLOBUS_TRUE;
                }
            }
        }
    } while(!done);
    
    i_space->thread_count--;
    globus_mutex_unlock(&i_space->lock);
    /*
     * If I was signaled, I need to pass that signal on to my parent poller
     * because I cant be sure that the signal was just for me
     */
    if(last_restart_info && restart_info.signaled)
    {
        last_restart_info->signaled = GLOBUS_TRUE;
    }
    
    globus_thread_setspecific(
        globus_l_callback_restart_info_key, last_restart_info);
        
    globus_thread_blocking_callback_pop(&restart_index);
    
    if(yield)
    {
        /* nothing was accomplished, so yield to prevent spinning */
        globus_thread_yield();
    }
}

void
globus_callback_signal_poll()
{
    globus_l_callback_restart_info_t *  restart_info;
    
    restart_info = (globus_l_callback_restart_info_t *)
        globus_thread_getspecific(globus_l_callback_restart_info_key);
        
    if(restart_info)
    {
        restart_info->signaled = GLOBUS_TRUE;
    }
}

/*
 * function for callbacks that get their own thread
 */
static
void *
globus_l_callback_thread_callback(
    void *                              user_args)
{
    globus_l_callback_info_t *          callback_info;
    globus_abstime_t                    time_now;
    globus_l_callback_restart_info_t    restart_info;
    globus_thread_callback_index_t      restart_index;
    globus_bool_t                       run_now;
    globus_l_callback_space_t *         i_space;
    
    callback_info = (globus_l_callback_info_t *) user_args;
    i_space = callback_info->my_space;
    
    /* if this thread is restarted, the periodic will just get requeued and
     * an new thread may be created by one of the pollers
     */
    restart_info.restarted = GLOBUS_FALSE;
    restart_info.create_thread = GLOBUS_FALSE;
    restart_info.own_thread = GLOBUS_TRUE;
    restart_info.time_stop = &globus_i_abstime_infinity;
    restart_info.callback_info = callback_info;
    
    globus_thread_setspecific(
        globus_l_callback_restart_info_key, &restart_info);

    globus_thread_blocking_callback_push(
        globus_l_callback_blocked_cb,
        &restart_info,
        &restart_index);
    
    do
    {
        callback_info->callback_func(callback_info->callback_args);
        
        globus_thread_yield();
        
        run_now = GLOBUS_FALSE;
        
        globus_thread_blocking_callback_disable(&restart_index);
        
        globus_mutex_lock(&i_space->lock);
        {
            /* just check whats necessary to rerun this callback */
            if(!restart_info.restarted &&
                callback_info->is_periodic &&
                globus_reltime_cmp(
                    &callback_info->period,
                    &globus_l_callback_own_thread_period) <= 0)
            {
                /* period is still small enough to keep him in his own 
                 * thread. gotta figure out if I should sleep or run again
                 */
                
                if(!i_space->shutdown)
                {
                    if(globus_reltime_cmp(
                        &callback_info->period, &globus_i_reltime_zero) > 0)
                    {
                        GlobusTimeAbstimeGetCurrent(time_now);
                        GlobusTimeAbstimeInc(
                            callback_info->start_time, callback_info->period);

                        if(globus_abstime_cmp(
                            &time_now, &callback_info->start_time) < 0)
                        {
                            do
                            {
                                i_space->idle_count++;
                                globus_cond_timedwait(
                                    &i_space->cond,
                                    &i_space->lock,
                                    &callback_info->start_time);
                                i_space->idle_count--;
                                
                                GlobusTimeAbstimeGetCurrent(time_now);
                                
                            } while(globus_abstime_cmp(
                                &time_now, &callback_info->start_time) < 0 &&
                                !i_space->shutdown);
                            
                            /* lost mutex, need to make sure wasnt unregistered */
                            if(!i_space->shutdown &&
                                callback_info->is_periodic &&
                                globus_reltime_cmp(
                                    &callback_info->period,
                                    &globus_l_callback_own_thread_period) <= 0)
                            {
                                run_now = GLOBUS_TRUE;
                            }
                        }
                        else
                        {
                            run_now = GLOBUS_TRUE;
                        }
                    }
                    else
                    {
                        run_now = GLOBUS_TRUE;
                    }
                }
            }
        }
        globus_mutex_unlock(&i_space->lock);
        
        globus_thread_blocking_callback_enable(&restart_index);
        
    } while(run_now);
    
    globus_l_callback_finish_callback(
        callback_info, restart_info.restarted, GLOBUS_NULL, GLOBUS_NULL);    
    
    globus_thread_blocking_reset();
    
    globus_thread_setspecific(
        globus_l_callback_restart_info_key, GLOBUS_NULL);
        
    /* this thread is exiting */
    globus_mutex_lock(&globus_l_callback_thread_lock);
    {
        globus_l_callback_thread_count--;
        if(globus_l_callback_thread_count == 0)
        {
            globus_cond_signal(&globus_l_callback_thread_cond);
        } 
    }
    globus_mutex_unlock(&globus_l_callback_thread_lock);
    
    return GLOBUS_NULL;
}

static
void
globus_l_callback_serialized_cleanup(
    globus_l_callback_space_t *         i_space,
    globus_bool_t                       restarted)
{
    if(restarted)
    {
        globus_mutex_lock(&i_space->lock);
        {
            i_space->thread_count--;
            if(i_space->thread_count == 0)
            {
                globus_cond_signal(&i_space->cond);
            }
        }
        globus_mutex_unlock(&i_space->lock);
    }
    else
    {
        globus_bool_t                   free_space;
        
        free_space = GLOBUS_FALSE;
        
        globus_mutex_lock(&globus_l_callback_thread_lock);
        {
            if(!globus_l_callback_shutting_down)
            {
                /* space was shutdown... clean up */
                /* I dont clean up the space in the case of module shutdown
                 * since there may be some references to this space.  When 
                 * the space handle table is destroyed, the destructor for
                 * this space will clean up the resources
                 */
                free_space = GLOBUS_TRUE;
            }
        }
        globus_mutex_unlock(&globus_l_callback_thread_lock);
        
        if(free_space)
        {
            /* wait for all the threads that might be in blocked callbacks
             * to exit
             */
            globus_mutex_lock(&i_space->lock);
            {
                i_space->thread_count--;
                while(i_space->thread_count > 0)
                {
                    globus_cond_wait(&i_space->cond, &i_space->lock);
                }
            }
            globus_mutex_unlock(&i_space->lock);
        
            globus_priority_q_destroy(&i_space->timed_queue);
            globus_mutex_destroy(&i_space->lock);
            globus_cond_destroy(&i_space->cond);
                
            globus_mutex_lock(&globus_l_callback_space_lock);
            {
                globus_memory_push_node(
                    &globus_l_callback_space_memory, i_space);
            }
            globus_mutex_unlock(&globus_l_callback_space_lock);
        }
    }
}

/* internal polling function 
 * all threads except for dedicated ones start here
 */
static
void *
globus_l_callback_thread_poll(
    void *                              user_args)
{
    globus_bool_t                       done;
    globus_l_callback_info_t *          callback_info;
    globus_abstime_t                    next_ready_time;
    globus_l_callback_restart_info_t    restart_info;
    globus_thread_callback_index_t      restart_index;
    globus_bool_t                       gets_own_thread;
    globus_l_callback_space_t *         i_space;
    
    i_space = (globus_l_callback_space_t *) user_args;
    /* if this thread is ever restarted, its going to terminate, since
     * it knows a new thread was started as a result of the restart
     */
    restart_info.restarted = GLOBUS_FALSE;
    restart_info.create_thread = GLOBUS_TRUE;
    restart_info.own_thread = GLOBUS_FALSE;
    restart_info.time_stop = &globus_i_abstime_infinity;
    globus_thread_setspecific(
        globus_l_callback_restart_info_key, &restart_info);

    globus_thread_blocking_callback_push(
        globus_l_callback_blocked_cb,
        &restart_info,
        &restart_index);
                
    done = GLOBUS_FALSE;
    
    do
    {
        callback_info = GLOBUS_NULL;
        
        globus_thread_blocking_callback_disable(&restart_index);
        
        globus_mutex_lock(&i_space->lock);
        {
            while(!i_space->shutdown && !callback_info)
            {
                GlobusICallbackReadyPeak(&i_space->ready_queue, callback_info);
                
                if(!callback_info &&
                    globus_priority_q_empty(&i_space->timed_queue))
                {
                    i_space->idle_count++;
                    globus_cond_wait(&i_space->cond, &i_space->lock);
                    i_space->idle_count--;
                }
                else
                {
                    callback_info = globus_l_callback_get_next(
                        i_space, GLOBUS_NULL, &next_ready_time);
                        
                    if(callback_info)
                    {
                        callback_info->running_count++;
                        gets_own_thread = GLOBUS_FALSE;
                        if(callback_info->is_periodic &&
                            globus_reltime_cmp(
                                &callback_info->period,
                                &globus_l_callback_own_thread_period) <= 0
                            && i_space->behavior !=
                                GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED)
                        {
                            gets_own_thread = GLOBUS_TRUE;
                        }
                    }
                    else
                    {
                        i_space->idle_count++;
                        globus_cond_timedwait(
                            &i_space->cond,
                            &i_space->lock,
                            &next_ready_time);
                        i_space->idle_count--;
                    }
                }
            }
            
            /* logic of loop above insures that it is
             * impossible to have a callback when shutdown is true.  We
             * leave it as an exercise for the reader to prove this.
             */
        }
        globus_mutex_unlock(&i_space->lock);
        
        if(callback_info)
        {
            /* if function does not have its own thread */
            if(!gets_own_thread)
            {
                restart_info.callback_info = callback_info;
                
                globus_thread_blocking_callback_enable(&restart_index);
                
                callback_info->callback_func(callback_info->callback_args);

                globus_l_callback_finish_callback(
                    callback_info,
                    restart_info.restarted,
                    GLOBUS_NULL,
                    GLOBUS_NULL);

                /* if I was restarted, a new thread has taken my place */
                done = restart_info.restarted;
            }
            /* small period, so he gets his own thread */
            else
            {
                globus_mutex_lock(&globus_l_callback_thread_lock);
                {
                    if(!globus_l_callback_shutting_down)
                    {
                        globus_l_callback_thread_count++;
                        globus_i_thread_start(
                            globus_l_callback_thread_callback,
                            callback_info);
                    }
                } 
                globus_mutex_unlock(&globus_l_callback_thread_lock);
            }
        }
        else
        {
            done = GLOBUS_TRUE;
        }
    } while(!done);
    
    globus_thread_blocking_reset();
    
    if(i_space->behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED)
    {
        globus_l_callback_serialized_cleanup(i_space, restart_info.restarted);
    }
    
    globus_thread_setspecific(
        globus_l_callback_restart_info_key, GLOBUS_NULL);
        
    /* this thread is exiting */
    globus_mutex_lock(&globus_l_callback_thread_lock);
    {
        globus_l_callback_thread_count--;
        if(globus_l_callback_thread_count == 0)
        {
            globus_cond_signal(&globus_l_callback_thread_cond);
        } 
    }
    globus_mutex_unlock(&globus_l_callback_thread_lock);
    
    return GLOBUS_NULL;
}

/**
 * globus_callback_space_get
 *
 * allow a user to get the current space from within a callback
 */
globus_result_t
globus_callback_space_get(
    globus_callback_space_t *           space)
{
    globus_l_callback_restart_info_t *  restart_info;
    
    if(!space)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_get", "space");
    }
    
    restart_info = (globus_l_callback_restart_info_t *)
        globus_thread_getspecific(globus_l_callback_restart_info_key);
        
    if(!restart_info)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_NO_ACTIVE_CALLBACK(
            "globus_callback_space_get");
    }
    
    *space = restart_info->callback_info->my_space->handle;
    
    return GLOBUS_SUCCESS;
}

/**
 * globus_callback_space_get_depth
 *
 * allow a user to get the current nesting level of a space
 */
int
globus_callback_space_get_depth(
    globus_callback_space_t             space)
{
    globus_l_callback_space_t *         i_space;
    
    if(space == GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        return 0;
    }
    
    globus_mutex_lock(&globus_l_callback_space_lock);
    {
        i_space = (globus_l_callback_space_t *)
            globus_handle_table_lookup(
                &globus_l_callback_space_table, space);
    }
    globus_mutex_unlock(&globus_l_callback_space_lock);
    
    if(!i_space)
    {
        return 0;
    }
    
    return i_space->behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SINGLE
        ? i_space->thread_count
        : 0;
}
 
globus_bool_t
globus_callback_space_is_single(
    globus_callback_space_t             space)
{
    globus_l_callback_space_t *         i_space;
    
    if(space == GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        return GLOBUS_FALSE;
    }
    
    globus_mutex_lock(&globus_l_callback_space_lock);
    {
        i_space = (globus_l_callback_space_t *)
            globus_handle_table_lookup(
                &globus_l_callback_space_table, space);
    }
    globus_mutex_unlock(&globus_l_callback_space_lock);
    
    if(i_space && i_space->behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SINGLE)
    {
        return GLOBUS_TRUE;
    }
    else
    {
        return GLOBUS_FALSE;
    }
}

/**
 * globus_callback_get_timeout
 *
 * returns true if already timed out.. remaining time is in time_left
 */

globus_bool_t
globus_callback_get_timeout(
    globus_reltime_t *                  time_left)
{
    globus_l_callback_restart_info_t *  restart_info;
    globus_l_callback_space_t *         i_space;
    globus_l_callback_info_t *          peek;
    globus_bool_t                       timedout;
    
    restart_info = (globus_l_callback_restart_info_t *)
        globus_thread_getspecific(globus_l_callback_restart_info_key);
        
    if(!restart_info || restart_info->own_thread)
    {
        GlobusTimeReltimeCopy(*time_left, globus_i_reltime_infinity);

        return GLOBUS_FALSE;
    }
    
    timedout = GLOBUS_FALSE;
    i_space = restart_info->callback_info->my_space;
    
    globus_mutex_lock(&i_space->lock);
    
    GlobusICallbackReadyPeak(&i_space->ready_queue, peek);
       
    if(peek)
    {
        GlobusTimeReltimeCopy(*time_left, globus_i_reltime_zero);
        
        timedout = GLOBUS_TRUE;
    }
    else
    {
        globus_abstime_t                time_now;
        const globus_abstime_t *        earlier_time;
        
        earlier_time = (globus_abstime_t *)
            globus_priority_q_first_priority(&i_space->timed_queue);
        
        if(!earlier_time || 
            globus_abstime_cmp(earlier_time, restart_info->time_stop) > 0)
        {
            earlier_time = restart_info->time_stop;
        }
        
        GlobusTimeAbstimeGetCurrent(time_now);
        if(globus_abstime_cmp(&time_now, earlier_time) >= 0)
        {
            GlobusTimeReltimeCopy(*time_left, globus_i_reltime_zero);
    
            timedout = GLOBUS_TRUE;
        }
        else if(globus_time_abstime_is_infinity(earlier_time))
        {
            GlobusTimeReltimeCopy(*time_left, globus_i_reltime_infinity);
        }
        else
        {
            GlobusTimeAbstimeDiff(*time_left, time_now, *earlier_time);
        }
    }
    
    globus_mutex_unlock(&i_space->lock);
    
    return timedout;
}

globus_bool_t
globus_callback_has_time_expired()
{
    globus_reltime_t                    time_left;
    
    return globus_callback_get_timeout(&time_left);
}

globus_bool_t
globus_callback_was_restarted()
{
    globus_l_callback_restart_info_t *  restart_info;
    
    restart_info = (globus_l_callback_restart_info_t *)
        globus_thread_getspecific(globus_l_callback_restart_info_key);
        
    return restart_info
        ? restart_info->restarted
        : GLOBUS_FALSE;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
