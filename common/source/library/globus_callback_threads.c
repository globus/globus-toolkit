#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

#include "globus_common.h"
#include "globus_i_callback.h"

#define GLOBUS_CALLBACK_POLLING_THREADS 1
#define GLOBUS_L_CALLBACK_INFO_BLOCK_SIZE 256
#define GLOBUS_L_CALLBACK_SPACE_BLOCK_SIZE 32

/* any periodic with period (in the global space) smaller than this is 
 * going to get its own thread
 */
#define GLOBUS_L_CALLBACK_OWN_THREAD_PERIOD 5000   /* 5 ms */

extern pid_t                        globus_l_callback_main_thread;

static
int
globus_l_callback_activate();

static
int
globus_l_callback_deactivate();

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

typedef struct
{
    globus_callback_space_t             handle;
    globus_callback_space_behavior_t    behavior;
    globus_priority_q_t                 queue;
    globus_mutex_t                      lock;
    globus_cond_t                       cond;
    globus_bool_t                       shutdown;
    /* only used for serialized space shutdowns */
    int                                 thread_count; 
} globus_l_callback_space_t;

typedef struct globus_l_callback_space_attr_s
{
    globus_callback_space_behavior_t    behavior;
} globus_l_callback_space_attr_t;

typedef struct
{
    globus_callback_handle_t            handle;

    globus_callback_func_t              callback_func;
    void *                              callback_args;
    
    globus_abstime_t                    start_time;
    globus_reltime_t                    period;
    globus_bool_t                       is_periodic;
    globus_bool_t                       in_queue;

    int                                 running_count;

    globus_callback_func_t              unregister_callback;
    void *                              unreg_args;

    globus_l_callback_space_t *         my_space;
} globus_l_callback_info_t;

typedef struct
{
    globus_bool_t                       restarted;
    globus_bool_t                       signaled;
    globus_abstime_t *                  timeout;
    globus_l_callback_info_t *          callback_info;
    globus_bool_t                       create_thread;
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
        globus_priority_q_destroy(&i_space->queue);
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
    
    if(!globus_l_callback_main_thread)
    {
        /* this is used by globus_dump_stack because linux threads have
         * different pids (and gdb can only attach to the main thread
         */
        globus_l_callback_main_thread = getpid();
    }
    
    rc = globus_module_activate(GLOBUS_THREAD_MODULE);
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
    globus_priority_q_init(
        &globus_l_callback_global_space.queue,
        (globus_priority_q_cmp_func_t) globus_abstime_cmp);
    globus_mutex_init(&globus_l_callback_global_space.lock, GLOBUS_NULL);
    globus_cond_init(&globus_l_callback_global_space.cond, GLOBUS_NULL);
    globus_l_callback_global_space.shutdown = GLOBUS_FALSE;
    
    globus_list_insert(
        &globus_l_callback_threaded_spaces, &globus_l_callback_global_space);
    
    globus_mutex_init(&globus_l_callback_handle_lock, GLOBUS_NULL);
    globus_mutex_init(&globus_l_callback_space_lock, GLOBUS_NULL);

    globus_mutex_init(&globus_l_callback_thread_lock, GLOBUS_NULL);
    globus_cond_init(&globus_l_callback_thread_cond, GLOBUS_NULL);
    
    globus_thread_key_create(
        &globus_l_callback_restart_info_key, GLOBUS_NULL);
    globus_thread_setspecific(
        globus_l_callback_restart_info_key, GLOBUS_NULL);
    
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
        rc = globus_thread_create(
            GLOBUS_NULL,
            GLOBUS_NULL,
            globus_l_callback_thread_poll,
            &globus_l_callback_global_space);
        globus_assert(rc == 0);
    }
    
    return GLOBUS_SUCCESS;
}

static
int
globus_l_callback_deactivate()
{
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
    globus_priority_q_destroy(&globus_l_callback_global_space.queue);
    
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

    if(!callback_func)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_register_oneshot", "callback_func");
    }

    globus_mutex_lock(&globus_l_callback_handle_lock);
    {
        callback_info = (globus_l_callback_info_t *)
            globus_memory_pop_node(&globus_l_callback_info_memory);
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
            globus_mutex_lock(&globus_l_callback_handle_lock);
            {
                globus_memory_push_node(
                    &globus_l_callback_info_memory, callback_info);
            }
            globus_mutex_unlock(&globus_l_callback_handle_lock);
    
            return GLOBUS_L_CALLBACK_CONSTRUCT_MEMORY_ALLOC(
                "globus_l_callback_register", "i_space");
        }
    }
    
    callback_info->my_space = i_space;
    callback_info->callback_func = callback_func;
    callback_info->callback_args = callback_user_args;
    callback_info->running_count = 0;
    callback_info->unregister_callback = GLOBUS_NULL;
    callback_info->in_queue = GLOBUS_TRUE;

    GlobusTimeAbstimeCopy(callback_info->start_time, *start_time);
    if(period)
    {
        GlobusTimeReltimeCopy(callback_info->period, *period);
        callback_info->is_periodic = GLOBUS_TRUE;
    }
    else
    {
        callback_info->is_periodic = GLOBUS_FALSE;
    }

    globus_mutex_lock(&globus_l_callback_handle_lock);
    {
        if(callback_handle)
        {
            /* if user passed callback_handle, there are two refs to this
             * info, me and user.  User had better unregister this handle
             * to free up the memory
             */
            callback_info->handle = globus_handle_table_insert(
                &globus_l_callback_handle_table, callback_info, 2);
    
            *callback_handle = callback_info->handle;
        }
        else
        {
            callback_info->handle = globus_handle_table_insert(
                &globus_l_callback_handle_table, callback_info, 1);
        }
    }
    globus_mutex_unlock(&globus_l_callback_handle_lock);
    
    globus_mutex_lock(&i_space->lock);
    {
        globus_priority_q_enqueue(
            &i_space->queue,
            callback_info,
            &callback_info->start_time);
            
        globus_cond_signal(&i_space->cond);
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

    if(!delay_time)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_register_oneshot", "delay_time");
    }

    GlobusTimeAbstimeGetCurrent(start_time);
    GlobusTimeAbstimeInc(start_time, *delay_time);

    return globus_l_callback_register(
        callback_handle,
        &start_time,
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

    if(!delay_time)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_register_periodic", "delay_time");
    }
    if(!period)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_register_periodic", "period");
    }

    GlobusTimeAbstimeGetCurrent(start_time);
    GlobusTimeAbstimeInc(start_time, *delay_time);

    return globus_l_callback_register(
        callback_handle,
        &start_time,
        period,
        callback_func,
        callback_user_args,
        space);
}

/**
 * globus_callback_space_register_abstime_oneshot
 *
 * external function that registers a one shot to start at some specific time.
 * this is useful if the user has a specific time that a callback should be
 * triggered.  It is also useful if the user is registering many callbacks at
 * once.  It it is more efficient to call this many times with the same time
 * then to call globus_callback_register_oneshot many times.  The latter would
 * have to make repeated, expensive, gettimeofday calls.
 */

globus_result_t
globus_callback_space_register_abstime_oneshot(
    globus_callback_handle_t *          callback_handle,
    const globus_abstime_t *            start_time,
    globus_callback_func_t              callback_func,
    void *                              callback_user_args,
    globus_callback_space_t             space)
{
    if(!start_time)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_register_abstime_oneshot", "start_time");
    }

    return globus_l_callback_register(
        callback_handle,
        start_time,
        GLOBUS_NULL,
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
    const globus_abstime_t *            time_now,
    const globus_abstime_t *            time_stop,
    void *                              user_args)
{
    globus_l_callback_info_t *          callback_info;

    callback_info = (globus_l_callback_info_t *) user_args;

    callback_info->unregister_callback(
        time_now,
        time_stop,
        callback_info->unreg_args);
    
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
    void *                              unreg_args)
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
            if(callback_info->in_queue)
            {
                globus_priority_q_remove(
                    &callback_info->my_space->queue, callback_info);
                    
                callback_info->in_queue = GLOBUS_FALSE;
            }

            callback_info->is_periodic = GLOBUS_FALSE;
        }
        
        globus_mutex_unlock(&callback_info->my_space->lock);
    
        /* unregister callback will get called when running_count == 0 */
        
        /* this decrements the user's reference */
        globus_l_callback_info_dec_ref(callback_handle);
        
        /* this is not really an error, just informing the user that I have
         * deffered the cancel until the callback is no longer running
         */
        return GLOBUS_L_CALLBACK_CONSTRUCT_CANCEL_RUNNING(
            "globus_callback_unregister");
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
            globus_priority_q_remove(
                &callback_info->my_space->queue, callback_info);
            
            callback_info->in_queue = GLOBUS_FALSE;
            
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
                &globus_i_reltime_zero,
                globus_l_callback_cancel_kickout_cb,
                callback_info,
                callback_info->my_space->handle);
        }
        else
        {
            /* not kicking one out, so decr last ref */
            globus_l_callback_info_dec_ref(callback_handle);
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

    if(!(callback_info))
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
            globus_priority_q_remove(
                &callback_info->my_space->queue,
                callback_info);
            
            callback_info->in_queue = GLOBUS_FALSE;
            
            /* decr my reference to this since I dont 
             * have control of it anymore  -- this is safe to do within space's
             * lock since user still holds one ref
             */
            globus_l_callback_info_dec_ref(callback_handle);
        }
    }
    else
    {
        callback_info->is_periodic = GLOBUS_TRUE;
        GlobusTimeReltimeCopy(callback_info->period, *new_period);
        
        /* may or may not be in queue depending on if its not running or its
         * been restarted.  if its not in queue and its running, no problem...
         * when it gets requeued it will be with the new period
         */
        if(callback_info->in_queue)
        {
            GlobusTimeAbstimeGetCurrent(callback_info->start_time);
            GlobusTimeAbstimeInc(callback_info->start_time, *new_period);

            globus_priority_q_modify(
                &callback_info->my_space->queue,
                callback_info,
                &callback_info->start_time);
        }
        else if(callback_info->running_count == 0)
        {
            /* it wasnt in the queue and its not running...  we must have
             * previously set this non-periodic... I need to requeue it
             * and take my ref to it back
             */
            GlobusTimeAbstimeGetCurrent(callback_info->start_time);
            GlobusTimeAbstimeInc(callback_info->start_time, *new_period);

            globus_priority_q_enqueue(
                &callback_info->my_space->queue,
                callback_info,
                &callback_info->start_time);
    
            callback_info->in_queue = GLOBUS_TRUE;
            
            globus_mutex_lock(&globus_l_callback_handle_lock);
            {
                globus_handle_table_increment_reference(
                    &globus_l_callback_handle_table, callback_handle);
            }
            globus_mutex_unlock(&globus_l_callback_handle_lock);
        }
        
        /* spaces with threaded behavior use the global queue.  I need to
         * wake up any sleeping threads to let them know about knew work 
         */
        if(callback_info->in_queue)
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
        
        globus_priority_q_init(
            &i_space->queue, (globus_priority_q_cmp_func_t) globus_abstime_cmp);
        globus_mutex_init(&i_space->lock, GLOBUS_NULL);
        globus_cond_init(&i_space->cond, GLOBUS_NULL);
        i_space->behavior = behavior;
        i_space->shutdown = GLOBUS_FALSE;
        
        /* this is only tracked for serialized spaces */
        i_space->thread_count = 1;
        
        if(behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED)
        {
            globus_mutex_lock(&globus_l_callback_thread_lock);
            {
                if(!globus_l_callback_shutting_down)
                {
                    int                         rc;
                    
                    rc = globus_thread_create(
                        GLOBUS_NULL,
                        GLOBUS_NULL,
                        globus_l_callback_thread_poll,
                        i_space);
                    globus_assert(rc == 0);
                
                    globus_list_insert(
                        &globus_l_callback_threaded_spaces, i_space);
                }
            }
            globus_mutex_unlock(&globus_l_callback_thread_lock);
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
 * check queue for ready entry, pass back next ready time
 * in ready_time.  return callback info.
 *
 * space should be locked before this call
 */

static
globus_l_callback_info_t *
globus_l_callback_get_next(
    globus_priority_q_t *               queue,
    globus_abstime_t *                  time_now,
    globus_abstime_t *                  ready_time)

{
    globus_abstime_t *                  tmp_time;
    globus_l_callback_info_t *          callback_info;

    if(!globus_priority_q_empty(queue))
    {
        tmp_time = (globus_abstime_t *)
            globus_priority_q_first_priority(queue);
        if(globus_abstime_cmp(tmp_time, time_now) > 0)
        {
            /* not ready yet */
            GlobusTimeAbstimeCopy(*ready_time, *tmp_time);
            callback_info = GLOBUS_NULL;
        }
        else
        {
            /* we got one */
            callback_info = (globus_l_callback_info_t *)
                globus_priority_q_dequeue(queue);
            
            callback_info->in_queue = GLOBUS_FALSE;
            
            /* get the next ready time */
            tmp_time = (globus_abstime_t *)
                globus_priority_q_first_priority(queue);
            if(tmp_time)
            {
                GlobusTimeAbstimeCopy(*ready_time, *tmp_time);
            }
            else
            {
                /* queue is empty */
                GlobusTimeAbstimeCopy(*ready_time, globus_i_abstime_infinity);
            }
        }
    }
    else
    {
        GlobusTimeAbstimeCopy(*ready_time, globus_i_abstime_infinity);
        callback_info = GLOBUS_NULL;
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
 * simply increments the start time associated with the callback by its period.
 * If the new start time is less than the current time, set the start time to
 * be the current time. This causes drift if we're falling behind, but at
 * least keeps the callback moving forward in time with all the other
 * callbacks.
 *
 * space should be locked before this call
 */

static
void
globus_l_callback_requeue(
    globus_l_callback_info_t *          callback_info)
{
    globus_abstime_t                    time_now;

    GlobusTimeAbstimeGetCurrent(time_now);
    GlobusTimeAbstimeInc(callback_info->start_time, callback_info->period);

    if(globus_abstime_cmp(&time_now, &callback_info->start_time) > 0)
    {
        /* we're running way behind, reset start time to current time
         */
        GlobusTimeAbstimeCopy(callback_info->start_time, time_now);
    }

    globus_priority_q_enqueue(
        &callback_info->my_space->queue,
        callback_info,
        &callback_info->start_time);
    
    callback_info->in_queue = GLOBUS_TRUE;
    
    globus_cond_signal(&callback_info->my_space->cond);
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
    globus_callback_space_t             space,
    globus_thread_callback_index_t      index,
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
                    globus_l_callback_requeue(callback_info);
                }
            }
            globus_mutex_unlock(&callback_info->my_space->lock);

            restart_info->restarted = GLOBUS_TRUE;
        }
        
        if(restart_info->create_thread)
        {
            globus_mutex_lock(&globus_l_callback_thread_lock);
            {
                if(!globus_l_callback_shutting_down)
                {
                    int                 rc;
                    
                    callback_info->my_space->thread_count++;
                    globus_l_callback_thread_count++;
                    
                    rc = globus_thread_create(
                        GLOBUS_NULL,
                        GLOBUS_NULL,
                        globus_l_callback_thread_poll,
                        callback_info->my_space);
                    globus_assert(rc == 0);
                }
            } 
            globus_mutex_unlock(&globus_l_callback_thread_lock);
        }
    }
}

static
void
globus_l_callback_finish_callback(
    globus_l_callback_info_t *          callback_info,
    globus_bool_t                       restarted)
{
    globus_l_callback_space_t *         i_space;
    globus_bool_t                       unregister;
    globus_callback_func_t              unregister_callback;
    
    i_space = callback_info->myspace;
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
            globus_l_callback_requeue(callback_info);
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
    int                                 restart_index;
    
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
    
    restart_info.create_thread = GLOBUS_FALSE;
    
    /*
     * If we get signaled, we will jump out of this function asap
     */
    restart_info.signaled = GLOBUS_FALSE;
    
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
    
    GlobusTimeAbstimeGetCurrent(time_now);
    
    done = GLOBUS_FALSE;
    
    do
    {
        globus_l_callback_info_t *      callback_info;
        globus_abstime_t                next_ready_time;
        
        globus_mutex_lock(&i_space->lock);
        
        callback_info = globus_l_callback_get_next(
            &i_space->queue, &time_now, &next_ready_time);
        
        if(callback_info)
        {
            callback_info->running_count++;
            
            globus_mutex_unlock(&i_space->lock);
            
            /* we got a callback, kick it out */
            if(globus_abstime_cmp(timestop, &next_ready_time) > 0)
            {
                restart_info.timeout = &next_ready_time;
            }
            else
            {
                restart_info.timeout = (globus_abstime_t *) timestop;
            }
            
            if(globus_abstime_cmp(&time_now, restart_info.timeout) > 0)
            {
                restart_info.timeout = &time_now;
            }
            
            restart_info.restarted = GLOBUS_FALSE;
            restart_info.callback_info = callback_info;
            
            globus_thread_blocking_callback_enable(&restart_index);
            
            callback_info->callback_func(
                &time_now, restart_info.timeout, callback_info->callback_args);
            
            globus_thread_yield();
            
            globus_thread_blocking_callback_disable(&restart_index);
            
            globus_l_callback_finish_callback(
                callback_info, restart_info.restarted);
            
            done = restart_info.signaled;
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
                globus_cond_timedwait(
                    &i_space->cond, &i_space->lock, &next_ready_time);
            }
            else if(globus_time_abstime_is_infinity(timestop))
            {
                /* we can only get here if queue is empty
                 * and we are blocking forever. 
                 */
                 globus_cond_wait(&i_space->cond, &i_space->lock);
            }
            else
            {
                /* wont be any ready before our time is up */
                done = GLOBUS_TRUE;
            }
                
            globus_mutex_unlock(&i_space->lock);
        }

        if(!done)
        {
            GlobusTimeAbstimeGetCurrent(time_now);
        }

    } while(!done && globus_abstime_cmp(timestop, &time_now) > 0);

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
        
    globus_thread_blocking_callback_pop(GLOBUS_NULL);
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
    globus_abstime_t                    next_ready_time;
    globus_abstime_t                    time_now;
    globus_l_callback_restart_info_t    restart_info;
    int                                 restart_index;
    globus_bool_t                       run_now;
    globus_l_callback_space_t *         i_space;
    
    callback_info = (globus_l_callback_info_t *) user_args;
    i_space = callback_info->my_space;
    GlobusTimeAbstimeCopy(next_ready_time, globus_i_abstime_infinity);
    GlobusTimeAbstimeGetCurrent(time_now);
    
    /* if this thread is restarted, the periodic will just get requeued and
     * an new thread may be created by one of the pollers
     */
    restart_info.restarted = GLOBUS_FALSE;
    restart_info.create_thread = GLOBUS_FALSE;
    restart_info.timeout = &next_ready_time;
    restart_info.callback_info = callback_info;
    
    globus_thread_setspecific(
        globus_l_callback_restart_info_key, &restart_info);

    globus_thread_blocking_callback_push(
        globus_l_callback_blocked_cb,
        &restart_info,
        &restart_index);
    
    do
    {
        callback_info->callback_func(
            &time_now,
            restart_info.timeout,
            callback_info->callback_args);
        
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
                GlobusTimeAbstimeGetCurrent(time_now);
                GlobusTimeAbstimeInc(
                    callback_info->start_time, callback_info->period);
                
                if(!i_space->shutdown)
                {
                    if(globus_abstime_cmp(
                        &time_now, &callback_info->start_time) < 0)
                    {
                        do
                        {
                            globus_cond_timedwait(
                                &i_space->cond,
                                &i_space->lock,
                                &callback_info->start_time);
                             
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
                        GlobusTimeAbstimeCopy(
                            callback_info->start_time, time_now);
                            
                        run_now = GLOBUS_TRUE;
                    }
                }
            }
        }
        globus_mutex_unlock(&i_space->lock);
        
        globus_thread_blocking_callback_enable(&restart_index);
        
    } while(run_now);
    
    globus_l_callback_finish_callback(callback_info, restart_info.restarted);    
    
    globus_thread_blocking_reset();
    
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
    globus_abstime_t                    time_now;
    globus_l_callback_restart_info_t    restart_info;
    int                                 restart_index;
    globus_bool_t                       gets_own_thread;
    globus_l_callback_space_t *         i_space;
    
    i_space = (globus_l_callback_space_t *) user_args;
    /* if this thread is ever restarted, its going to terminate, since
     * it knows a new thread was started as a result of the restart
     */
    restart_info.restarted = GLOBUS_FALSE;
    restart_info.create_thread = GLOBUS_TRUE;
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
                if(globus_priority_q_empty(&i_space->queue))
                {
                    globus_cond_wait(&i_space->cond, &i_space->lock);
                }
                else
                {
                    GlobusTimeAbstimeGetCurrent(time_now);
                
                    callback_info = globus_l_callback_get_next(
                        &i_space->queue, &time_now, &next_ready_time);
                        
                    if(!callback_info)
                    {
                        globus_cond_timedwait(
                            &i_space->cond, &i_space->lock, &next_ready_time);
                    }
                    else
                    {
                        callback_info->running_count++;
                        gets_own_thread = GLOBUS_FALSE;
                        if(callback_info->is_periodic &&
                            globus_reltime_cmp(
                                &callback_info->period,
                                &globus_l_callback_own_thread_period) <= 0 &&
                            i_space->behavior !=
                                GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED)
                        {
                            gets_own_thread = GLOBUS_TRUE;
                        }
                    }
                }
            }
            
            if(i_space->shutdown)
            {
                done = GLOBUS_TRUE;
            }
        }
        globus_mutex_unlock(&i_space->lock);
        
        if(callback_info)
        {
            /* if function does not have its own thread */
            if(!gets_own_thread)
            {
                restart_info.callback_info = callback_info;
                
                if(globus_abstime_cmp(&time_now, &next_ready_time) > 0)
                {
                    restart_info.timeout = &time_now;
                }
                else
                {
                    restart_info.timeout = &next_ready_time;
                }
                
                globus_thread_blocking_callback_enable(&restart_index);
                
                callback_info->callback_func(
                    &time_now,
                    restart_info.timeout,
                    callback_info->callback_args);
                
                globus_thread_yield();
                
                globus_l_callback_finish_callback(
                    callback_info, restart_info.restarted);

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
                        int             rc;

                        globus_l_callback_thread_count++;
                        rc = globus_thread_create(
                            GLOBUS_NULL,
                            GLOBUS_NULL,
                            globus_l_callback_thread_callback,
                            callback_info);
                        globus_assert(rc == 0);
                    }
                } 
                globus_mutex_unlock(&globus_l_callback_thread_lock);
            }
        }
    } while(!done);
    
    globus_thread_blocking_reset();
    
    if(i_space->behavior == GLOBUS_CALLBACK_SPACE_BEHAVIOR_SERIALIZED)
    {
        if(restart_info.restarted)
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
            globus_bool_t               free_space;
            
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
            
                globus_priority_q_destroy(&i_space->queue);
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

globus_bool_t
globus_callback_space_is_single(
    globus_callback_space_t             space)
{
    globus_l_callback_space_t *         i_space;
    
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
    globus_abstime_t                    time_now;
    globus_l_callback_restart_info_t *  restart_info;
    
    restart_info = (globus_l_callback_restart_info_t *)
        globus_thread_getspecific(globus_l_callback_restart_info_key);
        
    if(!restart_info || globus_time_abstime_is_infinity(restart_info->timeout))
    {
        if(time_left)
        {
            GlobusTimeReltimeCopy(*time_left, globus_i_reltime_infinity);
        }

        return GLOBUS_FALSE;
    }

    GlobusTimeAbstimeGetCurrent(time_now);
    if(globus_abstime_cmp(
        &time_now, restart_info->timeout) >= 0)
    {
        if(time_left)
        {
            GlobusTimeReltimeCopy(*time_left, globus_i_reltime_zero);
        }

        return GLOBUS_TRUE;
    }

    if(time_left)
    {
        GlobusTimeAbstimeDiff(
            *time_left, time_now, *restart_info->timeout);
    }

    return GLOBUS_FALSE;
}

globus_bool_t
globus_callback_has_time_expired()
{
    globus_abstime_t                    time_now;
    globus_l_callback_restart_info_t *  restart_info;
    
    restart_info = (globus_l_callback_restart_info_t *)
        globus_thread_getspecific(globus_l_callback_restart_info_key);

    if(!restart_info || globus_time_abstime_is_infinity(restart_info->timeout))
    {
        return GLOBUS_FALSE;
    }

    GlobusTimeAbstimeGetCurrent(time_now);
    if(globus_abstime_cmp(
        &time_now, restart_info->timeout) > 0)
    {
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
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
