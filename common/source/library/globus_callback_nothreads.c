#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

#include "globus_common.h"
#include "globus_i_callback.h"

#define GLOBUS_L_CALLBACK_INFO_BLOCK_SIZE 256
#define GLOBUS_L_CALLBACK_SPACE_BLOCK_SIZE 32

static
int
globus_l_callback_activate();

static
int
globus_l_callback_deactivate();

#include "version.h"

globus_module_descriptor_t              globus_i_callback_module =
{
    "globus_callback_nonthreaded",
    globus_l_callback_activate,
    globus_l_callback_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef struct
{
    globus_callback_space_t             handle;
    globus_priority_q_t                 queue;
} globus_l_callback_space_t;

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
} globus_l_callback_restart_info_t;

static globus_handle_table_t            globus_l_callback_handle_table;
static globus_handle_table_t            globus_l_callback_space_table;
static globus_memory_t                  globus_l_callback_info_memory;
static globus_memory_t                  globus_l_callback_space_memory;

static globus_l_callback_space_t        globus_l_callback_global_space;
static globus_l_callback_restart_info_t * globus_l_callback_restart_info;

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
            if(callback_info->is_periodic)
            {
                globus_l_callback_requeue(callback_info);
            }

            restart_info->restarted = GLOBUS_TRUE;
        }
    }
}

/*
 * destructor for globus_handle_table.  called whenever the reference for
 * a callback_info goes to zero.
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
        globus_handle_table_decrement_reference(
            &globus_l_callback_space_table, callback_info->my_space->handle);
    }

    globus_memory_push_node(
        &globus_l_callback_info_memory, callback_info);
}

/* 
 * destructor for globus_handle_table.  called whenever the reference for
 * a space goes to zero.
 *
 */
static
void
globus_l_callback_space_destructor(
    void *                              datum)
{
    globus_l_callback_space_t *         space;
    
    space = (globus_l_callback_space_t *) datum;
    
    globus_priority_q_destroy(&space->queue);
    
    globus_memory_push_node(
        &globus_l_callback_space_memory, space);
}

static
int
globus_l_callback_activate()
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_THREAD_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }

    globus_handle_table_init(
        &globus_l_callback_handle_table,
        globus_l_callback_info_destructor);
    
    globus_handle_table_init(
        &globus_l_callback_space_table,
        globus_l_callback_space_destructor);

    /* init global 'space' */
    globus_l_callback_global_space.handle = GLOBUS_CALLBACK_GLOBAL_SPACE;
    globus_priority_q_init(
        &globus_l_callback_global_space.queue,
        (globus_priority_q_cmp_func_t) globus_abstime_cmp);

    globus_memory_init(
        &globus_l_callback_info_memory,
        sizeof(globus_l_callback_info_t),
        GLOBUS_L_CALLBACK_INFO_BLOCK_SIZE);

    globus_memory_init(
        &globus_l_callback_space_memory,
        sizeof(globus_l_callback_space_t),
        GLOBUS_L_CALLBACK_SPACE_BLOCK_SIZE);

    globus_l_callback_restart_info = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}

static
int
globus_l_callback_deactivate()
{
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

    if(!callback_func)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_register_oneshot", "callback_func");
    }

    callback_info = (globus_l_callback_info_t *)
        globus_memory_pop_node(&globus_l_callback_info_memory);
    if(!callback_info)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_MEMORY_ALLOC(
            "globus_l_callback_register", "callback_info");
    }

    if(space == GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        callback_info->my_space = &globus_l_callback_global_space;
    }
    else
    {
        /* get internal space structure and increment its ref count */
        globus_l_callback_space_t *     i_space;

        i_space = (globus_l_callback_space_t *)
            globus_handle_table_lookup(
                &globus_l_callback_space_table, space);
        if(!i_space)
        {
            globus_memory_push_node(
                &globus_l_callback_info_memory, callback_info);

            return GLOBUS_L_CALLBACK_CONSTRUCT_MEMORY_ALLOC(
                "globus_l_callback_register", "i_space");
        }

        globus_handle_table_increment_reference(
            &globus_l_callback_space_table, space);

        callback_info->my_space = i_space;
    }

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

    globus_priority_q_enqueue(
        &callback_info->my_space->queue,
        callback_info,
        &callback_info->start_time);
    
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
 *
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
 *
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
 * driver callback to kickout unregister callback. registered by
 * globus_callback_register_cancel
 *
 * This is only going to get registered if the canceled callback was not
 * running or already complete.
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
    globus_handle_table_decrement_reference(
        &globus_l_callback_handle_table, callback_info->handle);
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

    callback_info = (globus_l_callback_info_t *)
        globus_handle_table_lookup(
                &globus_l_callback_handle_table, callback_handle);

    if(!callback_info)
    {
        /* this is definitely an error,
         * if user had the handle and didnt destroy it (or cancel it),
         * it has to exist
         */
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_CALLBACK_HANDLE(
            "globus_callback_unregister");
    }
    
    /* this doesnt catch a previously unregistered callback that passed a
     * NULL unregister -- bad things may happen in that case
     */
    if(callback_info->unregister_callback)
    {
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

        /* unregister callback will get registered when running_count == 0 */

        /* this decrements the user's reference */
        globus_handle_table_decrement_reference(
            &globus_l_callback_handle_table, callback_handle);
        
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
            globus_priority_q_remove(
                &callback_info->my_space->queue, callback_info);
            
            callback_info->in_queue = GLOBUS_FALSE;
            globus_handle_table_decrement_reference(
                &globus_l_callback_handle_table, callback_handle);
        }

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
            globus_handle_table_decrement_reference(
                &globus_l_callback_handle_table, callback_handle);
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

    callback_info = (globus_l_callback_info_t *)
        globus_handle_table_lookup(
            &globus_l_callback_handle_table, callback_handle);
    if(!(callback_info))
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_CALLBACK_HANDLE(
            "globus_callback_adjust_period");
    }
    
    /* this doesnt catch a previously unregistered callback that passed a
     * NULL unregister -- bad things may happen in that case
     */
    if(callback_info->unregister_callback)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_ALREADY_CANCELED(
            "globus_callback_unregister");
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
             * have control of it anymore
             */
            globus_handle_table_decrement_reference(
                &globus_l_callback_handle_table, callback_handle);
        }
    }
    else
    {
        callback_info->is_periodic = GLOBUS_TRUE;
        GlobusTimeAbstimeGetCurrent(callback_info->start_time);
        GlobusTimeAbstimeInc(callback_info->start_time, *new_period);
        GlobusTimeReltimeCopy(callback_info->period, *new_period);

        /* may or may not be in queue depending on if its not running or its
         * been restarted.  if its not in queue and its running, no problem...
         * when it gets requeued it will be with the new priority
         */
        if(callback_info->in_queue)
        {
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
            globus_priority_q_enqueue(
                &callback_info->my_space->queue,
                callback_info,
                &callback_info->start_time);
    
            callback_info->in_queue = GLOBUS_TRUE;
            
            globus_handle_table_increment_reference(
                &globus_l_callback_handle_table, callback_handle);
        }
    }

    return GLOBUS_SUCCESS;
}

/**
 * globus_callback_space_init
 *
 * -- attrs are ignored here since there are none that make sense in
 *    a non-threaded build
 *
 */

globus_result_t
globus_callback_space_init(
    globus_callback_space_t *           space,
    globus_callback_space_attr_t        attr)
{
    globus_l_callback_space_t *         i_space;

    if(!space)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_init", "space");
    }

    i_space = (globus_l_callback_space_t *)
        globus_memory_pop_node(&globus_l_callback_space_memory);
    if(!i_space)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_MEMORY_ALLOC(
            "globus_callback_space_init", "i_space");
    }

    globus_priority_q_init(
        &i_space->queue, (globus_priority_q_cmp_func_t) globus_abstime_cmp);

    i_space->handle =
        globus_handle_table_insert(
            &globus_l_callback_space_table, i_space, 1);

    *space = i_space->handle;

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
    
    in_table = globus_handle_table_increment_reference(
        &globus_l_callback_space_table, space);
        
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
    
    i_space = (globus_l_callback_space_t *)
        globus_handle_table_lookup(
                &globus_l_callback_space_table, space);
    if(!i_space)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_SPACE(
            "globus_callback_space_destroy");
    }
    
    globus_handle_table_decrement_reference(
        &globus_l_callback_space_table, space);

    return GLOBUS_SUCCESS;
}

/**
 * globus_callback_space_attr_*
 *
 * -- All of these are no-ops since there arent any meaning full attrs
 *      in a non-threaded build
 */

globus_result_t
globus_callback_space_attr_init(
    globus_callback_space_attr_t *      attr)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_callback_space_attr_destroy(
    globus_callback_space_attr_t        attr)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_callback_space_attr_set_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t    behavior)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_callback_space_attr_get_behavior(
    globus_callback_space_attr_t        attr,
    globus_callback_space_behavior_t *  behavior)
{
    if(!behavior)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_attr_get_behavior", "behavior");
    }

    *behavior = GLOBUS_CALLBACK_SPACE_BEHAVIOR_SINGLE;

    return GLOBUS_SUCCESS;
}

/**
 * globus_l_callback_get_next
 *
 * check queue for ready entry, pass back next ready time
 * in ready_time.  return callback info.
 *
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
    globus_priority_q_t *               space_queue;
    globus_abstime_t                    time_now;
    globus_l_callback_restart_info_t *  last_restart_info;
    globus_l_callback_restart_info_t    restart_info;
    globus_abstime_t                    l_timestop;

    space_queue = GLOBUS_NULL;

    if(space != GLOBUS_CALLBACK_GLOBAL_SPACE)
    {
        globus_l_callback_space_t *     i_space;

        i_space = (globus_l_callback_space_t *)
            globus_handle_table_lookup(
                &globus_l_callback_space_table, space);
        if(i_space)
        {
            space_queue = &i_space->queue;
        }
    }
    
    last_restart_info = globus_l_callback_restart_info;
    globus_l_callback_restart_info = &restart_info;
    
    /*
     * If we get signaled, we will jump out of this function asap
     */
    restart_info.signaled = GLOBUS_FALSE;
    
    globus_thread_blocking_callback_push(
        globus_l_callback_blocked_cb,
        &restart_info,
        GLOBUS_NULL);
    
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
        globus_abstime_t                space_ready_time;
        globus_abstime_t                global_ready_time;
        globus_abstime_t *              first_ready_time;

        callback_info = GLOBUS_NULL;

        /* first we'll see if there is a callback ready on the polled space */
        if(space_queue)
        {
            callback_info = globus_l_callback_get_next(
                space_queue, &time_now, &space_ready_time);
        }

        /* if we didnt get one from the polled space, check the global queue */
        if(!callback_info)
        {
            callback_info = globus_l_callback_get_next(
                &globus_l_callback_global_space.queue,
                &time_now,
                &global_ready_time);
        }
        else
        {
            /* still need to know when the next one is ready
             * on the global space
             */
            globus_abstime_t *          tmp_time;

            tmp_time = (globus_abstime_t *)
                globus_priority_q_first_priority(
                    &globus_l_callback_global_space.queue);
            if(tmp_time)
            {
                GlobusTimeAbstimeCopy(global_ready_time, *tmp_time);
            }
            else
            {
                /* queue is empty */
                GlobusTimeAbstimeCopy(
                    global_ready_time, globus_i_abstime_infinity);
            }
        }

        /* pick whoever's next is ready first */
        first_ready_time = &global_ready_time;
        if(space_queue)
        {
            if(globus_abstime_cmp(
                &global_ready_time, &space_ready_time) >= 0)
            {
                first_ready_time = &space_ready_time;
            }
        }

        if(callback_info)
        {
            /* we got a callback, kick it out */
            if(globus_abstime_cmp(timestop, first_ready_time) > 0)
            {
                restart_info.timeout = first_ready_time;
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

            callback_info->running_count++;

            callback_info->callback_func(
                &time_now, restart_info.timeout, callback_info->callback_args);

            callback_info->running_count--;

            /* a periodic that was canceled has is_periodic == false */
            if(!callback_info->is_periodic &&
                callback_info->running_count == 0)
            {
                /* if this was unregistered, we need to register for the
                 * unregister callback.  the kickout will decr the last ref
                 */
                if(callback_info->unregister_callback)
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
                    /* no unreg callback so I'll decrement my ref */
                    globus_handle_table_decrement_reference(
                        &globus_l_callback_handle_table, callback_info->handle);
                }
                
            }
            else if(callback_info->is_periodic && !restart_info.restarted)
            {
                globus_l_callback_requeue(callback_info);
            }
            
            done = restart_info.signaled;
        }
        else
        {
            /* no callbacks were ready */
            if(globus_abstime_cmp(timestop, first_ready_time) > 0)
            {
                /* sleep until first one is ready */
                globus_reltime_t        sleep_time;
                unsigned long           usec;

                GlobusTimeAbstimeDiff(sleep_time, *first_ready_time, time_now);
                GlobusTimeReltimeToUSec(usec, sleep_time);

                if(usec > 0)
                {
                    globus_libc_usleep(usec);
                }
            }
            else if(globus_time_abstime_is_infinity(timestop))
            {
                /* we can only get here if both queues are empty
                 * and we are blocking forever. in this case, it is not
                 * possible for a new callback to be registered, except by
                 * a signal handler. pause will wake up in that case
                 */
                 pause();
            }
            else
            {
                /* wont be any ready before our time is up */
                done = GLOBUS_TRUE;
            }
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
    
    globus_l_callback_restart_info = last_restart_info;
    
    globus_thread_blocking_callback_pop(GLOBUS_NULL);
}

void
globus_callback_signal_poll()
{
    if(globus_l_callback_restart_info)
    {
        globus_l_callback_restart_info->signaled = GLOBUS_TRUE;
    }
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
    if(!space)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(
            "globus_callback_space_get", "space");
    }
    
    if(!globus_l_callback_restart_info)
    {
        return GLOBUS_L_CALLBACK_CONSTRUCT_NO_ACTIVE_CALLBACK(
            "globus_callback_space_get");
    }
    
    *space = globus_l_callback_restart_info->callback_info->my_space->handle;
    
    return GLOBUS_SUCCESS;
}

globus_bool_t
globus_callback_space_is_single(
    globus_callback_space_t             space)
{
    return GLOBUS_TRUE;
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

    if(!globus_l_callback_restart_info ||
        globus_time_abstime_is_infinity(
            globus_l_callback_restart_info->timeout))
    {
        if(time_left)
        {
            GlobusTimeReltimeCopy(*time_left, globus_i_reltime_infinity);
        }

        return GLOBUS_FALSE;
    }

    GlobusTimeAbstimeGetCurrent(time_now);
    if(globus_abstime_cmp(
        &time_now, globus_l_callback_restart_info->timeout) >= 0)
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
            *time_left, time_now, *globus_l_callback_restart_info->timeout);
    }

    return GLOBUS_FALSE;
}

globus_bool_t
globus_callback_has_time_expired()
{
    globus_abstime_t                    time_now;

    if(!globus_l_callback_restart_info ||
        globus_time_abstime_is_infinity(
            globus_l_callback_restart_info->timeout))
    {
        return GLOBUS_FALSE;
    }

    GlobusTimeAbstimeGetCurrent(time_now);
    if(globus_abstime_cmp(
        &time_now, globus_l_callback_restart_info->timeout) > 0)
    {
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}

globus_bool_t
globus_callback_was_restarted()
{
    return globus_l_callback_restart_info
        ? globus_l_callback_restart_info->restarted
        : GLOBUS_FALSE;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
