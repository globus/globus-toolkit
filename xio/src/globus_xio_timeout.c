/*
 *  this is tightly coupled to operations data structure
 */ 
typedef struct globus_i_xio_op_timer_s
{
    globus_reltime_t                                minimal_delay;
    globus_mutex_t                                  mutex;
    globus_mutex_t                                  cond;
    globus_list_t *                                 op_list;
    globus_bool_t                                   running;
    globus_callback_handle_t                        periodic_handle;
} globus_i_xio_timer_t;

typedef

void
globus_i_xio_op_timer_init(
    globus_i_xio_timer_t *                          timer)
{
    globus_mutex_init(&timer->mutex, NULL);
    globus_cond_init(&timer->cond, NULL);
    timer->list = NULL;
    timer->running = GLOBUS_FALSE;

    globus_callback_space_register_periodic(
        &timer->periodic_handle,
        INFINITY,
        NEVER,
        globus_i_xio_op_timer_poller_callback,
        (void *)timer,
        GLOBUS_CALLBACK_GLOBAL_SPACE);
}

void
globus_l_xio_op_timer_unregister(
    void *                              user_args)
{
    globus_i_xio_timer_t *                          timer;

    timer = (globus_i_xio_timer_t *) user_args;

    globus_mutex_lock(&timer->mutex);
    {
        timer->running = GLOBUS_FALSE;
        globus_cond_signal(&timer->cond);
    }
    globus_mutex_unlock(&timer->mutex);
}


void
globus_i_xio_op_timer_destroy(
    globus_i_xio_timer_t *                          timer)
{
    globus_result_t                                 res;

    globus_mutex_lock(&timer->mutex);
    {
        /* reuse a bool */
        timer->running = GLOBUS_TRUE;
        res = globus_callback_unregister(
                timer->periodic_handle,
                globus_l_xio_op_timer_unregister,
                (void *)tiemr);
        if(res != GLOBUS_SUCCESS)
        {
            while(timer->running)
            {
                globus_cond_wait(&timer->cond, &timer->mutex);
            }
        }
    }
    globus_mutex_unlock(&timer->mutex);

    /* if the list is not empty i am not gonna complain */
    globus_mutex_destroy(timer->mutex, NULL);
}

void
globus_i_xio_op_timer_register_timeout(
    globus_i_xio_timer_t *                          timer,
    globus_i_xio_operation_t *                      op,
    globus_reltime_t *                              timeout)
{
    globus_mutex_lock(&timer->mutex);
    {
        if(!timer->running || 
            globus_reltime_cmp(op->timeout_rel, timer->minimal_delay) < 0)
        {
            GlobusTimeReltimeCopy(timer->minimal_delay, op->timeout_rel);
            globus_callback_adjust_period(
                timer->periodic_handle,
                timer->minimal_delay);
            timer->running = GLOBUS_TRUE;
        }
        globus_list_insert(&timer->op_list, op);
    }
    globus_mutex_unlock(&timer->mutex);
}

globus_bool_t
globus_i_xio_op_timer_unregister_timeout(
    globus_i_xio_operation_t *                      op)
{
    globus_list_t *                                 list;
    globus_bool_t                                   rc;

    globus_mutex_lock(&timer->mutex);
    {
        list = globus_list_search(&timer->op_list, op);
        if(list != NULL)
        {
            globus_list_remove(&timer->op_list, list);
            /* if the list is empty stop the callback */
            if(globus_list_empty(timer->op_list))
            {
                globus_callback_adjust_period(
                    timer->periodic_handle,
                    NULL);
                timer->running = GLOBUS_FALSE;
            }
            rc = GLOBUS_TRUE;
        }
        else
        {
            rc = GLOBUS_FALSE;
        }
    }
    globus_mutex_unlock(&timer->mutex);

    return rc;
}

void
globus_i_xio_op_timer_poller_callback(
    void *                                          user_arg)
{
    globus_i_xio_timer_t  *                         timer;
    globus_list_t *                                 list;
    globus_i_xio_operation_t *                      op;
    globus_abstime_t                                now;
    globus_reltime_t                                tmp_rel;
    globus_bool_t                                   done = GLOBUS_FALSE;

    timer = (globus_i_xio_timer_t *)user_arg;

    globus_mutex_lock(&timer->mutex);
    {
        for(list = timer->op_list; 
            !done && !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            op = (globus_i_xio_operation_t *) globus_list_first(list);

            /* time has expired */
            if(globus_abstime_cmp(&now, &op->abs_timeout))
            {
                /* if progress was made up the expiration point and flip
                 * the progress flag 
                 */
                if(op->progress)
                {
                    op->progress = GLOBUS_FALSE;
                    GlobusTimeReltimeDiff(tmp_rel, op->reltime, \
                                          timer->minimal_delay);
                    GlobusTimeAbstimeInc(op->abs_timeout, tmp_rel);
                }
                /* timeout */
                else
                {
                    /* 
                     * call the users function 
                     * of they return true then cancel the operation 
                     */
                    if(op->user_timeout_callback(
                        op->xio_handle, 
                        op->op_type, 
                        op->user_timeout_arg))
                    {
                        done = GLOBUS_TRUE;
                        globus_list_remove(&timer->op_list, list);

                        /* start cancel process */
                        globus_i_xio_operation_cancel(op);
                    }
                }
            }
        }
    }
    globus_mutex_unlock(&timer->mutex);
}
