typedef struct globus_i_xio_op_timer_s
{
    globus_reltime_t                                minimal_delay;
    globus_mutex_t                                  mutex;
    globus_mutex_t                                  cond;
    globus_list_t *                                 op_list;
    globus_bool_t                                   running;
    globus_callback_handle_t                        periodic_handle;
} globus_i_xio_timer_t;

typedef struct globus_i_xio_timer_entry_s
{
    void *                                          datum;
    globus_bool_t *                                 progress_ptr;
    globus_i_xio_timer_cb_t                         timer_cb;
    globus_reltime_t *                              rel_timeout;
    globus_abstime_t *                              abs_timeout;
} globus_i_xio_timer_entry_t;


typedef globus_bool_t
(*globus_i_xio_timer_cb_t)(
    void *                                          datum);

void
globus_i_xio_timer_init(
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
globus_l_xio_timer_unregister_cb(
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
globus_i_xio_timer_destroy(
    globus_i_xio_timer_t *                          timer)
{
    globus_result_t                                 res;

    globus_mutex_lock(&timer->mutex);
    {
        /* reuse a bool */
        timer->running = GLOBUS_TRUE;
        res = globus_callback_unregister(
                timer->periodic_handle,
                globus_l_xio_timer_unregister_cb,
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
globus_i_xio_timer_register_timeout(
    globus_i_xio_timer_t *                          timer,
    void *                                          datum,
    globus_bool_t *                                 progress_ptr,
    globus_i_xio_timer_cb_t                         timeout_cb,
    globus_reltime_t *                              timeout)
{
    globus_i_xio_timer_entry_t *                    entry;

    entry = globus_malloc(sizeof(globus_i_xio_timer_entry_t));
    entry->datum = datum;
    entry->progress_ptr = progress_ptr;
    GlobusTimeReltimeCopy(entry->rel_timeout, *timeout);
    GlobusTimeAbstimeGetCurrent(entry->abs_timeout);
    GlobusTimeAbstimeInc(entry->abs_timeout, *timerout);

    globus_mutex_lock(&timer->mutex);
    {
        if(!timer->running || 
            globus_reltime_cmp(entry->rel_timeout, timer->minimal_delay) < 0)
        {
            GlobusTimeReltimeCopy(timer->minimal_delay, entry->rel_timeout);
            globus_callback_adjust_period(
                timer->periodic_handle,
                &timer->minimal_delay);
            timer->running = GLOBUS_TRUE;
        }
        globus_list_insert(&timer->op_list, entry);
    }
    globus_mutex_unlock(&timer->mutex);
}

globus_bool_t
globus_i_xio_timer_unregister_timeout(
    void *                                          datum)
{
    globus_list_t *                                 list;
    globus_bool_t                                   found = GLOBUS_FALSE;
    globus_i_xio_timer_entry_t *                    entry;

    globus_mutex_lock(&timer->mutex);
    {
        for(list = timer->op_list;
            !found && !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            entry = (globus_i_xio_timer_entry_t *) globus_list_first(list);
            if(entry->datum == datum)
            {
                found = GLOBUS_TRUE;
                globus_list_remove(&timer->op_list, list);
                globus_free(entry);
                /* if the list is empty pause the callback */
                if(globus_list_empty(timer->op_list))
                {
                    globus_callback_adjust_period(
                        timer->periodic_handle,
                        NULL);
                    timer->running = GLOBUS_FALSE;
                }
            }
        }

    }
    globus_mutex_unlock(&timer->mutex);

    return found;
}

void
globus_i_xio_timer_poller_callback(
    void *                                          user_arg)
{
    globus_i_xio_timer_t  *                         timer;
    globus_list_t *                                 list;
    globus_abstime_t                                now;
    globus_reltime_t                                tmp_rel;
    globus_bool_t                                   done = GLOBUS_FALSE;
    globus_i_xio_timer_entry_t *                    entry;
    globus_list_t *                                 remove_list;

    timer = (globus_i_xio_timer_t *)user_arg;

    globus_mutex_lock(&timer->mutex);
    {
        for(list = timer->op_list; 
            !done && !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            entry = (globus_i_xio_timer_entry_t *) globus_list_first(list);

            /* time has expired */
            if(globus_abstime_cmp(&now, &entry->abs_timeout))
            {
                /* if progress was made up the expiration point and flip
                 * the progress flag 
                 */
                if(*entry->progress)
                {
                    *entry->progress = GLOBUS_FALSE;
                    GlobusTimeReltimeDiff(tmp_rel, entry->rel_timeout, \
                                          timer->minimal_delay);
                    GlobusTimeAbstimeInc(entry->abs_timeout, tmp_rel);
                }
                /* timeout */
                else
                {
                    /* 
                     * call the users function 
                     * if they return true then cancel the operation 
                     * by adding it to the list of callbacks to remove
                     * since we are travesing this list we can't remove it
                     * here
                     */
                    if(entry->timer_cb(entry->datum))
                    {
                        done = GLOBUS_TRUE;
                        globus_list_insert(&remove_list, list);
                    }
                }
            }
        }

        /* remove from the list all that were canceled */
        for(!globus_list_empty(remove_list))
        {
            list = (globus_list_t *) globus_list_remove(
                                        &remove_list, remove_list);
            globus_list_remove(&timer->op_list, list);
        }
    }
    globus_mutex_unlock(&timer->mutex);
}
