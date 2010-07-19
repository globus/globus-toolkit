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

#include "globus_i_xio.h"

#define GLOBUS_L_XIO_TIMER_MAX_POLL 60 /* seconds */

typedef struct globus_i_xio_timer_entry_s
{
    void *                              datum;
    globus_bool_t *                     progress_ptr;
    globus_i_xio_timer_cb_t             timer_cb;
    globus_reltime_t                    rel_timeout;
    globus_abstime_t                    abs_timeout;
} globus_i_xio_timer_entry_t;


void
globus_i_xio_timer_poller_callback(
    void *                              user_arg);

void
globus_i_xio_timer_init(
    globus_i_xio_timer_t *              timer)
{
    GlobusXIOName(globus_i_xio_timer_init);

    GlobusXIODebugInternalEnter();

    globus_mutex_init(&timer->mutex, NULL);
    globus_cond_init(&timer->cond, NULL);
    timer->op_list = NULL;
    timer->running = GLOBUS_FALSE;

    globus_callback_space_register_periodic(
        &timer->periodic_handle,
        &globus_i_reltime_infinity,
        &globus_i_reltime_infinity,
        globus_i_xio_timer_poller_callback,
        (void *)timer,
        GLOBUS_CALLBACK_GLOBAL_SPACE);

    GlobusXIODebugInternalExit();
}

void
globus_l_xio_timer_unregister_cb(
    void *                              user_args)
{
    globus_i_xio_timer_t *              timer;
    GlobusXIOName(globus_l_xio_timer_unregister_cb);

    GlobusXIODebugInternalEnter();

    timer = (globus_i_xio_timer_t *) user_args;

    globus_mutex_lock(&timer->mutex);
    {
        timer->running = GLOBUS_FALSE;
        globus_cond_signal(&timer->cond);
    }
    globus_mutex_unlock(&timer->mutex);

    /* GlobusXIODebugInternalExit(); having this in can cause core dumps */
}

void
globus_i_xio_timer_destroy(
    globus_i_xio_timer_t *              timer)
{
    globus_result_t                     res;
    GlobusXIOName(globus_i_xio_timer_destroy);

    GlobusXIODebugInternalEnter();

    globus_mutex_lock(&timer->mutex);
    {
        /* reuse a bool */
        timer->running = GLOBUS_TRUE;
        res = globus_callback_unregister(
                timer->periodic_handle,
                globus_l_xio_timer_unregister_cb,
                (void *)timer,
                NULL);
        /* logic of this code should prevent this from ever failing */
        globus_assert(res == GLOBUS_SUCCESS);
        while(timer->running)
        {
            globus_cond_wait(&timer->cond, &timer->mutex);
        }
    }
    globus_mutex_unlock(&timer->mutex);

    /* if the list is not empty i am not gonna complain */
    globus_mutex_destroy(&timer->mutex);

    GlobusXIODebugInternalExit();
}


void
globus_i_xio_timer_register_timeout(
    globus_i_xio_timer_t *              timer,
    void *                              datum,
    globus_bool_t *                     progress_ptr,
    globus_i_xio_timer_cb_t             timeout_cb,
    globus_reltime_t *                  timeout)
{
    globus_i_xio_timer_entry_t *        entry;
    globus_result_t                     res;
    globus_reltime_t                    poll_time;
    GlobusXIOName(globus_i_xio_timer_register_timeout);

    GlobusXIODebugInternalEnter();

    entry = globus_malloc(sizeof(globus_i_xio_timer_entry_t));
    entry->datum = datum;
    entry->progress_ptr = progress_ptr;
    entry->timer_cb = timeout_cb;
    GlobusTimeReltimeCopy(entry->rel_timeout, *timeout);
    GlobusTimeReltimeCopy(poll_time, entry->rel_timeout);
    
    /* limit poll time */
    if(poll_time.tv_sec > GLOBUS_L_XIO_TIMER_MAX_POLL)
    {
        GlobusTimeReltimeSet(poll_time, GLOBUS_L_XIO_TIMER_MAX_POLL, 0);
    }
    
    /* expire immediately to force setting of progress flag */
    GlobusTimeAbstimeGetCurrent(entry->abs_timeout);

    globus_mutex_lock(&timer->mutex);
    {
        if(!timer->running || 
            globus_reltime_cmp(&poll_time, &timer->minimal_delay) < 0)
        {
            GlobusTimeReltimeCopy(timer->minimal_delay, poll_time);
            res = globus_callback_adjust_period(
                    timer->periodic_handle,
                    &timer->minimal_delay);

            if(res != GLOBUS_SUCCESS)
            {
                globus_panic(GLOBUS_XIO_MODULE, res, 
                    _XIOSL("globus_callback_adjust_period should always return success"
                    " in this case\n"
                    "timer @ 0x%x\n"
                    " globus_callback_adjust_period(%d, 0x%x);\n"),
                    timer->periodic_handle,
                    &timer->minimal_delay);
            }
            timer->running = GLOBUS_TRUE;
        }
        *entry->progress_ptr = GLOBUS_TRUE;
        globus_list_insert(&timer->op_list, entry);
    }
    globus_mutex_unlock(&timer->mutex);

    GlobusXIODebugInternalExit();
}

globus_bool_t
globus_i_xio_timer_unregister_timeout(
    globus_i_xio_timer_t *              timer,
    void *                              datum)
{
    globus_list_t *                     list;
    globus_list_t *                     tmp_list = NULL;
    globus_bool_t                       found = GLOBUS_FALSE;
    /* intialize to remove warning, but not needed */
    globus_i_xio_timer_entry_t *        entry = NULL;
    GlobusXIOName(globus_i_xio_timer_unregister_timeout);

    GlobusXIODebugInternalEnter();

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
                tmp_list = list;
                /* if the list is empty pause the callback */
            }
        }
        if(found)
        {
            globus_list_remove(&timer->op_list, tmp_list);
            globus_free(entry);
            if(globus_list_empty(timer->op_list))
            {
                globus_callback_adjust_period(
                    timer->periodic_handle,
                    NULL);
                timer->running = GLOBUS_FALSE;
            }
        }
    }
    globus_mutex_unlock(&timer->mutex);

    GlobusXIODebugInternalExit();

    return found;
}

void
globus_i_xio_timer_poller_callback(
    void *                              user_arg)
{
    globus_i_xio_timer_t  *             timer;
    globus_list_t *                     list;
    globus_abstime_t                    now;
    globus_i_xio_timer_entry_t *        entry;
    globus_list_t *                     call_list = NULL;
    globus_list_t *                     tmp_list = NULL;
    GlobusXIOName(globus_i_xio_timer_poller_callback);

    GlobusXIODebugInternalEnter();

    timer = (globus_i_xio_timer_t *)user_arg;

    GlobusTimeAbstimeGetCurrent(now);
    globus_mutex_lock(&timer->mutex);
    {
        tmp_list = globus_list_copy(timer->op_list);
        for(list = tmp_list; 
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            entry = (globus_i_xio_timer_entry_t *) globus_list_first(list);

            /* time has expired */
            if(globus_abstime_cmp(&now, &entry->abs_timeout) >= 0)
            {
                /* if progress was made up the expiration point and flip
                 * the progress flag 
                 */
                if(*entry->progress_ptr)
                {
                    *entry->progress_ptr = GLOBUS_FALSE;
                }
                /* timeout */
                else
                {
                    globus_list_insert(&call_list, entry);
                    globus_list_remove(&timer->op_list,
                        globus_list_search(timer->op_list, entry));
                }
                
                GlobusTimeAbstimeCopy(entry->abs_timeout, now);
                GlobusTimeAbstimeInc(
                    entry->abs_timeout, entry->rel_timeout);
            }
        }
    }
    globus_mutex_unlock(&timer->mutex);
    globus_list_free(tmp_list);

    /* remove from the list all that were canceled */
    while(!globus_list_empty(call_list))
    {
        entry = (globus_i_xio_timer_entry_t *)globus_list_remove(
                    &call_list, call_list);

        /* 
         * call the users function 
         * if they return false then add the operation back into 
         * the pool list.
         */
        if(!entry->timer_cb(entry->datum))
        {
            globus_mutex_lock(&timer->mutex);
            {
                globus_list_insert(&timer->op_list, entry);
            }
            globus_mutex_unlock(&timer->mutex);
        }
        /* if they return true we are done with the entry */
        else
        {
            globus_free(entry);
        }
    }

    GlobusXIODebugInternalExit();
}
