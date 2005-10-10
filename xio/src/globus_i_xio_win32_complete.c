/*
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */
#include "globus_i_xio_win32.h"

#ifdef BUILD_LITE

#define GlobusLWin32PollQueueInit()                                         \
{                                                                           \
    globus_l_xio_win32_poll_queue = NULL;                                   \
    globus_l_xio_win32_poll_queue_tail = &globus_l_xio_win32_poll_queue;    \
}

#define GlobusLWin32PollQueueEnqueue(entry)                                 \
{                                                                           \
    (entry)->next = NULL;                                                   \
    *globus_l_xio_win32_poll_queue_tail = (entry);                          \
    globus_l_xio_win32_poll_queue_tail = &(entry)->next;                    \
}

#define GlobusLWin32PollQueueDequeue(entry)                                 \
{                                                                           \
    (entry) = globus_l_xio_win32_poll_queue;                                \
    globus_l_xio_win32_poll_queue = (entry)->next;                          \
    if(!globus_l_xio_win32_poll_queue)                                      \
        globus_l_xio_win32_poll_queue_tail = &globus_l_xio_win32_poll_queue;\
}

#define GlobusLWin32PollQueueEmpty()                                        \
    (globus_l_xio_win32_poll_queue == NULL)

typedef struct globus_l_xio_win32_poll_entry_s
{
    globus_callback_func_t              callback;
    void *                              user_arg;
    struct globus_l_xio_win32_poll_entry_s * next;
} globus_l_xio_win32_poll_entry_t;

static globus_callback_handle_t         globus_l_xio_win32_poll_handle;
static win32_mutex_t                    globus_l_xio_win32_poll_lock;
static HANDLE                           globus_l_xio_win32_poll_event;
static globus_bool_t                    globus_l_xio_win32_poll_event_sleeping;
static globus_bool_t                    globus_l_xio_win32_poll_event_pending;
static globus_l_xio_win32_poll_entry_t * globus_l_xio_win32_poll_queue;
static globus_l_xio_win32_poll_entry_t ** globus_l_xio_win32_poll_queue_tail;
static globus_l_xio_win32_poll_entry_t * globus_l_xio_win32_poll_free;

static
void
globus_l_xio_win32_wakeup_handler(
    void *                              user_arg)
{
    int                                 rc;
    char                                byte;
    GlobusXIOName(globus_l_xio_win32_wakeup_handler);

    GlobusXIOSystemDebugEnter();
    
    if(globus_l_xio_win32_poll_event != 0)
    {
        SetEvent(globus_l_xio_win32_poll_event);
    }
    
    GlobusXIOSystemDebugExit();
}

static
void
globus_l_xio_win32_poll(
    void *                              user_arg)
{
    GlobusXIOName(globus_l_xio_win32_poll);

    GlobusXIOSystemDebugEnter();

    win32_mutex_lock(&globus_l_xio_win32_poll_lock);
    {
        if(GlobusLWin32PollQueueEmpty())
        {
            globus_reltime_t            time_left;
            
            globus_callback_get_timeout(&time_left);
            if(globus_reltime_cmp(&time_left, &globus_i_reltime_zero) > 0)
            {
                DWORD                   millis = INFINITE;
                
                if(!globus_time_reltime_is_infinity(&time_left))
                {
                    GlobusTimeReltimeToMilliSec(millis, time_left);
                }
                
                globus_l_xio_win32_poll_event_sleeping = GLOBUS_TRUE;
                win32_mutex_unlock(&globus_l_xio_win32_poll_lock);
                
                WaitForSingleObject(globus_l_xio_win32_poll_event, millis);
                
                win32_mutex_lock(&globus_l_xio_win32_poll_lock);
                globus_l_xio_win32_poll_event_sleeping = GLOBUS_FALSE;
                globus_l_xio_win32_poll_event_pending = GLOBUS_FALSE;
            }
        }
        
        while(!GlobusLWin32PollQueueEmpty())
        {
            globus_l_xio_win32_poll_entry_t * entry;
            
            GlobusLWin32PollQueueDequeue(entry);
            
            win32_mutex_unlock(&globus_l_xio_win32_poll_lock);
                
            entry->callback(entry->user_arg);
            
            win32_mutex_lock(&globus_l_xio_win32_poll_lock);
            
            entry->next = globus_l_xio_win32_poll_free;
            globus_l_xio_win32_poll_free = entry;
        }
    }
    win32_mutex_unlock(&globus_l_xio_win32_poll_lock);

    GlobusXIOSystemDebugExit();
}

int
globus_i_xio_win32_complete_activate(void)
{
    globus_result_t                     result;
    globus_reltime_t                    period;
    GlobusXIOName(globus_i_xio_win32_complete_activate);
    
    GlobusXIOSystemDebugEnter();
    
    GlobusLWin32PollQueueInit();
    win32_mutex_init(&globus_l_xio_win32_poll_lock, NULL);
    globus_l_xio_win32_poll_event_sleeping = GLOBUS_FALSE;
    globus_l_xio_win32_poll_event_pending = GLOBUS_FALSE;
    globus_l_xio_win32_poll_free = NULL;
    
    globus_l_xio_win32_poll_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if(globus_l_xio_win32_poll_event == 0)
    {
        goto error_event;
    }
    
    GlobusTimeReltimeSet(period, 0, 0);
    result = globus_callback_register_periodic(
        &globus_l_xio_win32_poll_handle,
        NULL,
        &period,
        globus_l_xio_win32_poll,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_periodic;
    }
    
    globus_callback_add_wakeup_handler(
        globus_l_xio_win32_wakeup_handler, NULL);
    
    GlobusXIOSystemDebugExit();
    
    return GLOBUS_SUCCESS;
    
error_periodic:
    CloseHandle(globus_l_xio_win32_poll_event);
    globus_l_xio_win32_poll_event = 0;
error_event:
    win32_mutex_destroy(&globus_l_xio_win32_poll_lock);
    GlobusXIOSystemDebugExitWithError();
    return GLOBUS_FAILURE;
}

static
void
globus_l_xio_win32_unregister_poll_cb(
    void *                              user_arg)
{
    HANDLE                              unregistered;
    GlobusXIOName(globus_l_xio_win32_unregister_poll_cb);
    
    GlobusXIOSystemDebugEnter();
    
    unregistered = (HANDLE) user_arg;
    if(unregistered != 0)
    {
        SetEvent(unregistered);
    }
    
    GlobusXIOSystemDebugExit();
}

int
globus_i_xio_win32_complete_deactivate(void)
{
    HANDLE                              unregistered;
    globus_result_t                     result;
    GlobusXIOName(globus_i_xio_win32_complete_deactivate);
    
    GlobusXIOSystemDebugEnter();
    
    unregistered = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    result = globus_callback_unregister(
        globus_l_xio_win32_poll_handle,
        globus_l_xio_win32_unregister_poll_cb,
        unregistered,
        NULL);
    
    if(unregistered != 0)
    {
        if(result == GLOBUS_SUCCESS)
        {
            while(WaitForSingleObject(
                unregistered, INFINITE) != WAIT_OBJECT_0)
            {
                /* XXX error */
            }
        }
        
        CloseHandle(unregistered);
    }
    
    win32_mutex_destroy(&globus_l_xio_win32_poll_lock);
    
    CloseHandle(globus_l_xio_win32_poll_event);
    globus_l_xio_win32_poll_event = 0;
    
    while(globus_l_xio_win32_poll_free)
    {
        globus_l_xio_win32_poll_entry_t * next =
            globus_l_xio_win32_poll_free->next;
            
        globus_free(globus_l_xio_win32_poll_free);
        
        globus_l_xio_win32_poll_free = next;
    }
    
    GlobusXIOSystemDebugExit();
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_xio_win32_complete(
    globus_callback_func_t              callback,
    void *                              user_arg)
{
    globus_l_xio_win32_poll_entry_t *   entry;
    globus_result_t                     result;
    GlobusXIOName(globus_i_xio_win32_complete);

    GlobusXIOSystemDebugEnter();
    
    win32_mutex_lock(&globus_l_xio_win32_poll_lock);
    {
        if(globus_l_xio_win32_poll_free)
        {
            entry = globus_l_xio_win32_poll_free;
            globus_l_xio_win32_poll_free = entry->next;
        }
        else
        {
            entry = (globus_l_xio_win32_poll_entry_t *)
                globus_malloc(sizeof(globus_l_xio_win32_poll_entry_t));
            if(!entry)
            {
                result = GlobusXIOErrorMemory("entry");
                goto error_malloc;
            }
        }
        
        entry->callback = callback;
        entry->user_arg = user_arg;
    
        GlobusLWin32PollQueueEnqueue(entry);
        
        if(globus_l_xio_win32_poll_event_sleeping &&
            !globus_l_xio_win32_poll_event_pending)
        {
            SetEvent(globus_l_xio_win32_poll_event);
            globus_l_xio_win32_poll_event_pending = GLOBUS_TRUE;
        }
    }
    win32_mutex_unlock(&globus_l_xio_win32_poll_lock);
    
    GlobusXIOSystemDebugExit();

    return GLOBUS_SUCCESS;

error_malloc:
    return result;
}

#else

int
globus_i_xio_win32_complete_activate(void)
{
    return GLOBUS_SUCCESS;
}

int
globus_i_xio_win32_complete_deactivate(void)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_xio_win32_complete(
    globus_callback_func_t              callback,
    void *                              user_arg)
{
    return globus_callback_register_oneshot(
        NULL,
        NULL,
        callback,
        user_arg);
}

#endif
