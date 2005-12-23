/*
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */
#include "globus_i_xio_win32.h"

#include "version.h"

static
int
globus_l_xio_win32_event_activate(void);

static
int
globus_l_xio_win32_event_deactivate(void);

globus_module_descriptor_t              globus_i_xio_system_module =
{
    "globus_xio_system_win32",
    globus_l_xio_win32_event_activate,
    globus_l_xio_win32_event_deactivate,
    NULL,
    NULL,
    &local_version
};

typedef struct globus_l_xio_win32_event_entry_s
{
    /* these two are constant */
    struct globus_l_xio_win32_event_thread_s * owner;
    int                                 index;
    
    globus_i_xio_win32_event_cb_t       callback;
    void *                              user_arg;
    globus_bool_t                       post_pending;
} globus_l_xio_win32_event_entry_t;

typedef struct globus_l_xio_win32_event_thread_s
{
    win32_mutex_t                       lock;
    win32_mutex_t                       post_lock;
    win32_mutex_t                       wait_lock;
    int                                 num_entries;
    globus_list_t *                     pending_posts;
    globus_bool_t                       sleeping;
    globus_bool_t                       wakeup_pending;
    
    globus_l_xio_win32_event_entry_t *  entries[MAXIMUM_WAIT_OBJECTS];
    HANDLE                              events[MAXIMUM_WAIT_OBJECTS];
    HANDLE                              thread_handle;
    HANDLE                              wakeup_handle;
} globus_l_xio_win32_event_thread_t;

static win32_mutex_t                    globus_l_xio_win32_event_thread_lock;
static globus_l_xio_win32_event_thread_t ** globus_l_xio_win32_event_threads;
static int                              globus_l_xio_win32_event_thread_count;
static globus_bool_t                    globus_l_xio_win32_event_activated;

static
unsigned 
__stdcall
globus_l_xio_win32_event_thread(
    void *                              arg);

static
int
globus_l_xio_win32_event_activate(void)
{
    WORD                                version;
    WSADATA                             data;
    GlobusXIOName(globus_l_xio_win32_event_activate);
    
    if(globus_i_xio_system_common_activate() != GLOBUS_SUCCESS)
    {
        goto error_common;
    }
    
    GlobusXIOSystemDebugEnter();
    
    version = MAKEWORD(2, 0);
    if(WSAStartup(version, &data) != 0)
    {
        goto error_wsa;
    }
    
    if(globus_i_xio_win32_complete_activate() != GLOBUS_SUCCESS)
    {
        goto error_complete;
    }
    
    if(globus_i_xio_win32_file_activate() != GLOBUS_SUCCESS)
    {
        goto error_file;
    }
    
    if(globus_i_xio_win32_mode_activate() != GLOBUS_SUCCESS)
    {
        goto error_mode;
    }
    
    win32_mutex_init(&globus_l_xio_win32_event_thread_lock, 0);
    globus_l_xio_win32_event_thread_count = 0;
    globus_l_xio_win32_event_threads = 0;
    globus_l_xio_win32_event_activated = GLOBUS_TRUE;

    GlobusXIOSystemDebugExit();
    
    return GLOBUS_SUCCESS;

error_mode:
    globus_i_xio_win32_file_deactivate();
error_file:
    globus_i_xio_win32_complete_deactivate();
error_complete:
    WSACleanup();
error_wsa:
    GlobusXIOSystemDebugExitWithError();
    globus_i_xio_system_common_deactivate();
error_common:
    return GLOBUS_FAILURE;
}

static
void
globus_l_xio_win32_event_thread_destroy(
    globus_l_xio_win32_event_thread_t * thread);

static
int
globus_l_xio_win32_event_deactivate(void)
{
    int                                 i;
    globus_l_xio_win32_event_thread_t * thread;
    GlobusXIOName(globus_l_xio_win32_event_deactivate);
    
    GlobusXIOSystemDebugEnter();
    
    win32_mutex_lock(&globus_l_xio_win32_event_thread_lock);
    {
        globus_l_xio_win32_event_activated = GLOBUS_FALSE;
    }
    win32_mutex_unlock(&globus_l_xio_win32_event_thread_lock);
    
    for(i = 0; i < globus_l_xio_win32_event_thread_count; i++)
    {
        thread = globus_l_xio_win32_event_threads[i];
        
        win32_mutex_lock(&thread->lock);
        {
            thread->wakeup_pending = GLOBUS_TRUE;
            SetEvent(thread->wakeup_handle);
        }
        win32_mutex_unlock(&thread->lock);
        
        while(WaitForSingleObject(
            thread->thread_handle, INFINITE) != WAIT_OBJECT_0)
        {
            /* XXX error */
        }
        
        globus_l_xio_win32_event_thread_destroy(thread);
    }
    
    globus_free(globus_l_xio_win32_event_threads);
    
    win32_mutex_destroy(&globus_l_xio_win32_event_thread_lock);
    
    globus_i_xio_win32_file_deactivate();
    globus_i_xio_win32_complete_deactivate();
    
    WSACleanup();
    
    GlobusXIOSystemDebugExit();
    globus_i_xio_system_common_deactivate();
    
    return GLOBUS_SUCCESS;
}

static
int
globus_l_xio_win32_event_wait(
    const HANDLE *                      handles,
    int                                 count,
    int                                 offset,
    globus_bool_t                       infinite)
{
    DWORD                               rc = -1;
    GlobusXIOName(globus_l_xio_win32_event_wait);
    
    GlobusXIOSystemDebugEnter();
    
    if(offset < count)
    {
        count -= offset;
        
        rc = WaitForMultipleObjects(
            count, handles + offset, FALSE, infinite ? INFINITE : 0);
        if(rc >= WAIT_OBJECT_0 && rc < WAIT_OBJECT_0 + count)
        {
            rc = rc - WAIT_OBJECT_0 + offset;
        }
        else if(rc >= WAIT_ABANDONED_0 && rc < WAIT_ABANDONED_0 + count)
        {
            rc = rc - WAIT_ABANDONED_0 + offset;
        }
        else
        {
            rc = -1;
        }
    }
    
    GlobusXIOSystemDebugExit();
    return rc;
}

static
void
globus_l_xio_win32_event_remove(
    globus_l_xio_win32_event_thread_t * thread,
    globus_l_xio_win32_event_entry_t *  entry);

/**
 * this returns -1 or the prior index of the entry replacing this one
 */
static
int
globus_l_xio_win32_event_dispatch(
    globus_l_xio_win32_event_entry_t *  entry)
{
    int                                 index = -1;
    GlobusXIOName(globus_l_xio_win32_event_dispatch);
    
    GlobusXIOSystemDebugEnter();
    
    if(!entry->callback(entry->user_arg))
    {
        win32_mutex_lock(&entry->owner->lock);
        {
            globus_l_xio_win32_event_remove(entry->owner, entry);
            /* remove always takes last entry */
            index = entry->owner->num_entries;
        }
        win32_mutex_unlock(&entry->owner->lock);
    }
    
    GlobusXIOSystemDebugExit();
    return index;
}

static
unsigned 
__stdcall
globus_l_xio_win32_event_thread(
    void *                              arg)
{
    globus_l_xio_win32_event_thread_t * thread;
    int                                 count;
    DWORD                               index;
    GlobusXIOName(globus_l_xio_win32_event_thread);
    
    GlobusXIOSystemDebugEnter();
    
    thread = (globus_l_xio_win32_event_thread_t *) arg;
    
    do
    {
        /* this lock prevents event objects from being closed while
         * sleeping in the wait() call.  It is only used by
         * unregister_event() as a synchronization point
         */
        win32_mutex_lock(&thread->wait_lock);
        {
            win32_mutex_lock(&thread->lock);
            {
                count = thread->num_entries;
                thread->sleeping = GLOBUS_TRUE;
            }
            win32_mutex_unlock(&thread->lock);
            
            index = globus_l_xio_win32_event_wait(
                thread->events, count, 0, GLOBUS_TRUE);
        }
        win32_mutex_unlock(&thread->wait_lock);
        
        win32_mutex_lock(&thread->post_lock);
        {
            thread->sleeping = GLOBUS_FALSE;
            
            if(index < 0)
            {
                /* XXX error */
            }
            else if(!globus_list_empty(thread->pending_posts))
            {
                /**
                 * dispatch all pending posts
                 */
                globus_l_xio_win32_event_entry_t * consumed;
                globus_l_xio_win32_event_entry_t * entry;
                
                consumed = thread->entries[index];
                globus_l_xio_win32_event_dispatch(consumed);
                
                do
                {
                    entry = (globus_l_xio_win32_event_entry_t *)
                        globus_list_remove(
                            &thread->pending_posts, thread->pending_posts);
                    entry->post_pending = GLOBUS_FALSE;
                    
                    if(entry != consumed)
                    {
                        globus_l_xio_win32_event_dispatch(entry);
                    }
                    
                } while(!globus_list_empty(thread->pending_posts));
            }
            else
            {
                /**
                 * dispatch consumed event and check rest with 0 timeout
                 * The added complexity here ensures we don't starve anyone
                 */
                do
                {
                    int                 replacement;
                    
                    replacement = globus_l_xio_win32_event_dispatch(
                        thread->entries[index]);
                        
                    if(replacement < 0 || replacement >= count)
                    {
                        /**
                         * either wasn't removed or the replacement is
                         * outside the range I am processing in this iteration
                         * 
                         * skip to next entry
                         */
                        index++;
                    }
                    else
                    {
                        /**
                         * replacement is in my range, reduce count and
                         * maintain current index.
                         */
                        count--;
                    }
                    
                    /* check the rest */
                    index = globus_l_xio_win32_event_wait(
                        thread->events, count, index, GLOBUS_FALSE);
                } while(index >= 0);
            }
        }
        win32_mutex_unlock(&thread->post_lock);
        
    } while(globus_l_xio_win32_event_activated);

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_bool_t
globus_l_xio_win32_event_wakeup_cb(
    void *                              arg)
{
    globus_l_xio_win32_event_thread_t * thread;
    GlobusXIOName(globus_l_xio_win32_event_wakeup_cb);
    
    GlobusXIOSystemDebugEnter();
    
    thread = (globus_l_xio_win32_event_thread_t *) arg;
    
    win32_mutex_lock(&thread->lock);
    {
        thread->wakeup_pending = GLOBUS_FALSE;
    }
    win32_mutex_unlock(&thread->lock);
    
    GlobusXIOSystemDebugExit();
    
    return GLOBUS_TRUE;
}

static
globus_result_t
globus_l_xio_win32_event_add(
    globus_l_xio_win32_event_entry_t ** uentry,
    globus_l_xio_win32_event_thread_t * thread,
    HANDLE                              event_handle,
    globus_i_xio_win32_event_cb_t       callback,
    void *                              user_arg);

static
globus_result_t
globus_l_xio_win32_event_thread_init(
    globus_l_xio_win32_event_thread_t ** uthread)
{
    globus_result_t                     result;
    globus_l_xio_win32_event_thread_t * thread;
    globus_l_xio_win32_event_entry_t *  entry;
    GlobusXIOName(globus_l_xio_win32_event_thread_init);
    
    GlobusXIOSystemDebugEnter();
    
    thread = (globus_l_xio_win32_event_thread_t *)
        globus_calloc(1, sizeof(globus_l_xio_win32_event_thread_t));
    if(!thread)
    {
        result = GlobusXIOErrorMemory("thread");
        goto error_alloc;
    }
    
    thread->wakeup_handle = CreateEvent(0, FALSE, FALSE, 0);
    if(thread->wakeup_handle == 0)
    {
        result = GlobusXIOErrorSystemError(
            "CreateEvent", GetLastError());
        goto error_create;
    }
    
    result = globus_l_xio_win32_event_add(
        &entry, thread, thread->wakeup_handle,
        globus_l_xio_win32_event_wakeup_cb, thread);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_add;
    }
    
    win32_mutex_init(&thread->lock, 0);
    win32_mutex_init(&thread->post_lock, 0);
    win32_mutex_init(&thread->wait_lock, 0);
    
    *uthread = thread;
    
    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_add:
    CloseHandle(thread->wakeup_handle);
error_create:
    globus_free(thread);
error_alloc:
    GlobusXIOSystemDebugExitWithError();
    return result;
}

static
void
globus_l_xio_win32_event_thread_destroy(
    globus_l_xio_win32_event_thread_t * thread)
{
    int                                 i;
    GlobusXIOName(globus_l_xio_win32_event_thread_destroy);
    
    GlobusXIOSystemDebugEnter();
    
    win32_mutex_destroy(&thread->wait_lock);
    win32_mutex_destroy(&thread->post_lock);
    win32_mutex_destroy(&thread->lock);
    CloseHandle(thread->wakeup_handle);
    
    if(thread->thread_handle)
    {
        CloseHandle(thread->thread_handle);
    }
    
    globus_list_free(thread->pending_posts);
    
    for(i = 0; i < MAXIMUM_WAIT_OBJECTS; i++)
    {
        if(thread->entries[i])
        {
            globus_free(thread->entries[i]);
        }
    }
    
    globus_free(thread);
    
    GlobusXIOSystemDebugExit();
}

static
globus_result_t
globus_l_xio_win32_event_get_thread(
    globus_l_xio_win32_event_thread_t ** uthread)
{
    int                                 i;
    globus_l_xio_win32_event_thread_t * thread = 0;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_win32_event_get_thread);
    
    GlobusXIOSystemDebugEnter();
    
    for(i = 0; i < globus_l_xio_win32_event_thread_count; i++)
    {
        if(globus_l_xio_win32_event_threads[i]->num_entries < 
            MAXIMUM_WAIT_OBJECTS)
        {
            thread = globus_l_xio_win32_event_threads[i];
            break;
        }
    }
    
    if(!thread)
    {
        /* make room for another MAXIMUM_WAIT_OBJECTS (64) events */
        globus_l_xio_win32_event_thread_t ** new_threads;
         
        new_threads = (globus_l_xio_win32_event_thread_t **)
            globus_realloc(
                globus_l_xio_win32_event_threads,
                sizeof(globus_l_xio_win32_event_thread_t) *
                    (globus_l_xio_win32_event_thread_count + 1));
        if(!new_threads)
        {
            result = GlobusXIOErrorMemory("new_threads");
            goto error_realloc;
        }
        
        globus_l_xio_win32_event_threads = new_threads;
        
        result = globus_l_xio_win32_event_thread_init(&thread);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_init;
        }
        
        globus_l_xio_win32_event_threads[
            globus_l_xio_win32_event_thread_count] = thread;
        
        thread->thread_handle = (HANDLE) _beginthreadex(
            0, 0, globus_l_xio_win32_event_thread, thread, 0, 0);
        if(thread->thread_handle == 0)
        {
            /* technically, i should be checking errno, but a look at the
             * source code for _beginthreadex() shows LastError untouched
             * after CreateThread fails
             */
            result = GlobusXIOErrorSystemError(
                "_beginthreadex", GetLastError());
            goto error_thread;
        }
        
        globus_l_xio_win32_event_thread_count++;
    }
    
    *uthread = thread;
    
    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_thread:
    globus_l_xio_win32_event_thread_destroy(thread);
error_init:
error_realloc:
    GlobusXIOSystemDebugExitWithError();
    return result;
}

/* called with thread entry locked and guaranteed room for one more entry */
static
globus_result_t
globus_l_xio_win32_event_add(
    globus_l_xio_win32_event_entry_t ** uentry,
    globus_l_xio_win32_event_thread_t * thread,
    HANDLE                              event_handle,
    globus_i_xio_win32_event_cb_t       callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_xio_win32_event_entry_t *  entry;
    GlobusXIOName(globus_l_xio_win32_event_add);
    
    GlobusXIOSystemDebugEnter();
    
    if(!thread->entries[thread->num_entries])
    {
        entry = (globus_l_xio_win32_event_entry_t *)
            globus_malloc(sizeof(globus_l_xio_win32_event_entry_t));
        if(!entry)
        {
            result = GlobusXIOErrorMemory("entry");
            goto error_entry;
        }
        
        entry->owner = thread;
        entry->index = thread->num_entries;
        thread->entries[thread->num_entries] = entry;
    }
    else
    {
        entry = thread->entries[thread->num_entries];
    }
    
    thread->num_entries++;

    entry->callback = callback;
    entry->user_arg = user_arg;
    thread->events[entry->index] = event_handle;
    
    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_entry:
    GlobusXIOSystemDebugExitWithError();
    return result;
}

/* called with thread entry locked */
static
void
globus_l_xio_win32_event_remove(
    globus_l_xio_win32_event_thread_t * thread,
    globus_l_xio_win32_event_entry_t *  entry)
{
    globus_l_xio_win32_event_entry_t *  shift_entry;
    GlobusXIOName(globus_l_xio_win32_event_remove);
    
    GlobusXIOSystemDebugEnter();
    
    thread->num_entries--;
    
    /* if entry isn't already the last one, swap it with the last one */
    if(entry->index < thread->num_entries)
    {
        /* swap last entry with the 'removed' one */
        shift_entry = thread->entries[thread->num_entries];
        shift_entry->index = entry->index;
        thread->entries[shift_entry->index] = shift_entry;
        
        /* put old entry in it's place (effectively a free store) */
        entry->index = thread->num_entries;
        thread->entries[entry->index] = entry;
        
        /* move last event object to its new location */
        thread->events[shift_entry->index] =
            thread->events[thread->num_entries];
    }
    
    GlobusXIOSystemDebugExit();
}

globus_result_t
globus_i_xio_win32_event_register(
    globus_i_xio_win32_event_entry_t *  entry_handle,
    HANDLE                              event_handle,
    globus_i_xio_win32_event_cb_t       callback,
    void *                              user_arg)
{
    globus_l_xio_win32_event_thread_t * thread;
    globus_l_xio_win32_event_entry_t *  entry;
    globus_result_t                     result;
    globus_bool_t                       do_wakeup = GLOBUS_FALSE;
    GlobusXIOName(globus_i_xio_win32_event_register);
    
    GlobusXIOSystemDebugEnter();
    
    win32_mutex_lock(&globus_l_xio_win32_event_thread_lock);
    
    if(!globus_l_xio_win32_event_activated)
    {
        result = GlobusXIOErrorNotActivated();
        goto error_deactivated;
    }
    
    result = globus_l_xio_win32_event_get_thread(&thread);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_nothread;
    }
    
    win32_mutex_lock(&thread->lock);
    {
        result = globus_l_xio_win32_event_add(
            &entry, thread, event_handle, callback, user_arg);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_add;
        }
        
        if(thread->sleeping && !thread->wakeup_pending)
        {
            thread->wakeup_pending = GLOBUS_TRUE;
            do_wakeup = GLOBUS_TRUE;
        }
    }
    win32_mutex_unlock(&thread->lock);
    
    win32_mutex_unlock(&globus_l_xio_win32_event_thread_lock);
    
    if(do_wakeup)
    {
        /**
         * I do this outside the lock to avoid immediate contention in the
         * thead.  This leaves the possibility that the thread is gone
         * before this call, resulting in segv.  However, this is only
         * possible if we get deactivated, which means someone's being dumb
         * and using a deactivated lib.
         */
        SetEvent(thread->wakeup_handle);
    }
    
    *entry_handle = entry;
    
    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_add:
    win32_mutex_unlock(&thread->lock);
    
error_nothread:
error_deactivated:
    win32_mutex_unlock(&globus_l_xio_win32_event_thread_lock);
    
    GlobusXIOSystemDebugExitWithError();
    return result;
}

static
globus_bool_t
globus_l_xio_win32_event_unregister_cb(
    void *                              user_arg)
{
    GlobusXIOName(globus_l_xio_win32_event_unregister_cb);
    
    GlobusXIOSystemDebugEnter();
    
    GlobusXIOSystemDebugExit();
    return GLOBUS_FALSE;
}

/* the complexity here is to ensure that the event object will not be waited on
 * when this call returns.  this allows user to immediately close the event
 * object
 * 
 * this must be called with post_lock held
 */
void
globus_i_xio_win32_event_unregister(
    globus_i_xio_win32_event_entry_t    entry_handle)
{
    globus_l_xio_win32_event_thread_t * thread;
    GlobusXIOName(globus_i_xio_win32_event_unregister);
    
    GlobusXIOSystemDebugEnter();
    
    thread = entry_handle->owner;
    
    entry_handle->callback = globus_l_xio_win32_event_unregister_cb;
    
    win32_mutex_lock(&thread->lock);
    {
        if(thread->sleeping && !thread->wakeup_pending)
        {
            thread->wakeup_pending = GLOBUS_TRUE;
            SetEvent(thread->wakeup_handle);
        }
    }
    win32_mutex_unlock(&thread->lock);
        
    win32_mutex_lock(&thread->wait_lock);
    {
        if(thread->sleeping)
        {
            /* thread is waiting on post_lock
             * wait returned a signaled event, can't just remove entry
             * post event to force above callback to remove entry
             */
            globus_i_xio_win32_event_post(entry_handle);
        }
        else
        {
            /* thread is waiting on wait_lock, fake this event
             * above callback will cause it to be removed
             */
            if(entry_handle->post_pending)
            {
                /* remove posted event */
                globus_list_remove(
                    &thread->pending_posts,
                    globus_list_search(
                        thread->pending_posts, entry_handle));
                
                entry_handle->post_pending = GLOBUS_FALSE;
            }
            
            globus_l_xio_win32_event_dispatch(entry_handle);
        }
    }
    win32_mutex_unlock(&thread->wait_lock);
    
    GlobusXIOSystemDebugExit();
}

void
globus_i_xio_win32_event_lock(
    globus_i_xio_win32_event_entry_t    entry_handle)
{
    GlobusXIOName(globus_i_xio_win32_event_lock);
    
    GlobusXIOSystemDebugEnter();
    win32_mutex_lock(&entry_handle->owner->post_lock);
    GlobusXIOSystemDebugExit();
}

void
globus_i_xio_win32_event_unlock(
    globus_i_xio_win32_event_entry_t    entry_handle)
{
    GlobusXIOName(globus_i_xio_win32_event_unlock);
    
    GlobusXIOSystemDebugEnter();
    win32_mutex_unlock(&entry_handle->owner->post_lock);
    GlobusXIOSystemDebugExit();
}

/* this must be called with post_lock held */
void
globus_i_xio_win32_event_post(
    globus_i_xio_win32_event_entry_t    entry_handle)
{
    globus_l_xio_win32_event_thread_t * thread;
    GlobusXIOName(globus_i_xio_win32_event_post);
    
    GlobusXIOSystemDebugEnter();
    
    thread = entry_handle->owner;
    
    if(!entry_handle->post_pending)
    {
        globus_list_insert(&thread->pending_posts, entry_handle);
        entry_handle->post_pending = GLOBUS_TRUE;
        
        win32_mutex_lock(&thread->lock);
        {
            if(thread->sleeping && !thread->wakeup_pending)
            {
                thread->wakeup_pending = GLOBUS_TRUE;
                SetEvent(thread->wakeup_handle);
            }
        }
        win32_mutex_unlock(&thread->lock);
    }
    
    GlobusXIOSystemDebugExit();
}

