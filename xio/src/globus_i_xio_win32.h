/*
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */
#ifndef GLOBUS_I_XIO_WIN32_H_
#define GLOBUS_I_XIO_WIN32_H_

#include "globus_i_xio_system_common.h"
#include <Windows.h>
#include <process.h>
#include <Winsock2.h>

typedef struct globus_l_xio_win32_event_entry_s *
    globus_i_xio_win32_event_entry_t;
    
/**
 * this callback is called from within threads managed by this lib.
 * 
 * you must synchronize access between this and globus interface calls
 * and you must not call into globus calls unless globus has been built
 * threaded.
 * 
 * this callback is called while holding the 
 * globus_i_xio_win32_event_lock()
 * 
 * return false to unregister event handle, true to keep it
 * 
 * (this callback will not be reentered for any given event object)
 */
typedef
globus_bool_t
(*globus_i_xio_win32_event_cb_t)(
    void *                              user_arg);

globus_result_t
globus_i_xio_win32_event_register(
    globus_i_xio_win32_event_entry_t *  entry_handle,
    HANDLE                              event_handle,
    globus_i_xio_win32_event_cb_t       callback,
    void *                              user_arg);

/**
 * must be called after globus_i_xio_win32_event_lock()
 * Do NOT call within globus_i_xio_win32_event_cb_t callback
 */
void
globus_i_xio_win32_event_unregister(
    globus_i_xio_win32_event_entry_t    entry_handle);

/**
 * this lock effectively prevents events from occurring on the specified
 * handle (and others, but not all) while it is held.  This lock is also
 * held while calling event callbacks (so, don't call it within callbacks)
 */
void
globus_i_xio_win32_event_lock(
    globus_i_xio_win32_event_entry_t    entry_handle);

void
globus_i_xio_win32_event_unlock(
    globus_i_xio_win32_event_entry_t    entry_handle);

/**
 * must be called after globus_i_xio_win32_event_lock()
 * Do NOT call within globus_i_xio_win32_event_cb_t callback
 */
void
globus_i_xio_win32_event_post(
    globus_i_xio_win32_event_entry_t    entry_handle);

int
globus_i_xio_win32_complete_activate(void);

int
globus_i_xio_win32_complete_deactivate(void);

int
globus_i_xio_win32_file_activate(void);

int
globus_i_xio_win32_file_deactivate(void);

/**
 * dispatch callback to globus threads
 */
globus_result_t
globus_i_xio_win32_complete(
    globus_callback_func_t              callback,
    void *                              user_arg);

int
globus_i_xio_win32_mode_activate(void);

globus_bool_t
globus_i_xio_win32_mode_is_overlapped(
    HANDLE                              handle);

typedef CRITICAL_SECTION win32_mutex_t;

#define win32_mutex_init(x, y) InitializeCriticalSection(x)
#define win32_mutex_destroy(x) DeleteCriticalSection(x)
#define win32_mutex_lock(x) EnterCriticalSection(x)
#define win32_mutex_unlock(x) LeaveCriticalSection(x)

#define GlobusXIOSystemDebugSysError(message, err)                          \
    do                                                                      \
    {                                                                       \
        if(GlobusDebugTrue(                                                 \
            GLOBUS_XIO_SYSTEM, GLOBUS_I_XIO_SYSTEM_DEBUG_INFO))             \
        {                                                                   \
            char *                      msg = NULL;                         \
            int                         err_ = err;                         \
                                                                            \
            FormatMessage(                                                  \
                FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,  \
                NULL,                                                       \
                err_,                                                       \
                0,                                                          \
                (LPTSTR)&msg,                                               \
                0,                                                          \
                NULL);                                                      \
                                                                            \
            GlobusDebugMyPrintf(                                            \
                GLOBUS_XIO_SYSTEM,                                          \
                ("[%s] %s: %d:%s", _xio_name, message, err_, msg));         \
                                                                            \
            if(msg)                                                         \
            {                                                               \
                LocalFree(msg);                                             \
            }                                                               \
        }                                                                   \
    } while(0)

#endif
