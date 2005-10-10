/*
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */
#include "globus_i_xio_win32.h"

/**
 * Design notes:
 *
 * problem:  from xio's perspective, all threads have unknown lifetime.  io
 * requests can not be bound to the lifetime of the requesting thread.
 * if i start async io on one and the thread terminates before that io
 * completes, it will be canceled by win32.
 *
 * solutions: in order of ease.
 *
 * 1)
 * always block the request thread and do the operation there-- usually fast,
 * sometimes network files will stall app for up to 30 seconds.
 *
 * 2)
 * dispatch all io to separate worker thread- io can never be unexpectedly
 * canceled, so it's most reliable, but always pay double context switch
 * perf hit -- especially painful for small buffer (less than 512) writes
 * (which should only happen in test suites or conversations, in which the
 * round trip time will trump context switch time)
 *
 * 3)
 * add a thread-hold to globus' win32 thread lib to prevent thread from
 * terminating while io is pending on it, but this only protects against
 * globus threads terminating (which means all of our apps will be fine) If
 * win32 developers use globus libs and create their own win32 threads
 * directly and terminate them before io completes, it will be canceled.
 * this may be ok, since most people that would create own thread will keep
 * them around until io is complete anyway.  this has almost as good perf as
 * blocking would in its best case and will never stall the app.
 *
 *
 * This implementation is based on #2
 * NOTE: cancelation of file i/o will not be supported at this time because
 * CancelIo does not discriminate between read or write operations.
 *
 * Blocking io is implemented by queuing asynchronous operations on the
 * request thread.  This means that user APCs may also be run.
 */

/* assume 10ms slices, try for up to 5s since the system may be thrashing */
#define LOCKED_PAGES_RETRY_COUNT    500

#define GlobusOffToOverlapped(overlapped, off)                              \
{                                                                           \
    LARGE_INTEGER                       x;                                  \
    x.QuadPart = off;                                                       \
    overlapped.Offset = x.LowPart;                                          \
    overlapped.OffsetHigh = x.HighPart;                                     \
}

typedef struct
{
    OVERLAPPED                          overlapped; /* must be first */
    globus_bool_t                       pending;
     /* io apc pending (does not track user apc) */
    globus_bool_t                       apc_pending;
    
    globus_xio_operation_t              op;
    globus_off_t                        offset;
    globus_size_t                       waitforbytes;
    globus_xio_iovec_t *                iov;
    int                                 iovc;

    struct iovec *                      start_iov;
    int                                 start_iovc;

    globus_object_t *                   error;
    globus_size_t                       nbytes;
    globus_xio_system_data_callback_t   callback;
    void *                              user_arg;

    /* reference to containing handle, here to avoid goofy pointer math */
    struct globus_l_xio_win32_file_s *  handle;
} globus_l_xio_win32_file_op_t;

typedef struct globus_l_xio_win32_file_s
{
    win32_mutex_t                       lock;
    HANDLE                              fd;
    globus_bool_t                       is_overlapped;
    
    globus_l_xio_win32_file_op_t        read_op;
    globus_l_xio_win32_file_op_t        write_op;
} globus_l_xio_win32_file_t;

static HANDLE                           globus_l_xio_win32_file_thread_handle;
static globus_bool_t                    globus_l_xio_win32_activated;

static
unsigned
__stdcall
globus_l_xio_win32_file_thread(
    void *                              arg);

static
void
CALLBACK
globus_l_xio_win32_file_deactivate_apc(
    ULONG_PTR                           arg);

int
globus_i_xio_win32_file_activate(void)
{
    GlobusXIOName(globus_i_xio_win32_file_activate);

    GlobusXIOSystemDebugEnter();

    globus_l_xio_win32_file_thread_handle = (HANDLE) _beginthreadex(
        0, 0, globus_l_xio_win32_file_thread, 0, 0, 0);
    if(globus_l_xio_win32_file_thread_handle == 0)
    {
        goto error_thread;
    }

    globus_l_xio_win32_activated = GLOBUS_TRUE;

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_thread:
    GlobusXIOSystemDebugExitWithError();
    return GLOBUS_FAILURE;
}

int
globus_i_xio_win32_file_deactivate(void)
{
    GlobusXIOName(globus_i_xio_win32_file_deactivate);

    GlobusXIOSystemDebugEnter();

    globus_l_xio_win32_activated = GLOBUS_FALSE;
    QueueUserAPC(
        globus_l_xio_win32_file_deactivate_apc,
        globus_l_xio_win32_file_thread_handle,
        0);

    while(WaitForSingleObject(
        globus_l_xio_win32_file_thread_handle, INFINITE) != WAIT_OBJECT_0)
    {
        /* XXX error */
    }

    CloseHandle(globus_l_xio_win32_file_thread_handle);

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;
}

static
unsigned
__stdcall
globus_l_xio_win32_file_thread(
    void *                              arg)
{
    GlobusXIOName(globus_l_xio_win32_file_thread);

    GlobusXIOSystemDebugEnter();

    while(globus_l_xio_win32_activated)
    {
        SleepEx(INFINITE, GLOBUS_TRUE);  /* the APCs below execute here */
    }

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_win32_file_kickout(
    void *                              user_arg)
{
    globus_l_xio_win32_file_op_t *      op;
    HANDLE                              fd;
    struct iovec *                      start_iov;
    int                                 start_iovc;
    globus_object_t *                   error;
    globus_size_t                       nbytes;
    globus_xio_system_data_callback_t   callback;
    GlobusXIOName(globus_l_xio_win32_file_kickout);

    op = (globus_l_xio_win32_file_op_t *) user_arg;
    fd = op->handle->fd;

    GlobusXIOSystemDebugEnterFD(fd);

    start_iov = op->start_iov;
    start_iovc = op->start_iovc;
    error = op->error;
    nbytes = op->nbytes;
    callback = op->callback;
    user_arg = op->user_arg;

    win32_mutex_lock(&op->handle->lock);
    {
        op->pending = GLOBUS_FALSE;
    }
    win32_mutex_unlock(&op->handle->lock);

    callback(
        error ? globus_error_put(error) : GLOBUS_SUCCESS, nbytes, user_arg);

    GlobusIXIOSystemFreeIovec(start_iovc, start_iov);

    GlobusXIOSystemDebugExitFD(fd);
}

static
void
CALLBACK
globus_l_xio_win32_file_deactivate_apc(
    ULONG_PTR                           arg)
{
    GlobusXIOName(globus_l_xio_win32_file_deactivate_apc);

    GlobusXIOSystemDebugEnter();
    /* do nothing, this just forces SleepEx to awaken */
    GlobusXIOSystemDebugExit();
}

static
void
CALLBACK
globus_l_xio_win32_file_start_read_apc(
    ULONG_PTR                           arg);

static
void
CALLBACK
globus_l_xio_win32_file_start_write_apc(
    ULONG_PTR                           arg);

static
void
CALLBACK
globus_l_xio_win32_file_read_apc(
    DWORD                               error,
    DWORD                               nbytes,
    LPOVERLAPPED                        overlapped)
{
    globus_l_xio_win32_file_op_t *      op;
    HANDLE                              fd;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_win32_file_read_apc);

    op = (globus_l_xio_win32_file_op_t *) overlapped;
    fd = op->handle->fd;

    GlobusXIOSystemDebugEnterFD(fd);
    
    if(op->op != 0)
    {
        globus_xio_operation_refresh_timeout(op->op);
    }
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Read %ld bytes\n", _xio_name, (long)nbytes));

    GlobusXIOSystemDebugRawBuffer(nbytes, op->iov->iov_base);
        
    op->nbytes += nbytes;
    op->offset += nbytes;
    GlobusIXIOUtilAdjustIovec(op->iov, op->iovc, nbytes);
    op->apc_pending = GLOBUS_FALSE;
    
    if(error == ERROR_SUCCESS && op->nbytes < op->waitforbytes)
    {
        if(op->iovc > 0)
        {
            /* start next read.
             * this could result in this function being reentered on error
             * not a problem, though.
             */
            globus_l_xio_win32_file_start_read_apc((ULONG_PTR)op);
            goto reading_more;
        }
        else
        {
            op->error = GlobusXIOErrorObjParameter("waitforbytes");
        }
    }
    else if(error == ERROR_HANDLE_EOF)
    {
        op->error = GlobusXIOErrorObjEOF();
    }
    else if(error != ERROR_SUCCESS)
    {
        op->error = GlobusXIOErrorObjSystemError("ReadFileEx", error);
    }

    if(op->op != 0)
    {
        result = globus_i_xio_win32_complete(
            globus_l_xio_win32_file_kickout, op);
        /* really cant do anything else */
        if(result != GLOBUS_SUCCESS)
        {
            globus_panic(
                GLOBUS_XIO_SYSTEM_MODULE,
                result,
                _XIOSL("[%s:%d] Couldn't register callback"),
                _xio_name,
                __LINE__);
        }
    }

reading_more:
    GlobusXIOSystemDebugExitFD(fd);
}

static
void
CALLBACK
globus_l_xio_win32_file_write_apc(
    DWORD                               error,
    DWORD                               nbytes,
    LPOVERLAPPED                        overlapped)
{
    globus_l_xio_win32_file_op_t *      op;
    HANDLE                              fd;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_win32_file_write_apc);

    op = (globus_l_xio_win32_file_op_t *) overlapped;
    fd = op->handle->fd;

    GlobusXIOSystemDebugEnterFD(fd);
    
    if(op->op != 0)
    {
        globus_xio_operation_refresh_timeout(op->op);
    }
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Wrote %ld bytes\n", _xio_name, (long)nbytes));

    GlobusXIOSystemDebugRawBuffer(nbytes, op->iov->iov_base);
    
    op->nbytes += nbytes;
    op->offset += nbytes;
    GlobusIXIOUtilAdjustIovec(op->iov, op->iovc, nbytes);
    op->apc_pending = GLOBUS_FALSE;
    
    if(error == ERROR_SUCCESS && op->nbytes < op->waitforbytes)
    {
        if(op->iovc > 0)
        {
            /* start next write.
             * this could result in this function being reentered on error
             * not a problem, though.
             */
            globus_l_xio_win32_file_start_write_apc((ULONG_PTR)op);
            goto writing_more;
        }
        else
        {
            op->error = GlobusXIOErrorObjParameter("waitforbytes");
        }
    }
    else if(error != ERROR_SUCCESS)
    {
        op->error = GlobusXIOErrorObjSystemError("WriteFileEx", error);
    }

    if(op->op != 0)
    {
        result = globus_i_xio_win32_complete(
            globus_l_xio_win32_file_kickout, op);
        /* really cant do anything else */
        if(result != GLOBUS_SUCCESS)
        {
            globus_panic(
                GLOBUS_XIO_SYSTEM_MODULE,
                result,
                _XIOSL("[%s:%d] Couldn't register callback"),
                _xio_name,
                __LINE__);
        }
    }

writing_more:
    GlobusXIOSystemDebugExitFD(fd);
}

static
void
CALLBACK
globus_l_xio_win32_file_start_read_apc(
    ULONG_PTR                           arg)
{
    globus_l_xio_win32_file_op_t *      op;
    HANDLE                              fd;
    int                                 retry = LOCKED_PAGES_RETRY_COUNT;
    int                                 error;
    GlobusXIOName(globus_l_xio_win32_file_start_read_apc);

    op = (globus_l_xio_win32_file_op_t *) arg;
    fd = op->handle->fd;

    GlobusXIOSystemDebugEnterFD(fd);
    
    op->apc_pending = GLOBUS_TRUE;
    do
    {
        error = ERROR_SUCCESS;
        memset(&op->overlapped, 0, sizeof(OVERLAPPED));
        GlobusOffToOverlapped(op->overlapped, op->offset);

        if(!ReadFileEx(fd,
            op->iov->iov_base, op->iov->iov_len, &op->overlapped,
            globus_l_xio_win32_file_read_apc))
        {
            error = GetLastError();
        }

        /* if the following is true, we sleep for the rest of this timeslice
         * and try again.  This happens when there are too many outstanding
         * asynchronous operations and the os cant lock down any more pages
         */
    } while((error == ERROR_INVALID_USER_BUFFER ||
        error == ERROR_NOT_ENOUGH_MEMORY) && retry-- > 0 && (Sleep(0), 1));

    if(retry < LOCKED_PAGES_RETRY_COUNT)
    {
        GlobusXIOSystemDebugPrintf(
            GLOBUS_I_XIO_SYSTEM_DEBUG_INFO,
            ("[%s] fd=%lu, Retried read %d times\n",
                _xio_name, (unsigned long)fd,
                LOCKED_PAGES_RETRY_COUNT - (retry > 0 ? retry : 0)));
    }

    if(error != ERROR_SUCCESS)
    {
        globus_l_xio_win32_file_read_apc(error, 0, &op->overlapped);
    }

    GlobusXIOSystemDebugExitFD(fd);
}

static
void
CALLBACK
globus_l_xio_win32_file_start_write_apc(
    ULONG_PTR                           arg)
{
    globus_l_xio_win32_file_op_t *      op;
    HANDLE                              fd;
    int                                 retry = LOCKED_PAGES_RETRY_COUNT;
    int                                 error;
    GlobusXIOName(globus_l_xio_win32_file_start_write_apc);

    op = (globus_l_xio_win32_file_op_t *) arg;
    fd = op->handle->fd;

    GlobusXIOSystemDebugEnterFD(fd);
    
    op->apc_pending = GLOBUS_TRUE;
    do
    {
        error = ERROR_SUCCESS;
        memset(&op->overlapped, 0, sizeof(OVERLAPPED));
        GlobusOffToOverlapped(op->overlapped, op->offset);

        if(!WriteFileEx(fd,
            op->iov->iov_base, op->iov->iov_len, &op->overlapped,
            globus_l_xio_win32_file_write_apc))
        {
            error = GetLastError();
        }

        /* if the following is true, we sleep for the rest of this timeslice
         * and try again.  This happens when there are too many outstanding
         * asynchronous operations and the os cant lock down any more pages
         */
    } while((error == ERROR_INVALID_USER_BUFFER ||
        error == ERROR_NOT_ENOUGH_MEMORY) && retry-- > 0 && (Sleep(0), 1));

    if(retry < LOCKED_PAGES_RETRY_COUNT)
    {
        GlobusXIOSystemDebugPrintf(
            GLOBUS_I_XIO_SYSTEM_DEBUG_INFO,
            ("[%s] fd=%lu, Retried write %d times\n",
                _xio_name, (unsigned long)fd,
                LOCKED_PAGES_RETRY_COUNT - (retry > 0 ? retry : 0)));
    }

    if(error != ERROR_SUCCESS)
    {
        globus_l_xio_win32_file_write_apc(error, 0, &op->overlapped);
    }

    GlobusXIOSystemDebugExitFD(fd);
}

globus_result_t
globus_xio_system_file_init(
    globus_xio_system_file_handle_t *   handle,
    globus_xio_system_file_t            fd)
{
    globus_result_t                     result;
    globus_l_xio_win32_file_t *         handle;
    GlobusXIOName(globus_xio_system_file_init);

    GlobusXIOSystemDebugEnterFD(fd);

    handle = (globus_l_xio_win32_file_t *)
        globus_calloc(1, sizeof(globus_l_xio_win32_file_t));
    if(!handle)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error_alloc;
    }

    win32_mutex_init(&handle->lock, 0);

    handle->fd = fd;
    handle->read_op.handle = handle;
    handle->write_op.handle = handle;
    handle->is_overlapped = globus_i_xio_win32_mode_is_overlapped(fd);
    
    if(!handle->is_overlapped)
    {
        GlobusXIOSystemDebugPrintf(
            GLOBUS_I_XIO_SYSTEM_DEBUG_INFO,
            ("[%s] fd=%lu, Handle is NOT overlapped\n",
                _xio_name, (unsigned long)fd));
    }
    
    *uhandle = handle;

    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_alloc:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

void
globus_xio_system_file_destroy(
    globus_xio_system_file_handle_t     handle)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_file_destroy);

    GlobusXIOSystemDebugEnterFD(handle->fd);

    win32_mutex_destroy(&handle->lock);

    GlobusXIOSystemDebugExitFD(handle->fd);
    globus_free(handle);
}

/* called only on non-overlapped handles */
static
void
globus_l_xio_win32_file_blocking_read(
    globus_l_xio_win32_file_op_t *      op)
{
    DWORD                               nbytes;
    HANDLE                              fd = op->handle->fd;
    int                                 error;
    int                                 rc;
    GlobusXIOName(globus_l_xio_win32_file_blocking_read);

    GlobusXIOSystemDebugEnterFD(fd);

    do
    {
        if(op->nbytes < op->waitforbytes && op->iovc <= 0)
        {
            op->error = GlobusXIOErrorObjParameter("waitforbytes");
            goto error_param;
        }
        
        memset(&op->overlapped, 0, sizeof(OVERLAPPED));
        GlobusOffToOverlapped(op->overlapped, op->offset);
        
        rc = ReadFile(fd,
            op->iov->iov_base, op->iov->iov_len, &nbytes, &op->overlapped);
            
        GlobusXIOSystemDebugPrintf(
            GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
            ("[%s] Read %ld bytes\n", _xio_name, (long)nbytes));

        GlobusXIOSystemDebugRawBuffer(nbytes, op->iov->iov_base);
        
        op->nbytes += nbytes;
        op->offset += nbytes;
        GlobusIXIOUtilAdjustIovec(op->iov, op->iovc, nbytes);
        
        if(!rc || nbytes == 0)
        {
            error = GetLastError();
            if(rc && nbytes == 0 || error == ERROR_HANDLE_EOF)
            {
                op->error = GlobusXIOErrorObjEOF();
            }
            else
            {
                op->error = GlobusXIOErrorObjSystemError("ReadFile", error);
            }
            
            goto error_read;
        }
    } while(op->nbytes < op->waitforbytes);
        
    GlobusXIOSystemDebugExitFD(fd);
    return;

error_read:
error_param:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
}

/* called only on non-overlapped handles */
static
void
globus_l_xio_win32_file_blocking_write(
    globus_l_xio_win32_file_op_t *      op)
{
    DWORD                               nbytes;
    HANDLE                              fd = op->handle->fd;
    int                                 error;
    int                                 rc;
    GlobusXIOName(globus_l_xio_win32_file_blocking_write);

    GlobusXIOSystemDebugEnterFD(fd);

    do
    {
        if(op->nbytes < op->waitforbytes && op->iovc <= 0)
        {
            op->error = GlobusXIOErrorObjParameter("waitforbytes");
            goto error_param;
        }
        
        memset(&op->overlapped, 0, sizeof(OVERLAPPED));
        GlobusOffToOverlapped(op->overlapped, op->offset);
        
        rc = WriteFile(fd,
            op->iov->iov_base, op->iov->iov_len, &nbytes, &op->overlapped);
            
        GlobusXIOSystemDebugPrintf(
            GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
            ("[%s] Wrote %ld bytes\n", _xio_name, (long)nbytes));

        GlobusXIOSystemDebugRawBuffer(nbytes, op->iov->iov_base);
        
        op->nbytes += nbytes;
        op->offset += nbytes;
        GlobusIXIOUtilAdjustIovec(op->iov, op->iovc, nbytes);
        
        if(!rc)
        {
            op->error = GlobusXIOErrorObjSystemError(
                "WriteFile", GetLastError());
            goto error_write;
        }
    } while(op->nbytes < op->waitforbytes);
        
    GlobusXIOSystemDebugExitFD(fd);
    return;

error_write:
error_param:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
}

/* if op == null, just set up the operation... internal use only */
globus_result_t
globus_xio_system_file_register_read(
    globus_xio_operation_t              op,
    globus_xio_system_file_handle_t     handle,
    globus_off_t                        offset,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    HANDLE                              fd = handle->fd;
    globus_xio_iovec_t *                iov;
    int                                 iovc;
    GlobusXIOName(globus_xio_system_file_register_read);

    GlobusXIOSystemDebugEnterFD(fd);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Waiting for %ld bytes\n", _xio_name, (long) waitforbytes));
        
    win32_mutex_lock(&handle->lock);
    {
        if(handle->read_op.pending)
        {
            result = GlobusXIOErrorAlreadyRegistered();
            goto error_already_registered;
        }

        handle->read_op.pending = GLOBUS_TRUE;
    }
    win32_mutex_unlock(&handle->lock);

    GlobusIXIOSystemAllocIovec(u_iovc, iov);
    if(!iov)
    {
        result = GlobusXIOErrorMemory("iov");
        goto error_iovec;
    }

    GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);

    handle->read_op.start_iov = iov;
    handle->read_op.start_iovc = u_iovc;
    handle->read_op.iov = iov;
    handle->read_op.iovc = u_iovc;

    handle->read_op.op = op;
    handle->read_op.offset = offset;
    handle->read_op.waitforbytes = waitforbytes;
    handle->read_op.callback = callback;
    handle->read_op.user_arg = user_arg;
    handle->read_op.error = 0;
    handle->read_op.nbytes = 0;

    if(op != 0)
    {
        if(!handle->is_overlapped || waitforbytes == 0)
        {
            if(waitforbytes > 0)
            {
                globus_l_xio_win32_file_blocking_read(&handle->read_op);
            }
            /* else complete immediately, simulated select() */
            
            result = globus_callback_register_oneshot(
                0,
                0,
                globus_l_xio_win32_file_kickout,
                &handle->read_op);
            /* may have read data above, cant do anything else */
            if(result != GLOBUS_SUCCESS)
            {
                globus_panic(
                    GLOBUS_XIO_SYSTEM_MODULE,
                    result,
                    _XIOSL("[%s:%d] Couldn't register callback"),
                    _xio_name,
                    __LINE__);
            }
        }
        else
        {
            if(!QueueUserAPC(
                globus_l_xio_win32_file_start_read_apc,
                globus_l_xio_win32_file_thread_handle,
                &handle->read_op))
            {
                result = GlobusXIOErrorSystemError(
                    "QueueUserAPC", ERROR_NOT_ENOUGH_MEMORY);
                goto error_register;
            }
        }
    }

    /* handle could be destroyed by time we get here - no touch! */
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeIovec(iov, u_iovc);
error_iovec:
    win32_mutex_lock(&handle->lock);
    handle->read_op.pending = GLOBUS_FALSE;
error_already_registered:
    win32_mutex_unlock(&handle->lock);
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

/* if op == null, just set up the operation... internal use only */
globus_result_t
globus_xio_system_file_register_write(
    globus_xio_operation_t              op,
    globus_xio_system_file_handle_t     handle,
    globus_off_t                        offset,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    HANDLE                              fd = handle->fd;
    globus_xio_iovec_t *                iov;
    int                                 iovc;
    GlobusXIOName(globus_xio_system_file_register_write);

    GlobusXIOSystemDebugEnterFD(fd);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Waiting for %ld bytes\n", _xio_name, (long) waitforbytes));
        
    win32_mutex_lock(&handle->lock);
    {
        if(handle->write_op.pending)
        {
            result = GlobusXIOErrorAlreadyRegistered();
            goto error_already_registered;
        }

        handle->write_op.pending = GLOBUS_TRUE;
    }
    win32_mutex_unlock(&handle->lock);

    GlobusIXIOSystemAllocIovec(u_iovc, iov);
    if(!iov)
    {
        result = GlobusXIOErrorMemory("iov");
        goto error_iovec;
    }

    GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);

    handle->write_op.start_iov = iov;
    handle->write_op.start_iovc = u_iovc;
    handle->write_op.iov = iov;
    handle->write_op.iovc = u_iovc;

    handle->write_op.op = op;
    handle->write_op.offset = offset;
    handle->write_op.waitforbytes = waitforbytes;
    handle->write_op.callback = callback;
    handle->write_op.user_arg = user_arg;
    handle->write_op.error = 0;
    handle->write_op.nbytes = 0;

    if(op != 0)
    {
        if(!handle->is_overlapped || waitforbytes == 0)
        {
            if(waitforbytes > 0)
            {
                globus_l_xio_win32_file_blocking_write(&handle->write_op);
            }
            /* else complete immediately, simulated select() */
            
            result = globus_callback_register_oneshot(
                0,
                0,
                globus_l_xio_win32_file_kickout,
                &handle->write_op);
            /* may have read data above, cant do anything else */
            if(result != GLOBUS_SUCCESS)
            {
                globus_panic(
                    GLOBUS_XIO_SYSTEM_MODULE,
                    result,
                    _XIOSL("[%s:%d] Couldn't register callback"),
                    _xio_name,
                    __LINE__);
            }
        }
        else
        {
            if(!QueueUserAPC(
                globus_l_xio_win32_file_start_write_apc,
                globus_l_xio_win32_file_thread_handle,
                &handle->write_op))
            {
                result = GlobusXIOErrorSystemError(
                    "QueueUserAPC", ERROR_NOT_ENOUGH_MEMORY);
                goto error_register;
            }
        }
    }

    /* handle could be destroyed by time we get here - no touch! */
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeIovec(iov, u_iovc);
error_iovec:
    win32_mutex_lock(&handle->lock);
    handle->write_op.pending = GLOBUS_FALSE;
error_already_registered:
    win32_mutex_unlock(&handle->lock);
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

/* always blocks (even on waitforbytes == 0) */
globus_result_t
globus_xio_system_file_read(
    globus_xio_system_file_handle_t     handle,
    globus_off_t                        offset,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_file_read);

    GlobusXIOSystemDebugEnterFD(handle->fd);

    /* set up read_op */
    result = globus_xio_system_file_register_read(
        0, handle, offset, iov, iovc, waitforbytes, 0, 0);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_xio_system_file_register_read", result);
        goto error_setup;
    }

    if(handle->is_overlapped)
    {
        globus_l_xio_win32_file_start_read_apc((ULONG_PTR)&handle->read_op);
        
        while(handle->read_op.apc_pending)
        {
            SleepEx(INFINITE, GLOBUS_TRUE); /* drive APCs */
        }
    }
    else
    {
        globus_l_xio_win32_file_blocking_read(&handle->read_op);
    }
    
    if(handle->read_op.error)
    {
        result = globus_error_put(handle->read_op.error);
    }
    
    GlobusIXIOSystemFreeIovec(
        handle->read_op.start_iovc, handle->read_op.start_iov);

    *nbytes = handle->read_op.nbytes;

    win32_mutex_lock(&handle->lock);
    {
        handle->read_op.pending = GLOBUS_FALSE;
    }
    win32_mutex_unlock(&handle->lock);

    GlobusXIOSystemDebugExitFD(handle->fd);
    return result;

error_setup:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(handle->fd);
    return result;
}

/* always blocks (even on waitforbytes == 0) */
globus_result_t
globus_xio_system_file_write(
    globus_xio_system_file_handle_t     handle,
    globus_off_t                        offset,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_file_write);

    GlobusXIOSystemDebugEnterFD(handle->fd);

    /* set up write_op */
    result = globus_xio_system_file_register_write(
        0, handle, offset, iov, iovc, waitforbytes, 0, 0);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_xio_system_file_register_write", result);
        goto error_setup;
    }
    
    if(handle->is_overlapped)
    {
        globus_l_xio_win32_file_start_write_apc((ULONG_PTR)&handle->write_op);
        
        while(handle->write_op.apc_pending)
        {
            SleepEx(INFINITE, GLOBUS_TRUE); /* drive APCs */
        }
    }
    else
    {
        globus_l_xio_win32_file_blocking_write(&handle->write_op);
    }
    
    if(handle->write_op.error)
    {
        result = globus_error_put(handle->write_op.error);
    }
        
    GlobusIXIOSystemFreeIovec(
        handle->write_op.start_iovc, handle->write_op.start_iov);

    *nbytes = handle->write_op.nbytes;

    win32_mutex_lock(&handle->lock);
    {
        handle->write_op.pending = GLOBUS_FALSE;
    }
    win32_mutex_unlock(&handle->lock);

    GlobusXIOSystemDebugExitFD(handle->fd);
    return result;

error_setup:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(handle->fd);
    return result;
}

globus_off_t
globus_xio_system_file_get_position(
    globus_xio_system_file_t            fd)
{
    LARGE_INTEGER                       offset;
    GlobusXIOName(globus_xio_system_file_get_position);

    GlobusXIOSystemDebugEnterFD(fd);

    /* ignore errors, may be a pipe or other unseekable */
    if(!SetFilePointerEx(fd, 0, &offset, FILE_CURRENT))
    {
        offset = 0;
    }

    GlobusXIOSystemDebugExitFD(fd);

    return offset;
}

globus_off_t
globus_xio_system_file_get_size(
    globus_xio_system_file_t            fd)
{
    LARGE_INTEGER                       size;
    GlobusXIOName(globus_xio_system_file_get_size);

    GlobusXIOSystemDebugEnterFD(fd);

    if(!GetFileSizeEx(fd, &size))
    {
        size = -1;
    }

    GlobusXIOSystemDebugExitFD(fd);

    return size;
}

globus_xio_system_file_t
globus_xio_system_convert_stdio(
    const char *                        stdio)
{
    HANDLE                              fd = 0;

    if(strcmp(stdio, "stdin") == 0)
    {
        fd = GetStdHandle(STD_INPUT_HANDLE);
    }
    else if(strcmp(stdio, "stdout") == 0)
    {
        fd = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    else if(strcmp(stdio, "stderr") == 0)
    {
        fd = GetStdHandle(STD_ERROR_HANDLE);
    }

    if(fd == 0) /* GetStdHandle() can also return 0 */
    {
        fd = GLOBUS_XIO_SYSTEM_INVALID_FILE;
    }

    return fd;
}

globus_result_t
globus_xio_system_file_truncate(
    globus_xio_system_file_t            fd,
    globus_off_t                        size)
{
    globus_result_t                     result;
    LARGE_INTEGER                       offset;
    GlobusXIOName(globus_xio_system_file_truncate);

    GlobusXIOSystemDebugEnterFD(fd);

    /* save file position and move to new size */
    if(!SetFilePointerEx(fd, 0, &offset, FILE_CURRENT) ||
        !SetFilePointerEx(fd, size, 0, FILE_BEGIN))
    {
        result = GlobusXIOErrorSystemError("SetFilePointerEx", GetLastError());
        goto error_seek;
    }

    if(!SetEndOfFile(fd))
    {
        result = GlobusXIOErrorSystemError("SetEndOfFile", GetLastError());
        goto error_truncate;
    }

    /* restore file pointer */
    SetFilePointerEx(fd, offset, 0, FILE_BEGIN);

    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_truncate:
    SetFilePointerEx(fd, offset, 0, FILE_BEGIN);
error_seek:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

globus_result_t
globus_xio_system_file_open(
    globus_xio_system_file_t *          fd,
    const char *                        filename,
    int                                 flags,
    unsigned long                       mode)
{
    globus_result_t                     result;
    SECURITY_ATTRIBUTES                 sec_attr;
    DWORD                               access;
    DWORD                               create_mode;
    DWORD                               file_attr;
    GlobusXIOName(globus_xio_system_file_open);
    
    *fd = INVALID_HANDLE_VALUE;
    GlobusXIOSystemDebugEnterFD(*fd);

    access = flags & (O_RDONLY|O_WRONLY|O_RDWR);
    if(access == O_WRONLY)
    {
        access = flags & O_APPEND
            ? FILE_APPEND_DATA|SYNCHRONIZE
            : FILE_GENERIC_WRITE;
    }
    else if(access == O_RDWR)
    {
        access = flags & O_APPEND
            ? FILE_APPEND_DATA|FILE_GENERIC_READ 
            : FILE_GENERIC_READ|FILE_GENERIC_WRITE;
    }
    else
    {
        access = flags & O_APPEND
            ? FILE_APPEND_DATA|FILE_GENERIC_READ 
            : FILE_GENERIC_READ;
    }
    
    switch(flags & (O_CREAT|O_EXCL|O_TRUNC))
    {
      case O_CREAT:
        create_mode = OPEN_ALWAYS;
        break;
        
      case O_CREAT|O_EXCL:
      case O_CREAT|O_EXCL|O_TRUNC:
        create_mode = CREATE_NEW;
        break;
      
      case O_TRUNC:
      case O_TRUNC|O_EXCL: /* ignore O_EXCL on missing O_CREAT */
        create_mode = TRUNCATE_EXISTING;
        break;
      
      case O_CREAT|O_TRUNC:
        create_mode = CREATE_ALWAYS;
        break;
      
      default:
        create_mode = OPEN_EXISTING;
        break;
    }
    
    if(flags & O_CREAT && (mode & GLOBUS_XIO_SYSTEM_FILE_WRITABLE) == 0)
    {
        file_attr = FILE_ATTRIBUTE_READONLY;
    }
    else
    {
        file_attr = FILE_ATTRIBUTE_NORMAL;
    }
    
    file_attr |= FILE_FLAG_OVERLAPPED;
    
    /* handles created by me are not inherited on exec */
    sec_attr.nLength = sizeof(sec_attr);
    sec_attr.lpSecurityDescriptor = 0;
    sec_attr.bInheritHandle = FALSE;
    
    *fd = CreateFile(
        filename,
        access,
        FILE_SHARE_READ|FILE_SHARE_WRITE,
        &sec_attr,
        create_mode,
        file_attr,
        0);
    if(*fd == INVALID_HANDLE_VALUE)
    {
        result = GlobusXIOErrorSystemError("CreateFile", GetLastError());
        goto error_open;
    }
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_I_XIO_SYSTEM_DEBUG_INFO,
        ("[%s] Opened file, %s fd=%d\n", _xio_name, filename, *fd));

    GlobusXIOSystemDebugExitFD(*fd);
    return GLOBUS_SUCCESS;

error_open:
    GlobusXIOSystemDebugExitWithErrorFD(*fd);
    return result;
}

globus_result_t
globus_xio_system_file_close(
    globus_xio_system_file_t            fd)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_file_close);

    GlobusXIOSystemDebugEnterFD(fd);

    if(!CloseHandle(fd))
    {
        result = GlobusXIOErrorSystemError("CloseHandle", GetLastError());
        goto error_close;
    }

    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_close:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}
