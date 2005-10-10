/*
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */
#include "globus_i_xio_win32.h"

typedef struct globus_l_xio_win32_socket_s
{
    win32_mutex_t                       lock;
    SOCKET                              socket;
    WSAEVENT                            event;
    long                                ready_events;
    globus_i_xio_win32_event_entry_t    event_entry;
    globus_i_xio_system_op_info_t *     read_info;
    globus_i_xio_system_op_info_t *     write_info;
} globus_l_xio_win32_socket_t;

static
void
globus_l_xio_win32_socket_kickout(
    void *                              user_arg)
{
    globus_i_xio_system_op_info_t *     op_info;
    GlobusXIOName(globus_l_xio_win32_socket_kickout);

    op_info = (globus_i_xio_system_op_info_t *) user_arg;

    GlobusXIOSystemDebugEnterFD(op_info->fd);

    if(op_info->op)
    {
        globus_xio_operation_disable_cancel(op_info->op);
    }
    
    switch(op_info->type)
    {
      case GLOBUS_I_XIO_SYSTEM_OP_CONNECT:
      case GLOBUS_I_XIO_SYSTEM_OP_ACCEPT:
        op_info->sop.non_data.callback(
            op_info->error ? globus_error_put(op_info->error) : GLOBUS_SUCCESS,
            op_info->user_arg);
        break;

      default:
        op_info->sop.data.callback(
            op_info->error ? globus_error_put(op_info->error) : GLOBUS_SUCCESS,
            op_info->nbytes,
            op_info->user_arg);
            
        GlobusIXIOSystemFreeIovec(
            op_info->sop.data.start_iovc,
            op_info->sop.data.start_iov);
        break;
    }
    
    GlobusXIOSystemDebugExitFD(op_info->fd);
    GlobusIXIOSystemFreeOperation(op_info);
}

/* must be safe to call from win32 thread */
static
void
globus_l_xio_win32_socket_handle_read(
    globus_l_xio_win32_socket_t *       handle,
    globus_bool_t                       win32_thread)
{
    globus_i_xio_system_op_info_t *     read_info;
    globus_size_t                       nbytes;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_win32_socket_handle_read);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);

    read_info = handle->read_info;
    result = GLOBUS_SUCCESS;

    if(read_info->op)
    {
        globus_xio_operation_refresh_timeout(read_info->op);
    }
    
    switch(read_info->type)
    {
      case GLOBUS_I_XIO_SYSTEM_OP_ACCEPT:
        {
            SOCKET                      new_fd;

            new_fd = accept(handle->socket, NULL, NULL);
            
            if(new_fd == INVALID_SOCKET)
            {
                int                     error = WSAGetLastError();
                
                if(error != WSAECONNRESET && error != WSAEWOULDBLOCK)
                {
                    result = GlobusXIOErrorSystemError("accept", error);
                }
            }
            else
            {
                unsigned long           flag = 0;
                
                /* clear inherited attrs */
                WSAEventSelect(new_fd, 0, 0);
                ioctlsocket(new_fd, FIONBIO, &flag);
    
                *read_info->sop.non_data.out_fd = new_fd;
                read_info->nbytes++;
                GlobusXIOSystemDebugPrintf(
                    GLOBUS_I_XIO_SYSTEM_DEBUG_INFO,
                    ("[%s] Accepted new connection, fd=%lu\n",
                         _xio_name, (unsigned long)new_fd));
            }
        }
        break;

      case GLOBUS_I_XIO_SYSTEM_OP_READ:
        result = globus_i_xio_system_socket_try_read(
            handle->socket,
            read_info->sop.data.iov,
            read_info->sop.data.iovc,
            read_info->sop.data.flags,
            read_info->sop.data.addr,
            &nbytes);
        if(result == GLOBUS_SUCCESS)
        {
            if(nbytes == 0)
            {
                /* this is only possible when there is no user buffer space to
                 * read data into.  (user likely using select() behavior)
                 * may not have re-enabled READ event, save it now
                 */
                handle->ready_events |= FD_READ;
            }
            else
            {
                read_info->nbytes += nbytes;
                GlobusIXIOUtilAdjustIovec(
                    read_info->sop.data.iov, read_info->sop.data.iovc, nbytes);
            }
        }
        break;

      default:
        globus_assert(0 && "Unexpected type for read operation");
        return;
        break;
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        read_info->error = globus_error_get(result);
    }
    
    /* always true for accept operations */
    if(read_info->nbytes >= read_info->waitforbytes ||
        result != GLOBUS_SUCCESS)
    {
        read_info->state = GLOBUS_I_XIO_SYSTEM_OP_COMPLETE;
        handle->read_info = NULL;
        
        if(!read_info->op)
        {
            /* internal usage */
            globus_l_xio_win32_socket_kickout(read_info);
        }
        else if(win32_thread)
        {
            result = globus_i_xio_win32_complete(
                globus_l_xio_win32_socket_kickout, read_info);
        }
        else
        {
            result = globus_callback_register_oneshot(
                NULL, NULL, globus_l_xio_win32_socket_kickout, read_info);
        }
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

    GlobusXIOSystemDebugExitFD(handle->socket);
}

/* must be safe to call from win32 thread */
static
void
globus_l_xio_win32_socket_handle_write(
    globus_l_xio_win32_socket_t *       handle,
    globus_bool_t                       win32_thread)
{
    globus_l_operation_info_t *         write_info;
    globus_size_t                       nbytes;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_win32_socket_handle_write);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);

    result = GLOBUS_SUCCESS;
    write_info = handle->write_info;

    if(write_info->op)
    {
        globus_xio_operation_refresh_timeout(write_info->op);
    }
    
    switch(write_info->type)
    {
      case GLOBUS_I_XIO_SYSTEM_OP_CONNECT:
        {
            int                         err;
            globus_socklen_t            errlen;

            errlen = sizeof(err);
            if(getsockopt(
                handle->socket, SOL_SOCKET, SO_ERROR, &err, &errlen)
                    == SOCKET_ERROR)
            {
                err = WSAGetLastError();
            }

            if(err)
            {
                result = GlobusXIOErrorSystemError("connect", err);
            }
        }
        break;

      case GLOBUS_I_XIO_SYSTEM_OP_WRITE:
        /* we loop repeatedly here to use up all available space until
         * the write would return EWOULDBLOCK.  at that time, we'll get
         * another event to land us back here
         */
        do
        {
            result = globus_i_xio_system_socket_try_write(
                handle->socket,
                write_info->sop.data.iov,
                write_info->sop.data.iovc,
                write_info->sop.data.flags,
                write_info->sop.data.addr,
                &nbytes);
            if(result == GLOBUS_SUCCESS)
            {
                write_info->nbytes += nbytes;
                GlobusIXIOUtilAdjustIovec(
                    write_info->sop.data.iov,
                    write_info->sop.data.iovc,
                    nbytes);
            }
        } while(nbytes > 0 && write_info->nbytes < write_info->waitforbytes);
        break;

      default:
        globus_assert(0 && "Unexpected type for write operation");
        return;
        break;
    }
  
    if(result != GLOBUS_SUCCESS)
    {
        write_info->error = globus_error_get(result);
    }
    
    /* always true for connect operations */
    if(write_info->nbytes >= write_info->waitforbytes ||
        result != GLOBUS_SUCCESS)
    {
        /* didn't use all available space (or this is a connect)
         * record for next write
         */
        handle->ready_events |= FD_WRITE;
        
        write_info->state = GLOBUS_I_XIO_SYSTEM_OP_COMPLETE;
        handle->write_info = NULL;
        
        if(!write_info->op)
        {
            /* internal usage */
            globus_l_xio_win32_socket_kickout(write_info);
        }
        else if(win32_thread)
        {
            result = globus_i_xio_win32_complete(
                globus_l_xio_win32_socket_kickout, write_info);
        }
        else
        {
            result = globus_callback_register_oneshot(
                NULL, NULL, globus_l_xio_win32_socket_kickout, write_info);
        }
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

    GlobusXIOSystemDebugExitFD(handle->socket);
}

static
void
globus_l_xio_win32_socket_cancel_cb(
    globus_xio_operation_t              op,
    void *                              user_arg,
    globus_xio_error_type_t             reason)
{
    globus_l_operation_info_t *         op_info;
    GlobusXIOName(globus_l_xio_win32_socket_cancel_cb);

    GlobusXIOSystemDebugEnter();

    op_info = (globus_i_xio_system_op_info_t *) user_arg;
    
    /* this access of the handle is not safe if users destroy it
     * with outstanding callbacks.  I don't think that is allowed, so we
     * should be ok.
     */
    win32_mutex_lock(&op_info->handle->lock);
    {
        if(op_info->state != GLOBUS_I_XIO_SYSTEM_OP_COMPLETE && 
            op_info->state != GLOBUS_I_XIO_SYSTEM_OP_CANCELED)
        {
            op_info->error = reason == GLOBUS_XIO_ERROR_TIMEOUT
                ? GlobusXIOErrorObjTimeout()
                : GlobusXIOErrorObjCanceled();
            
            if(op_info->state == GLOBUS_I_XIO_SYSTEM_OP_NEW)
            {
                op_info->state = GLOBUS_I_XIO_SYSTEM_OP_CANCELED;
                    
                GlobusXIOSystemDebugPrintf(
                    GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                    ("[%s] fd=%lu, Canceling NEW\n",
                        _xio_name, (unsigned long)op_info->fd));
            }
            else
            {
                globus_result_t         result;

                op_info->state = GLOBUS_I_XIO_SYSTEM_OP_COMPLETE;
                
                GlobusXIOSystemDebugPrintf(
                    GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                    ("[%s] fd=%lu, Canceling Pending\n",
                        _xio_name, (unsigned long)op_info->fd));
                
                if(op_info->handle->read_info == op_info)
                {
                    op_info->handle->read_info = NULL;
                }
                else
                {
                    globus_assert(op_info->handle->write_info == op_info);
                    op_info->handle->write_info = NULL;
                }
                
                /* unregister and kickout now */
                result = globus_callback_register_oneshot(
                    NULL,
                    NULL,
                    globus_l_xio_win32_socket_kickout,
                    op_info);
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
        }
    }
    win32_mutex_unlock(&op_info->handle->lock);

    GlobusXIOSystemDebugExit();
}

/* always called from win32 thread */
static
globus_bool_t
globus_l_xio_win32_socket_event_cb(
    void *                              user_arg)
{
    globus_l_xio_win32_socket_t *       handle;
    WSANETWORKEVENTS                    events;
    GlobusXIOName(globus_l_xio_win32_socket_event_cb);
    
    handle = (globus_l_xio_win32_socket_t *) user_arg;
    
    GlobusXIOSystemDebugEnterFD(handle->socket);
    
    if(WSAEnumNetworkEvents(
        handle->socket, handle->event, &events) == SOCKET_ERROR)
    {
        goto error_enum;
    }

    win32_mutex_lock(&handle->lock);
    {
        /* save the close event if it exists */
        handle->ready_events |= events & FD_CLOSE;
        
        if(events & (FD_ACCEPT|FD_READ|FD_CLOSE))
        {
            if(handle->read_info)
            {
                globus_l_xio_win32_socket_handle_read(handle, GLOBUS_TRUE);
            }
            else
            {
                handle->ready_events |= events & (FD_ACCEPT|FD_READ);
            }
        }
        
        if(events & (FD_CONNECT|FD_WRITE|FD_CLOSE))
        {
            if(handle->write_info)
            {
                globus_l_xio_win32_socket_handle_write(handle, GLOBUS_TRUE);
            }
            else
            {
                handle->ready_events |= events & (FD_CONNECT|FD_WRITE);
            }
        }
    }
    win32_mutex_unlock(&handle->lock);
    
    GlobusXIOSystemDebugExitFD(handle->socket);
    return GLOBUS_TRUE;

error_enum:
    GlobusXIOSystemDebugExitWithErrorFD(handle->socket);
    return GLOBUS_TRUE;
}

static
globus_result_t
globus_l_xio_win32_socket_register_read(
    globus_l_xio_win32_socket_t *       handle,
    globus_i_xio_system_op_info_t *     read_info)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_win32_socket_register_read);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);
    
    /* I have to do this outside the lock because of lock inversion issues */
    if(read_info->op && globus_xio_operation_enable_cancel(
        read_info->op, globus_l_xio_win32_socket_cancel_cb, read_info))
    {
        result = GlobusXIOErrorCanceled();
        goto error_cancel_enable;
    }

    win32_mutex_lock(&handle->lock);
    {
        if(read_info->state == GLOBUS_I_XIO_SYSTEM_OP_CANCELED)
        {
            result = globus_error_put(read_info->error);
            goto error_canceled;
        }

        if(handle->read_info)
        {
            result = GlobusXIOErrorAlreadyRegistered();
            goto error_already_registered;
        }
        
        handle->read_info = read_info;
        read_info->state = GLOBUS_I_XIO_SYSTEM_OP_PENDING;
        
        if(handle->ready_events & (FD_ACCEPT|FD_READ|FD_CLOSE))
        {
            handle->ready_events &= ~(FD_ACCEPT|FD_READ);
            globus_l_xio_win32_socket_handle_read(handle, GLOBUS_FALSE);
        }
    }
    win32_mutex_unlock(&handle->lock);
    
    GlobusXIOSystemDebugExitFD(handle->socket);
    return GLOBUS_SUCCESS;

error_already_registered:
error_canceled:
    read_info->state = GLOBUS_I_XIO_SYSTEM_OP_COMPLETE;
    win32_mutex_unlock(&handle->lock);
    if(read_info->op)
    {
        globus_xio_operation_disable_cancel(read_info->op);
    }
    
    GlobusXIOSystemDebugExitWithErrorFD(handle->socket);
    return result;
}

static
globus_result_t
globus_l_xio_win32_socket_register_write(
    globus_l_xio_win32_socket_t *       handle,
    globus_i_xio_system_op_info_t *     write_info)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_win32_socket_register_write);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);
    
    /* I have to do this outside the lock because of lock inversion issues */
    if(write_info->op && globus_xio_operation_enable_cancel(
        write_info->op, globus_l_xio_win32_socket_cancel_cb, write_info))
    {
        result = GlobusXIOErrorCanceled();
        goto error_cancel_enable;
    }

    win32_mutex_lock(&handle->lock);
    {
        if(write_info->state == GLOBUS_I_XIO_SYSTEM_OP_CANCELED)
        {
            result = globus_error_put(write_info->error);
            goto error_canceled;
        }

        if(handle->write_info)
        {
            result = GlobusXIOErrorAlreadyRegistered();
            goto error_already_registered;
        }
        
        handle->write_info = write_info;
        read_info->state = GLOBUS_I_XIO_SYSTEM_OP_PENDING;
        
        if(handle->ready_events & (FD_CONNECT|FD_WRITE|FD_CLOSE))
        {
            handle->ready_events &= ~(FD_CONNECT|FD_WRITE);
            globus_l_xio_win32_socket_handle_write(handle, GLOBUS_FALSE);
        }
    }
    win32_mutex_unlock(&handle->lock);
    
    GlobusXIOSystemDebugExitFD(handle->socket);
    return GLOBUS_SUCCESS;

error_already_registered:
error_canceled:
    write_info->state = GLOBUS_I_XIO_SYSTEM_OP_COMPLETE;
    win32_mutex_unlock(&handle->lock);
    if(write_info->op)
    {
        globus_xio_operation_disable_cancel(write_info->op);
    }
    
    GlobusXIOSystemDebugExitWithErrorFD(handle->socket);
    return result;
}

globus_result_t
globus_xio_system_socket_init(
    globus_xio_system_socket_handle_t * uhandle,
    globus_xio_system_socket_t          socket,
    globus_xio_system_type_t            type)
{
    globus_result_t                     result;
    globus_l_xio_win32_socket_t *       handle;
    unsigned long                       flag;
    GlobusXIOName(globus_xio_system_socket_init);
    
    GlobusXIOSystemDebugEnterFD(socket);
    
    handle = (globus_l_xio_win32_socket_t *)
        globus_calloc(1, sizeof(globus_l_xio_win32_socket_t));
    if(!handle)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error_alloc;
    }
    
    handle->socket = socket;
    win32_mutex_init(&handle->lock, NULL);
    
    handle->event = WSACreateEvent();
    if(handle->event == 0)
    {
        result = GlobusXIOErrorSystemError(
            "WSACreateEvent", GetLastError());
        goto error_create;
    }
    
    /* XXX not be necessary if I never clear events with WSAEventSelect */
    flag = 1;
    if(ioctlsocket(socket, FIONBIO, &flag) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError(
            "ioctlsocket", WSAGetLastError());
        goto error_ioctl;
    }
    
    if(WSAEventSelect(
        socket, handle->event,
        type == GLOBUS_XIO_SYSTEM_TCP_LISTENER 
            ? FD_ACCEPT 
            : FD_CONNECT|FD_WRITE|FD_READ|FD_CLOSE) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError(
            "WSAEventSelect", WSAGetLastError());
        goto error_select;
    }
    
    result = globus_i_xio_win32_event_register(
        &handle->event_entry,
        handle->event,
        globus_l_xio_win32_socket_event_cb,
        handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_i_xio_win32_event_register", result);
        goto error_register;
    }
    
    *uhandle = handle;
    
    GlobusXIOSystemDebugExitFD(socket);
    return GLOBUS_SUCCESS;

error_register:
    WSAEventSelect(socket, 0, 0);
error_select:
    flag = 0;
    ioctlsocket(socket, FIONBIO, &flag);
error_ioctl:
    CloseHandle(handle->event);
error_create:
    win32_mutex_destroy(&handle->lock);
    globus_free(handle);
error_alloc:
    GlobusXIOSystemDebugExitWithErrorFD(socket);
    return result;
}

void
globus_xio_system_socket_destroy(
    globus_xio_system_socket_handle_t   handle)
{
    unsigned long                       flag = 0;
    GlobusXIOName(globus_xio_system_socket_destroy);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);
    
    globus_assert(!handle->read_info && !handle->write_info);
    
    /* no need to ensure entry is still registered, as I always return true
     * in the callback and this is only place i unregister
     */
    globus_i_xio_win32_event_lock(handle->event_entry);
    globus_i_xio_win32_event_unregister(handle->event_entry);
    globus_i_xio_win32_event_unlock(handle->event_entry);
    
    WSAEventSelect(handle->socket, 0, 0);
    ioctlsocket(handle->socket, FIONBIO, &flag)
    CloseHandle(handle->event);
    win32_mutex_destroy(&handle->lock);
    
    GlobusXIOSystemDebugExitFD(handle->socket);
    globus_free(handle);
}
    
globus_result_t
globus_xio_system_socket_register_connect(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   handle,
    globus_sockaddr_t *                 addr,
    globus_xio_system_callback_t        callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    int                                 error;
    globus_i_xio_system_op_info_t *     op_info;
    GlobusXIOName(globus_xio_system_socket_register_connect);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);
    
    if(connect(
        handle->socket, (const struct sockaddr *) addr,
        GlobusLibcSockaddrLen(addr)) == SOCKET_ERROR &&
        (error = WSAGetLastError()) != WSAEWOULDBLOCK)
    {
        result = GlobusXIOErrorSystemError("connect", error);
        goto error_connect;
    }

    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }

    op_info->type = GLOBUS_I_XIO_SYSTEM_OP_CONNECT;
    op_info->state = GLOBUS_I_XIO_SYSTEM_OP_NEW;
    op_info->op = op;
    op_info->fd = handle->socket;
    op_info->handle = handle;
    op_info->user_arg = user_arg;
    op_info->sop.non_data.callback = callback;

    result = globus_l_xio_win32_socket_register_write(handle, op_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_win32_socket_register_write", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExitFD(handle->socket);
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeOperation(op_info);
error_op_info:
error_connect:
    GlobusXIOSystemDebugExitWithErrorFD(handle->socket);
    return result;
}

globus_result_t
globus_xio_system_socket_register_accept(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   listener_handle,
    globus_xio_system_socket_t *        out_handle,
    globus_xio_system_callback_t        callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_xio_system_op_info_t *     op_info;
    GlobusXIOName(globus_xio_system_socket_register_accept);
    
    GlobusXIOSystemDebugEnterFD(listener_handle->socket);
    
    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }

    op_info->type = GLOBUS_I_XIO_SYSTEM_OP_ACCEPT;
    op_info->state = GLOBUS_I_XIO_SYSTEM_OP_NEW;
    op_info->op = op;
    op_info->fd = listener_handle->socket;
    op_info->handle = listener_handle;
    op_info->user_arg = user_arg;
    op_info->sop.non_data.callback = callback;
    op_info->sop.non_data.out_fd.socket = out_handle;
    op_info->waitforbytes = 1;

    result = globus_l_xio_win32_socket_register_read(listener_handle, op_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_win32_socket_register_read", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExitFD(listener_handle->socket);
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeOperation(op_info);
error_op_info:
    GlobusXIOSystemDebugExitWithErrorFD(listener_handle->socket);
    return result;
}

/* calling this with null op could cause deadlock... 
 * reserved for internal use
 */
globus_result_t
globus_l_xio_system_socket_register_read(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_sockaddr_t *                 out_from,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_xio_system_op_info_t *     op_info;
    struct iovec *                      iov;
    int                                 iovc;
    GlobusXIOName(globus_l_xio_system_socket_register_read);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Waiting for %ld bytes\n", _xio_name, (long) waitforbytes));
    
    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }
    
    GlobusIXIOSystemAllocIovec(u_iovc, iov);
    if(!iov)
    {
        result = GlobusXIOErrorMemory("iov");
        goto error_iovec;
    }
    
    GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);
    iovc = u_iovc;
    
    op_info->type = GLOBUS_I_XIO_SYSTEM_OP_READ;
    op_info->sop.data.start_iov = iov;
    op_info->sop.data.start_iovc = iovc;
    
    GlobusIXIOUtilAdjustIovec(iov, iovc, nbytes);
    op_info->sop.data.iov = iov;
    op_info->sop.data.iovc = iovc;
    op_info->sop.data.addr = out_from;
    op_info->sop.data.flags = flags;
    
    op_info->state = GLOBUS_I_XIO_SYSTEM_OP_NEW;
    op_info->op = op;
    op_info->fd = handle->socket;
    op_info->handle = handle;
    op_info->user_arg = user_arg;
    op_info->sop.data.callback = callback;
    op_info->waitforbytes = waitforbytes;
    op_info->nbytes = nbytes;
    
    result = globus_l_xio_win32_socket_register_read(handle, op_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_win32_socket_register_read", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExitFD(handle->socket);
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeIovec(u_iovc, op_info->sop.data.start_iov);
error_iovec:
    GlobusIXIOSystemFreeOperation(op_info);
error_op_info:
    GlobusXIOSystemDebugExitWithErrorFD(handle->socket);
    return result;
}

globus_result_t
globus_xio_system_socket_register_read(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 out_from,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    return globus_l_xio_system_socket_register_read(
        op,
        handle,
        u_iov,
        u_iovc,
        waitforbytes,
        0,
        flags,
        out_from,
        callback,
        user_arg);
}

/* calling this with null op could cause deadlock... 
 * reserved for internal use
 */
globus_result_t
globus_l_xio_system_socket_register_write(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    globus_size_t                       nbytes,
    int                                 flags,
    globus_sockaddr_t *                 to,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_xio_system_op_info_t *     op_info;
    struct iovec *                      iov;
    int                                 iovc;
    GlobusXIOName(globus_l_xio_system_socket_register_write);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Waiting for %ld bytes\n", _xio_name, (long) waitforbytes));
    
    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }
    
    GlobusIXIOSystemAllocIovec(u_iovc, iov);
    if(!iov)
    {
        result = GlobusXIOErrorMemory("iov");
        goto error_iovec;
    }

    GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);
    iovc = u_iovc;

    op_info->type = GLOBUS_I_XIO_SYSTEM_OP_WRITE;
    op_info->sop.data.start_iov = iov;
    op_info->sop.data.start_iovc = iovc;
    
    GlobusIXIOUtilAdjustIovec(iov, iovc, nbytes);
    op_info->sop.data.iov = iov;
    op_info->sop.data.iovc = iovc;
    op_info->sop.data.addr = to;
    op_info->sop.data.flags = flags;
    
    op_info->state = GLOBUS_I_XIO_SYSTEM_OP_NEW;
    op_info->op = op;
    op_info->fd = handle->socket;
    op_info->handle = handle;
    op_info->user_arg = user_arg;
    op_info->sop.data.callback = callback;
    op_info->waitforbytes = waitforbytes;
    op_info->nbytes = nbytes;
    
    result = globus_l_xio_win32_socket_register_write(handle, op_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_win32_socket_register_write", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExitFD(handle->socket);
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeIovec(u_iovc, op_info->sop.data.start_iov);
error_iovec:
    GlobusIXIOSystemFreeOperation(op_info);
error_op_info:
    GlobusXIOSystemDebugExitWithErrorFD(handle->socket);
    return result;
}

globus_result_t
globus_xio_system_socket_register_write(
    globus_xio_operation_t              op,
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 to,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    return globus_l_xio_system_socket_register_write(
        op,
        handle,
        u_iov,
        u_iovc,
        waitforbytes,
        0,
        flags,
        to,
        callback,
        user_arg);
}

typedef struct
{
    HANDLE                              event;
    globus_size_t                       nbytes;
    globus_object_t *                   error;
} globus_l_xio_win32_blocking_info_t;

static
globus_result_t
globus_l_xio_win32_blocking_init(
    globus_l_xio_win32_blocking_info_t ** u_blocking_info)
{
    globus_l_xio_win32_blocking_info_t * blocking_info;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_win32_blocking_init);
    
    GlobusXIOSystemDebugEnter();
    
    blocking_info = (globus_l_xio_win32_blocking_info_t *)
        globus_calloc(1, sizeof(globus_l_xio_win32_blocking_info_t));
    if(!blocking_info)
    {
        result = GlobusXIOErrorMemory("blocking_info");
        goto error_info;
    }
    
    blocking_info->event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if(blocking_info->event == 0)
    {
        result = GlobusXIOErrorSystemError(
            "CreateEvent", GetLastError());
        goto error_create;
    }
    
    *u_blocking_info = blocking_info;
    
    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_create:
    globus_free(*blocking_info);
error_info:
    *u_blocking_info = NULL;
    GlobusXIOSystemDebugExitWithError();
    return result;
}

static
void
globus_l_xio_win32_blocking_destroy(
    globus_l_xio_win32_blocking_info_t * blocking_info)
{
    GlobusXIOName(globus_l_xio_win32_blocking_destroy);
    
    GlobusXIOSystemDebugEnter();
    
    CloseHandle(blocking_info->event);
    globus_free(blocking_info);
    
    GlobusXIOSystemDebugExit();
}

static
void
globus_l_xio_win32_blocking_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_xio_win32_blocking_info_t * blocking_info;
    GlobusXIOName(globus_l_xio_win32_blocking_cb);
    
    GlobusXIOSystemDebugEnter();
    
    blocking_info = (globus_l_xio_win32_blocking_info_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        blocking_info->error = globus_error_get(result);
    }
    blocking_info->nbytes = nbytes;
    SetEvent(blocking_info->event);
    
    GlobusXIOSystemDebugExit();
}

globus_result_t
globus_xio_system_socket_read(
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 from,
    globus_size_t *                     u_nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_read);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Waiting for %ld bytes\n", _xio_name, (long) waitforbytes));
    
    win32_mutex_lock(&handle->lock);
    {
        handle->ready_events &= ~FD_READ;
        
        result = globus_i_xio_system_socket_try_read(
            fd,
            u_iov,
            u_iovc,
            flags,
            from,
            u_nbytes);
    }
    win32_mutex_unlock(&handle->lock);
    
    if(result == GLOBUS_SUCCESS && *u_nbytes < waitforbytes)
    {
        globus_l_xio_win32_blocking_info_t * blocking_info;
        
        result = globus_l_xio_win32_blocking_init(&blocking_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_win32_blocking_init", result);
            goto error_init;
        }
        
        result = globus_l_xio_system_socket_register_read(
            NULL,
            handle,
            u_iov,
            u_iovc,
            waitforbytes,
            *u_nbytes
            flags,
            from,
            globus_l_xio_win32_blocking_cb,
            blocking_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_system_socket_register_read", result);
            goto error_register;
        }
        
        while(WaitForSingleObject(
            blocking_info->event, INFINITE) != WAIT_OBJECT_0) {}
        
        if(blocking_info->error)
        {
            result = globus_error_put(blocking_info->error);
        }
        *u_nbytes = blocking_info->nbytes;
        
        globus_l_xio_win32_blocking_destroy(blocking_info);
    }

    GlobusXIOSystemDebugExitFD(handle->socket);
    return result;

error_register:
    globus_l_xio_win32_blocking_destroy(blocking_info);
error_init:
    GlobusXIOSystemDebugExitWithErrorFD(handle->socket);
    return result;
}

globus_result_t
globus_xio_system_socket_write(
    globus_xio_system_socket_handle_t   handle,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 to,
    globus_size_t *                     u_nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_write);
    
    GlobusXIOSystemDebugEnterFD(handle->socket);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_I_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Waiting for %ld bytes\n", _xio_name, (long) waitforbytes));
    
    win32_mutex_lock(&handle->lock);
    {
        result = globus_i_xio_system_socket_try_write(
            handle->socket,
            u_iov,
            u_iovc,
            flags,
            to,
            u_nbytes);
        
        if(result == GLOBUS_SUCCESS && *u_nbytes == 0 && 
            (u_iovc > 1 || u_iov->iov_len > 0))
        {
            /* couldnt write any data, clear write event */
            handle->ready_events &= ~FD_WRITE;
        }
    }
    win32_mutex_unlock(&handle->lock);
    
    if(result == GLOBUS_SUCCESS && *u_nbytes < waitforbytes)
    {
        globus_l_xio_win32_blocking_info_t * blocking_info;
                
        result = globus_l_xio_win32_blocking_init(&blocking_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_win32_blocking_init", result);
            goto error_init;
        }
        
        result = globus_l_xio_system_socket_register_write(
            NULL,
            handle,
            iov,
            iovc,
            waitforbytes,
            *u_nbytes,
            flags,
            to,
            globus_l_xio_win32_blocking_cb,
            blocking_info);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_system_socket_register_write", result);
            goto error_register;
        }
        
        while(WaitForSingleObject(
            blocking_info->event, INFINITE) != WAIT_OBJECT_0) {}
        
        if(blocking_info->error)
        {
            result = globus_error_put(blocking_info->error);
        }
        *u_nbytes = blocking_info->nbytes;
        
        globus_l_xio_win32_blocking_destroy(blocking_info);
    }

    GlobusXIOSystemDebugExitFD(handle->socket);
    return result;

error_register:
    globus_l_xio_win32_blocking_destroy(blocking_info);
error_init:
    GlobusXIOSystemDebugExitWithErrorFD(handle->socket);
    return result;
}

globus_result_t
globus_xio_system_socket_create(
    globus_xio_system_socket_t *        socket,
    int                                 domain,
    int                                 type,
    int                                 protocol)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_create);
    
    *socket = INVALID_SOCKET;
    GlobusXIOSystemDebugEnterFD(*socket);
    
    *socket = socket(domain, type, protocol);
    if(*socket == INVALID_SOCKET)
    {
        result = GlobusXIOErrorSystemError("socket", WSAGetLastError());
        goto error_socket;
    }

    /* all handles created by me are closed on exec */
    SetHandleInformation(*socket, HANDLE_FLAG_INHERIT, 0);

    GlobusXIOSystemDebugExitFD(*socket);
    return GLOBUS_SUCCESS;

error_socket:
    GlobusXIOSystemDebugExitWithErrorFD(*socket);
    return result;
}

globus_result_t
globus_xio_system_socket_setsockopt(
    globus_xio_system_socket_t          socket,
    int                                 level,
    int                                 optname,
    const void *                        optval,
    socklen_t                           optlen)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_setsockopt);
    
    GlobusXIOSystemDebugEnterFD(socket);
    
    if(setsockopt(socket, level, optname, optval, optlen) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError("setsockopt", WSAGetLastError());
        goto error_setsockopt;
    }
    
    GlobusXIOSystemDebugExitFD(socket);
    return GLOBUS_SUCCESS;

error_setsockopt:
    GlobusXIOSystemDebugExitWithErrorFD(socket);
    return result;
}

globus_result_t
globus_xio_system_socket_getsockopt(
    globus_xio_system_socket_t          socket,
    int                                 level,
    int                                 optname,
    void *                              optval,
    socklen_t *                         optlen)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_getsockopt);
    
    GlobusXIOSystemDebugEnterFD(socket);
    
    if(getsockopt(socket, level, optname, optval, optlen) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError("getsockopt", WSAGetLastError());
        goto error_getsockopt;
    }
    
    GlobusXIOSystemDebugExitFD(socket);
    return GLOBUS_SUCCESS;

error_getsockopt:
    GlobusXIOSystemDebugExitWithErrorFD(socket);
    return result;
}

globus_result_t
globus_xio_system_socket_getsockname(
    globus_xio_system_socket_t          socket,
    struct sockaddr *                   name,
    socklen_t *                         namelen)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_getsockname);
    
    GlobusXIOSystemDebugEnterFD(socket);
    
    if(getsockname(socket, name, namelen) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError("getsockname", WSAGetLastError());
        goto error_getsockname;
    }
    
    GlobusXIOSystemDebugExitFD(socket);
    return GLOBUS_SUCCESS;

error_getsockname:
    GlobusXIOSystemDebugExitWithErrorFD(socket);
    return result;
}

globus_result_t
globus_xio_system_socket_getpeername(
    globus_xio_system_socket_t          socket,
    struct sockaddr *                   name,
    socklen_t *                         namelen)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_getpeername);
    
    GlobusXIOSystemDebugEnterFD(socket);
    
    if(getpeername(socket, name, namelen) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError("getpeername", WSAGetLastError());
        goto error_getpeername;
    }
    
    GlobusXIOSystemDebugExitFD(socket);
    return GLOBUS_SUCCESS;

error_getpeername:
    GlobusXIOSystemDebugExitWithErrorFD(socket);
    return result;
}

globus_result_t
globus_xio_system_socket_bind(
    globus_xio_system_socket_t          socket,
    struct sockaddr *                   addr,
    socklen_t                           addrlen)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_bind);
    
    GlobusXIOSystemDebugEnterFD(socket);
    
    if(bind(socket, addr, addrlen) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError("bind", WSAGetLastError());
        goto error_bind;
    }
    
    GlobusXIOSystemDebugExitFD(socket);
    return GLOBUS_SUCCESS;

error_bind:
    GlobusXIOSystemDebugExitWithErrorFD(socket);
    return result;
}

globus_result_t
globus_xio_system_socket_listen(
    globus_xio_system_socket_t          socket,
    int                                 backlog)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_listen);
    
    GlobusXIOSystemDebugEnterFD(socket);
    
    if(listen(socket, backlog) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError("listen", WSAGetLastError());
        goto error_listen;
    }
    
    GlobusXIOSystemDebugExitFD(socket);
    return GLOBUS_SUCCESS;

error_listen:
    GlobusXIOSystemDebugExitWithErrorFD(socket);
    return result;
}

globus_result_t
globus_xio_system_socket_connect(
    globus_xio_system_socket_t          socket,
    const struct sockaddr *             addr,
    socklen_t                           addrlen)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_connect);
    
    GlobusXIOSystemDebugEnterFD(socket);
    
    if(connect(socket, addr, addrlen) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError("connect", WSAGetLastError());
        goto error_connect;
    }
    
    GlobusXIOSystemDebugExitFD(socket);
    return GLOBUS_SUCCESS;

error_connect:
    GlobusXIOSystemDebugExitWithErrorFD(socket);
    return result;
}

globus_result_t
globus_xio_system_socket_close(
    globus_xio_system_socket_t          socket)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_socket_close);
    
    GlobusXIOSystemDebugEnterFD(socket);
    
    if(closesocket(socket) == SOCKET_ERROR)
    {
        result = GlobusXIOErrorSystemError("closesocket", WSAGetLastError());
        goto error_close;
    }
    
    GlobusXIOSystemDebugExitFD(socket);
    return GLOBUS_SUCCESS;

error_close:
    GlobusXIOSystemDebugExitWithErrorFD(socket);
    return result;
}
