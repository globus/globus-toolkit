/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */


#include "config.h"
#include "globus_common.h"
#include "globus_xio_system.h"
#include "globus_xio_driver.h"

GlobusDebugDefine(GLOBUS_XIO_SYSTEM);

#define GlobusXIOSystemDebugPrintf(level, message)                          \
    GlobusDebugPrintf(GLOBUS_XIO_SYSTEM, level, message)

#define GlobusXIOSystemDebugFwrite(level, buffer, size, count)              \
    GlobusDebugFwrite(GLOBUS_XIO_SYSTEM, level, buffer, size, count)

#define GlobusXIOSystemDebugEnter()                                         \
    GlobusXIOSystemDebugPrintf(                                             \
        GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE,                                    \
        (_XIOSL("[%s] Entering\n"), _xio_name))

#define GlobusXIOSystemDebugExit()                                          \
    GlobusXIOSystemDebugPrintf(                                             \
        GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE,                                    \
        (_XIOSL("[%s] Exiting\n"), _xio_name))

#define GlobusXIOSystemDebugExitWithError()                                 \
    GlobusXIOSystemDebugPrintf(                                             \
        GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE,                                    \
        (_XIOSL("[%s] Exiting with error\n"), _xio_name))

#define GlobusXIOSystemDebugEnterFD(fd)                                     \
    GlobusXIOSystemDebugPrintf(                                             \
        GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE,                                    \
        (_XIOSL("[%s] fd=%d, Entering\n"), _xio_name, (fd)))

#define GlobusXIOSystemDebugExitFD(fd)                                      \
    GlobusXIOSystemDebugPrintf(                                             \
        GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE,                                    \
        (_XIOSL("[%s] fd=%d, Exiting\n"), _xio_name, (fd)))

#define GlobusXIOSystemDebugExitWithErrorFD(fd)                             \
    GlobusXIOSystemDebugPrintf(                                             \
        GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE,                                    \
        (_XIOSL("[%s] fd=%d, Exiting with error\n"), _xio_name, (fd)))

#define GlobusXIOSystemDebugRawBuffer(nbytes, buffer)                       \
    do                                                                      \
    {                                                                       \
        GlobusXIOSystemDebugPrintf(                                         \
            GLOBUS_L_XIO_SYSTEM_DEBUG_RAW,                                  \
            (_XIOSL("[%s] Begin RAW data ************\n"), _xio_name));             \
        GlobusXIOSystemDebugFwrite(                                         \
            GLOBUS_L_XIO_SYSTEM_DEBUG_RAW, buffer, 1, nbytes);              \
        GlobusXIOSystemDebugPrintf(                                         \
            GLOBUS_L_XIO_SYSTEM_DEBUG_RAW,                                  \
            (_XIOSL("\n[%s] End RAW data ************\n"), _xio_name));             \
    } while(0)
 
#define GlobusXIOSystemDebugRawIovec(nbytes, iovec)                         \
    do                                                                      \
    {                                                                       \
        if(GlobusDebugTrue(                                                 \
            GLOBUS_XIO_SYSTEM, GLOBUS_L_XIO_SYSTEM_DEBUG_RAW))              \
        {                                                                   \
            globus_size_t               _bytes = nbytes;                    \
            int                         _i = 0;                             \
                                                                            \
            while(_bytes > 0)                                               \
            {                                                               \
                globus_size_t           _len = (iovec)[_i].iov_len;         \
                                                                            \
                if(_bytes < _len)                                           \
                {                                                           \
                    _len = _bytes;                                          \
                }                                                           \
                _bytes -= _len;                                             \
                                                                            \
                GlobusDebugMyPrintf(                                        \
                    GLOBUS_XIO_SYSTEM,                                      \
                    (_XIOSL("[%s] Begin RAW data %i ************\n"),               \
                    _xio_name, _i));                                        \
                GlobusDebugMyFwrite(                                        \
                    GLOBUS_XIO_SYSTEM,                                      \
                    (iovec)[_i].iov_base, 1, _len);                         \
                GlobusDebugMyPrintf(                                        \
                    GLOBUS_XIO_SYSTEM,                                      \
                    (_XIOSL("\n[%s] End RAW data %i ************\n"),               \
                    _xio_name, _i));                                        \
                _i++;                                                       \
            }                                                               \
        }                                                                   \
    } while(0)

enum globus_l_xio_error_levels
{
    GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE     = 1,
    GLOBUS_L_XIO_SYSTEM_DEBUG_DATA      = 2,
    GLOBUS_L_XIO_SYSTEM_DEBUG_INFO      = 4,
    GLOBUS_L_XIO_SYSTEM_DEBUG_RAW       = 8
};

#ifdef HAVE_SYSCONF
#define GLOBUS_L_OPEN_MAX sysconf(_SC_OPEN_MAX)
#else
#define GLOBUS_L_OPEN_MAX 256
#endif

#define GlobusIXIOSystemAllocOperation(op_info)                             \
    do                                                                      \
    {                                                                       \
        globus_l_operation_info_t *     _op_info;                           \
                                                                            \
        _op_info = (globus_l_operation_info_t *)                            \
            globus_memory_pop_node(&globus_l_xio_system_op_info_memory);    \
        if(_op_info)                                                        \
        {                                                                   \
            memset(_op_info, 0, sizeof(globus_l_operation_info_t));         \
        }                                                                   \
        (op_info) = _op_info;                                               \
    } while(0)

#define GlobusIXIOSystemFreeOperation(op_info)                              \
    (globus_memory_push_node(&globus_l_xio_system_op_info_memory, (op_info)))

#define GlobusIXIOSystemAllocIovec(count, iov)                              \
    do                                                                      \
    {                                                                       \
        int                             _count;                             \
                                                                            \
        _count = (count);                                                   \
                                                                            \
        if(_count < 10)                                                     \
        {                                                                   \
            (iov) = (struct iovec *)                                        \
                globus_memory_pop_node(&globus_l_xio_system_iov_memory);    \
        }                                                                   \
        else                                                                \
        {                                                                   \
            (iov) = (struct iovec *)                                        \
                globus_malloc(sizeof(struct iovec) * _count);               \
        }                                                                   \
    } while(0)

#define GlobusIXIOSystemFreeIovec(count, iovec)                             \
    do                                                                      \
    {                                                                       \
        if((count) < 10)                                                    \
        {                                                                   \
            globus_memory_push_node(                                        \
                &globus_l_xio_system_iov_memory, (iovec));                  \
        }                                                                   \
        else                                                                \
        {                                                                   \
            globus_free((iovec));                                           \
        }                                                                   \
    } while(0)

#define GlobusIXIOSystemAllocMsghdr(msghdr)                                 \
    do                                                                      \
    {                                                                       \
        struct msghdr *                 _msghdr;                            \
                                                                            \
        _msghdr = (struct msghdr *)                                         \
            globus_memory_pop_node(&globus_l_xio_system_msghdr_memory);     \
        if(_msghdr)                                                         \
        {                                                                   \
            memset(_msghdr, 0, sizeof(struct msghdr));                      \
        }                                                                   \
        (msghdr) = _msghdr;                                                 \
    } while(0)

#define GlobusIXIOSystemFreeMsghdr(msghdr)                                  \
    (globus_memory_push_node(&globus_l_xio_system_msghdr_memory, (msghdr)))

#define GlobusIXIOSystemCloseFd(fd)                                         \
    do                                                                      \
    {                                                                       \
        int                             _rc;                                \
        int                             _fd;                                \
                                                                            \
        _fd = (fd);                                                         \
        do                                                                  \
        {                                                                   \
            _rc = close(_fd);                                               \
        } while(_rc < 0 && errno == EINTR);                                 \
    } while(0)

#define GlobusIXIOSystemAddNonBlocking(fd, rc)                              \
    do                                                                      \
    {                                                                       \
        int                             _fd;                                \
        int                             _flags;                             \
                                                                            \
        _fd = (fd);                                                         \
        _flags = fcntl(_fd, F_GETFL);                                       \
        if(_flags < 0)                                                      \
        {                                                                   \
            (rc) = _flags;                                                  \
        }                                                                   \
        else                                                                \
        {                                                                   \
            _flags |= O_NONBLOCK;                                           \
            (rc) = fcntl(_fd, F_SETFL, _flags);                             \
        }                                                                   \
    } while(0)

#define GlobusIXIOSystemRemoveNonBlocking(fd, rc)                           \
    do                                                                      \
    {                                                                       \
        int                             _fd;                                \
        int                             _flags;                             \
                                                                            \
        _fd = (fd);                                                         \
        _flags = fcntl(_fd, F_GETFL);                                       \
        if(_flags < 0)                                                      \
        {                                                                   \
            (rc) = _flags;                                                  \
        }                                                                   \
        else                                                                \
        {                                                                   \
             _flags &= ~O_NONBLOCK;                                         \
            (rc) = fcntl(_fd, F_SETFL, _flags);                             \
        }                                                                   \
    } while(0)

static
int
globus_l_xio_system_activate(void);

static
int
globus_l_xio_system_deactivate(void);

#include "version.h"

globus_module_descriptor_t              globus_i_xio_system_module =
{
    "globus_xio_system_select",
    globus_l_xio_system_activate,
    globus_l_xio_system_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef enum
{
    GLOBUS_L_OPERATION_ACCEPT,
    GLOBUS_L_OPERATION_CONNECT,
    GLOBUS_L_OPERATION_READ,
    GLOBUS_L_OPERATION_READV,
    GLOBUS_L_OPERATION_RECV,
    GLOBUS_L_OPERATION_RECVFROM,
    GLOBUS_L_OPERATION_RECVMSG,
    GLOBUS_L_OPERATION_WRITE,
    GLOBUS_L_OPERATION_WRITEV,
    GLOBUS_L_OPERATION_SEND,
    GLOBUS_L_OPERATION_SENDTO,
    GLOBUS_L_OPERATION_SENDMSG
} globus_l_operation_type_t;

typedef enum
{
    /* initial state */
    GLOBUS_L_OPERATION_NEW,
    /* transition to this requires fdset lock */
    GLOBUS_L_OPERATION_PENDING,
    /* transition to this requires cancel lock */
    GLOBUS_L_OPERATION_COMPLETE,
    /* transition to this requires fdset and cancel lock */
    GLOBUS_L_OPERATION_CANCELED
} globus_l_operation_state_t;

#define _sop_single          sop.data.buf.single
#define _sop_iovecCom        sop.data.buf.iovec
#define _sop_iovec           sop.data.buf.iovec.cont.plain
#define _sop_msg             sop.data.buf.iovec.cont.ex

typedef struct
{
    /* common members */
    globus_l_operation_type_t           type;
    globus_l_operation_state_t          state;
    globus_xio_operation_t              op;
    int                                 fd;
    globus_object_t *                   error;
    void *                              user_arg;
    /* used for reads/writes, 0 for others. here to simplify some things */
    globus_size_t                       nbytes;
    globus_size_t                       waitforbytes;

    union
    {
        /* non data ops -- connect, accept */
        struct
        {
            globus_xio_system_callback_t callback;
            int *                       out_fd;
        } non_data;

        /* data ops */
        struct
        {
            globus_xio_system_data_callback_t   callback;

            union
            {
                /* single buffer ops -- read, recv[from], write, send[to] */
                struct
                {
                    void *              buf;
                    globus_size_t       bufsize;

                    /* extra data used for recv[from] and send[to] */
                    struct
                    {
                        globus_sockaddr_t * addr;
                        int             flags;
                    } ex;
                } single;

                /* ops involving iovecs  -- readv, writev, recvmsg, sendmsg */
                struct
                {
                    struct iovec *      start_iov;
                    int                 start_iovc;

                    union
                    {
                        /* for readv and writev */
                        struct
                        {
                            struct iovec * iov;
                            int         iovc;
                        } plain;

                        /* for recvmsg and sendmsg */
                        struct
                        {
                            struct msghdr * msghdr;
                            int         flags;
                        } ex;
                    } cont;
                } iovec;
            } buf;
        } data;
    } sop;
} globus_l_operation_info_t;

static globus_cond_t                    globus_l_xio_system_cond;
static globus_mutex_t                   globus_l_xio_system_fdset_mutex;
static globus_mutex_t                   globus_l_xio_system_cancel_mutex;
static globus_bool_t                    globus_l_xio_system_select_active;
static globus_bool_t                    globus_l_xio_system_wakeup_pending;
static globus_bool_t                    globus_l_xio_system_shutdown_called;
static int                              globus_l_xio_system_highest_fd;
static int                              globus_l_xio_system_max_fds;
static int                              globus_l_xio_system_fd_allocsize;
static fd_set *                         globus_l_xio_system_read_fds;
static fd_set *                         globus_l_xio_system_write_fds;
static fd_set *                         globus_l_xio_system_ready_reads;
static fd_set *                         globus_l_xio_system_ready_writes;
static globus_list_t *                  globus_l_xio_system_canceled_reads;
static globus_list_t *                  globus_l_xio_system_canceled_writes;
static globus_l_operation_info_t **     globus_l_xio_system_read_operations;
static globus_l_operation_info_t **     globus_l_xio_system_write_operations;
static globus_memory_t                  globus_l_xio_system_op_info_memory;
static globus_memory_t                  globus_l_xio_system_iov_memory;
static globus_memory_t                  globus_l_xio_system_msghdr_memory;
static globus_bool_t                    globus_l_xio_system_memory_initialized;
static int                              globus_l_xio_system_wakeup_pipe[2];
static globus_callback_handle_t         globus_l_xio_system_poll_handle;

/* In the pre-activation of the thread module, we
 * are setting up some code to block the SIGPIPE
 * signal. This is necessary because some of
 * the TCP protocols we are using do not have
 * a mode in which we can safely detect a remotely-
 * closing socket.
 */

static
void
globus_l_xio_system_poll(
    void *                              user_args);

static
void
globus_l_xio_system_kickout(
    void *                              user_arg);

static
void
globus_l_xio_system_select_wakeup(void);

static
void
globus_l_xio_system_unregister_read(
    int                                 fd);

static
void
globus_l_xio_system_unregister_write(
    int                                 fd);

static
void
globus_l_xio_system_wakeup_handler(
    void *                              user_arg)
{
    int                                 rc;
    char                                byte;
    GlobusXIOName(globus_l_xio_system_wakeup_handler);

    GlobusXIOSystemDebugEnter();
    
    byte = 0;
    do
    {
        rc = write(globus_l_xio_system_wakeup_pipe[1], &byte, sizeof(byte));
    } while(rc < 0 && errno == EINTR);

    GlobusXIOSystemDebugExit();
}

static
int
globus_l_xio_system_activate(void)
{
    int                                 i;
    char *                              block;
    globus_result_t                     result;
    globus_reltime_t                    period;
    GlobusXIOName(globus_l_xio_system_activate);

    GlobusDebugInit(GLOBUS_XIO_SYSTEM, TRACE DATA INFO RAW);
    GlobusXIOSystemDebugEnter();

    if(globus_module_activate(GLOBUS_XIO_MODULE) != GLOBUS_SUCCESS)
    {
        goto error_activate;
    }

    globus_cond_init(&globus_l_xio_system_cond, GLOBUS_NULL);
    globus_mutex_init(&globus_l_xio_system_fdset_mutex, GLOBUS_NULL);
    globus_mutex_init(&globus_l_xio_system_cancel_mutex, GLOBUS_NULL);

    globus_l_xio_system_select_active = GLOBUS_FALSE;
    globus_l_xio_system_wakeup_pending = GLOBUS_FALSE;
    globus_l_xio_system_shutdown_called = GLOBUS_FALSE;

    /*
     * On some machines (SGI Irix at least), the fd_set structure isn't
     * necessarily large enough to hold the maximum number of open file
     * descriptors.  This ensures that it will be.
     */
    globus_l_xio_system_max_fds = GLOBUS_L_OPEN_MAX;
    globus_l_xio_system_fd_allocsize = sizeof(fd_set);
    if(globus_l_xio_system_fd_allocsize * 8 < globus_l_xio_system_max_fds)
    {
        /* Conservatively round up to 64 bits */
        globus_l_xio_system_fd_allocsize =
            ((globus_l_xio_system_max_fds + 63) & ~63) / 8;
    }

    i = globus_l_xio_system_fd_allocsize;
    block = (char *) globus_calloc(4, i);
    if(!block)
    {
        goto error_fdsets;
    }
    globus_l_xio_system_read_fds        = (fd_set *) block;
    globus_l_xio_system_write_fds       = (fd_set *) (block + i * 1);
    globus_l_xio_system_ready_reads     = (fd_set *) (block + i * 2);
    globus_l_xio_system_ready_writes    = (fd_set *) (block + i * 3);

    globus_l_xio_system_canceled_reads  = GLOBUS_NULL;
    globus_l_xio_system_canceled_writes = GLOBUS_NULL;

    globus_l_xio_system_read_operations = (globus_l_operation_info_t **)
        globus_calloc(
            globus_l_xio_system_max_fds * 2,
            sizeof(globus_l_operation_info_t *));
    if(!globus_l_xio_system_read_operations)
    {
        goto error_operations;
    }
    globus_l_xio_system_write_operations =
        globus_l_xio_system_read_operations + globus_l_xio_system_max_fds;

    /* I am going to leave this memory around after deactivation.  To safely
     * destroy them, I would need a lot more synchronization of kicked out
     * callbacks
     */
    if(!globus_l_xio_system_memory_initialized)
    {
        globus_l_xio_system_memory_initialized = 1;
        globus_memory_init(
            &globus_l_xio_system_op_info_memory,
            sizeof(globus_l_operation_info_t),
            10);
        globus_memory_init(
            &globus_l_xio_system_iov_memory, sizeof(struct iovec) * 10, 10);
        globus_memory_init(
            &globus_l_xio_system_msghdr_memory, sizeof(struct msghdr), 10);
    }

    /*
     * Create a pipe to myself, so that I can wake up the thread that is
     * blocked on a select().
     */
    if(pipe(globus_l_xio_system_wakeup_pipe) != 0)
    {
        goto error_pipe;
    }
    fcntl(globus_l_xio_system_wakeup_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(globus_l_xio_system_wakeup_pipe[1], F_SETFD, FD_CLOEXEC);
    
    globus_l_xio_system_highest_fd = globus_l_xio_system_wakeup_pipe[0];
    FD_SET(globus_l_xio_system_wakeup_pipe[0], globus_l_xio_system_read_fds);

    GlobusTimeReltimeSet(period, 0, 0);
    result = globus_callback_register_periodic(
        &globus_l_xio_system_poll_handle,
         GLOBUS_NULL,
         &period,
         globus_l_xio_system_poll,
         GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_callback_register_periodic", result);
        goto error_register;
    }
    
    globus_callback_add_wakeup_handler(
        globus_l_xio_system_wakeup_handler, GLOBUS_NULL);

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemCloseFd(globus_l_xio_system_wakeup_pipe[0]);
    GlobusIXIOSystemCloseFd(globus_l_xio_system_wakeup_pipe[1]);

error_pipe:
    globus_free(globus_l_xio_system_read_operations);

error_operations:
    globus_free(globus_l_xio_system_read_fds);

error_fdsets:
    globus_mutex_destroy(&globus_l_xio_system_cancel_mutex);
    globus_mutex_destroy(&globus_l_xio_system_fdset_mutex);
    globus_cond_destroy(&globus_l_xio_system_cond);
    globus_module_deactivate(GLOBUS_XIO_MODULE);

error_activate:
    GlobusXIOSystemDebugExitWithError();
    return GLOBUS_FAILURE;
}

static
void
globus_l_xio_system_unregister_periodic_cb(
    void *                              user_args)
{
    globus_bool_t *                     signaled;
    GlobusXIOName(globus_l_xio_system_unregister_periodic_cb);
    
    GlobusXIOSystemDebugEnter();
    
    signaled = (globus_bool_t *) user_args;
    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
    {
        *signaled = GLOBUS_TRUE;
        globus_cond_signal(&globus_l_xio_system_cond);
    }
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);

    GlobusXIOSystemDebugExit();
}

static
int
globus_l_xio_system_deactivate(void)
{
    GlobusXIOName(globus_l_xio_system_deactivate);

    GlobusXIOSystemDebugEnter();

    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
    {
        globus_bool_t                   signaled;
        
        globus_l_xio_system_shutdown_called = GLOBUS_TRUE;
        signaled = GLOBUS_FALSE;
        globus_callback_unregister(
            globus_l_xio_system_poll_handle,
            globus_l_xio_system_unregister_periodic_cb,
            &signaled,
            GLOBUS_NULL);
        globus_l_xio_system_wakeup_pending = GLOBUS_TRUE;
        globus_l_xio_system_select_wakeup();

        while(!signaled)
        {
            globus_cond_wait(
                &globus_l_xio_system_cond, &globus_l_xio_system_fdset_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);

    GlobusIXIOSystemCloseFd(globus_l_xio_system_wakeup_pipe[0]);
    GlobusIXIOSystemCloseFd(globus_l_xio_system_wakeup_pipe[1]);

    globus_list_free(globus_l_xio_system_canceled_reads);
    globus_list_free(globus_l_xio_system_canceled_writes);
    globus_free(globus_l_xio_system_read_operations);
    globus_free(globus_l_xio_system_read_fds);

    globus_mutex_destroy(&globus_l_xio_system_cancel_mutex);
    globus_mutex_destroy(&globus_l_xio_system_fdset_mutex);
    globus_cond_destroy(&globus_l_xio_system_cond);

    globus_module_deactivate(GLOBUS_XIO_MODULE);

    GlobusXIOSystemDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_SYSTEM);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_system_handle_init(
    globus_xio_system_handle_t *        handle,
    globus_xio_system_native_handle_t   fd,
    globus_xio_system_type_t            type)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_handle_init);

    GlobusXIOSystemDebugEnterFD(fd);

    GlobusIXIOSystemAddNonBlocking(fd, rc);
    if(rc < 0)
    {
        result = GlobusXIOErrorSystemError("fcntl", errno);
        goto error_fcntl;
    }
    
    *handle = fd;
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;
    
error_fcntl:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

void
globus_xio_system_handle_destroy(
    globus_xio_system_handle_t          fd)
{
    int                                 rc;
    GlobusXIOName(globus_xio_system_handle_destroy);

    GlobusXIOSystemDebugEnterFD(fd);

    GlobusIXIOSystemRemoveNonBlocking(fd, rc);
    
    GlobusXIOSystemDebugExitFD(fd);
}

static
void
globus_l_xio_system_cancel_cb(
    globus_xio_operation_t              op,
    void *                              user_arg,
    globus_xio_error_type_t             reason)
{
    globus_l_operation_info_t *         op_info;
    GlobusXIOName(globus_l_xio_system_cancel_cb);

    GlobusXIOSystemDebugEnter();

    op_info = (globus_l_operation_info_t *) user_arg;

    globus_mutex_lock(&globus_l_xio_system_cancel_mutex);
    {
        if(op_info->state != GLOBUS_L_OPERATION_COMPLETE && 
            op_info->state != GLOBUS_L_OPERATION_CANCELED)
        {
            op_info->error = reason == GLOBUS_XIO_ERROR_TIMEOUT
                ? GlobusXIOErrorObjTimeout()
                : GlobusXIOErrorObjCanceled();
                    
            globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
            {
                globus_bool_t           pend;
                
                if(op_info->state == GLOBUS_L_OPERATION_NEW)
                {
                    op_info->state = GLOBUS_L_OPERATION_CANCELED;
                        
                    GlobusXIOSystemDebugPrintf(
                        GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                        (_XIOSL("[%s] fd=%d, Canceling NEW\n"),
                            _xio_name, op_info->fd));
                }
                else
                {
                    if(globus_l_xio_system_select_active)
                    {
                        op_info->state = GLOBUS_L_OPERATION_CANCELED;
                        
                        GlobusXIOSystemDebugPrintf(
                            GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                            (_XIOSL("[%s] fd=%d, Canceling Active\n"),
                                _xio_name, op_info->fd));
                            
                        /* pend the cancel for after select wakes up */
                        if(!globus_l_xio_system_wakeup_pending)
                        {
                            globus_l_xio_system_wakeup_pending = GLOBUS_TRUE;
                            globus_l_xio_system_select_wakeup();
                        }

                        pend = GLOBUS_TRUE;
                    }
                    else
                    {
                        globus_result_t result;

                        op_info->state = GLOBUS_L_OPERATION_COMPLETE;
                        
                        GlobusXIOSystemDebugPrintf(
                            GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                            (_XIOSL("[%s] fd=%d, Canceling Pending\n"),
                                _xio_name, op_info->fd));
                                
                        /* unregister and kickout now */
                        result = globus_callback_register_oneshot(
                            GLOBUS_NULL,
                            GLOBUS_NULL,
                            globus_l_xio_system_kickout,
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

                        pend = GLOBUS_FALSE;
                    }

                    /* I can access op_info even though I oneshoted above
                     * because the CancelDisallow() call in the kickout will
                     * block until I leave this function
                     */
                    if(op_info->type == GLOBUS_L_OPERATION_READ             ||
                        op_info->type == GLOBUS_L_OPERATION_READV           ||
                        op_info->type == GLOBUS_L_OPERATION_RECV            ||
                        op_info->type == GLOBUS_L_OPERATION_RECVFROM        ||
                        op_info->type == GLOBUS_L_OPERATION_RECVMSG         ||
                        op_info->type == GLOBUS_L_OPERATION_ACCEPT)
                    {
                        if(pend)
                        {
                            globus_list_insert(
                                &globus_l_xio_system_canceled_reads,
                                (void *) op_info->fd);
                        }
                        else
                        {
                            globus_l_xio_system_unregister_read(op_info->fd);
                        }
                    }
                    else
                    {
                        if(pend)
                        {
                            globus_list_insert(
                                &globus_l_xio_system_canceled_writes,
                                (void *) op_info->fd);
                        }
                        else
                        {
                            globus_l_xio_system_unregister_write(op_info->fd);
                        }
                    }
                }
            }
            globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_xio_system_cancel_mutex);

    GlobusXIOSystemDebugExit();
}

static
globus_result_t
globus_l_xio_system_register_read(
    int                                 fd,
    globus_l_operation_info_t *         read_info)
{
    globus_result_t                     result;
    globus_bool_t                       do_wakeup = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_system_register_read);

    GlobusXIOSystemDebugEnterFD(fd);

    /* I have to do this outside the lock because of lock inversion issues */
    if(globus_xio_operation_enable_cancel(
        read_info->op, globus_l_xio_system_cancel_cb, read_info))
    {
        result = GlobusXIOErrorCanceled();
        goto error_cancel_enable;
    }

    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
    {
        /* this really shouldnt be possible, but to be thorough ... */
        if(read_info->state == GLOBUS_L_OPERATION_CANCELED)
        {
            result = globus_error_put(read_info->error);
            goto error_canceled;
        }

        if(globus_l_xio_system_shutdown_called)
        {
            result = GlobusXIOErrorNotActivated();
            goto error_deactivated;
        }
        
        if(fd >= globus_l_xio_system_max_fds)
        {
            result = GlobusXIOErrorSystemResource(_XIOSL("too many fds"));
            goto error_too_many_fds;
        }

        if(FD_ISSET(fd, globus_l_xio_system_read_fds))
        {
            result = GlobusXIOErrorAlreadyRegistered();
            goto error_already_registered;
        }

        if(fd > globus_l_xio_system_highest_fd)
        {
            globus_l_xio_system_highest_fd = fd;
        }

        FD_SET(fd, globus_l_xio_system_read_fds);
        globus_l_xio_system_read_operations[fd] = read_info;

        if(globus_l_xio_system_select_active &&
            !globus_l_xio_system_wakeup_pending)
        {
            globus_l_xio_system_wakeup_pending = GLOBUS_TRUE;
            do_wakeup = GLOBUS_TRUE;
        }

        read_info->state = GLOBUS_L_OPERATION_PENDING;
    }
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);

    if(do_wakeup)
    {
        /* I do this outside the lock because the select thread is likely
         * to wakeup immediately which would mean immediate contention for
         * that lock
         */
        globus_l_xio_system_select_wakeup();
    }
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_already_registered:
error_too_many_fds:
error_deactivated:
error_canceled:
    read_info->state = GLOBUS_L_OPERATION_COMPLETE;
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);
    globus_xio_operation_disable_cancel(read_info->op);

error_cancel_enable:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_register_write(
    int                                 fd,
    globus_l_operation_info_t *         write_info)
{
    globus_result_t                     result;
    globus_bool_t                       do_wakeup = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_system_register_write);

    GlobusXIOSystemDebugEnterFD(fd);

    /* I have to do this outside the lock because of lock inversion issues */
    if(globus_xio_operation_enable_cancel(
        write_info->op, globus_l_xio_system_cancel_cb, write_info))
    {
        result = GlobusXIOErrorCanceled();
        goto error_cancel_enable;
    }

    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
    {
        /* this really shouldnt be possible, but to be thorough ... */
        if(write_info->state == GLOBUS_L_OPERATION_CANCELED)
        {
            result = globus_error_put(write_info->error);
            goto error_canceled;
        }
        
        if(globus_l_xio_system_shutdown_called)
        {
            result = GlobusXIOErrorNotActivated();
            goto error_deactivated;
        }
        
        if(fd >= globus_l_xio_system_max_fds)
        {
            result = GlobusXIOErrorSystemResource(_XIOSL("too many fds"));
            goto error_too_many_fds;
        }

        if(FD_ISSET(fd, globus_l_xio_system_write_fds))
        {
            result = GlobusXIOErrorAlreadyRegistered();
            goto error_already_registered;
        }

        if(fd > globus_l_xio_system_highest_fd)
        {
            globus_l_xio_system_highest_fd = fd;
        }

        FD_SET(fd, globus_l_xio_system_write_fds);
        globus_l_xio_system_write_operations[fd] = write_info;

        if(globus_l_xio_system_select_active &&
            !globus_l_xio_system_wakeup_pending)
        {
            globus_l_xio_system_wakeup_pending = GLOBUS_TRUE;
            do_wakeup = GLOBUS_TRUE;
        }

        write_info->state = GLOBUS_L_OPERATION_PENDING;
    }
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);
    
    if(do_wakeup)
    {
        /* I do this outside the lock because the select thread is likely
         * to wakeup immediately which would mean immediate contention for
         * that lock
         */
        globus_l_xio_system_select_wakeup();
    }
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_already_registered:
error_too_many_fds:
error_deactivated:
error_canceled:
    write_info->state = GLOBUS_L_OPERATION_COMPLETE;
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);
    globus_xio_operation_disable_cancel(write_info->op);

error_cancel_enable:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

/* called locked */
static
void
globus_l_xio_system_unregister_read(
    int                                 fd)
{
    GlobusXIOName(globus_l_xio_system_unregister_read);

    GlobusXIOSystemDebugEnterFD(fd);

    globus_assert(FD_ISSET(fd, globus_l_xio_system_read_fds));
    FD_CLR(fd, globus_l_xio_system_read_fds);
    globus_l_xio_system_read_operations[fd] = GLOBUS_NULL;

    GlobusXIOSystemDebugExitFD(fd);
}

/* called locked */
static
void
globus_l_xio_system_unregister_write(
    int                                 fd)
{
    GlobusXIOName(globus_l_xio_system_unregister_write);

    GlobusXIOSystemDebugEnterFD(fd);

    globus_assert(FD_ISSET(fd, globus_l_xio_system_write_fds));
    FD_CLR(fd, globus_l_xio_system_write_fds);
    globus_l_xio_system_write_operations[fd] = GLOBUS_NULL;

    GlobusXIOSystemDebugExitFD(fd);
}

static
void
globus_l_xio_system_kickout(
    void *                              user_arg)
{
    globus_l_operation_info_t *         op_info;
    GlobusXIOName(globus_l_xio_system_kickout);

    op_info = (globus_l_operation_info_t *) user_arg;

    GlobusXIOSystemDebugEnterFD(op_info->fd);

    globus_xio_operation_disable_cancel(op_info->op);

    switch(op_info->type)
    {
      case GLOBUS_L_OPERATION_CONNECT:
      case GLOBUS_L_OPERATION_ACCEPT:
        op_info->sop.non_data.callback(
            op_info->error ? globus_error_put(op_info->error) : GLOBUS_SUCCESS,
            op_info->user_arg);
        break;

      default:
        op_info->sop.data.callback(
            op_info->error ? globus_error_put(op_info->error) : GLOBUS_SUCCESS,
            op_info->nbytes,
            op_info->user_arg);

        switch(op_info->type)
        {
          case GLOBUS_L_OPERATION_SENDMSG:
            if(op_info->_sop_msg.msghdr->msg_name)
            {
                globus_free(op_info->_sop_msg.msghdr->msg_name);
            }

            /* fall through */
          case GLOBUS_L_OPERATION_RECVMSG:
            GlobusIXIOSystemFreeMsghdr(op_info->_sop_msg.msghdr);

            /* fall through */
          case GLOBUS_L_OPERATION_READV:
          case GLOBUS_L_OPERATION_WRITEV:
            GlobusIXIOSystemFreeIovec(
                op_info->_sop_iovecCom.start_iovc,
                op_info->_sop_iovecCom.start_iov);
            break;

          case GLOBUS_L_OPERATION_SENDTO:
            globus_free(op_info->_sop_single.ex.addr);
            break;

          default:
            break;
        }

        break;
    }
    
    GlobusXIOSystemDebugExitFD(op_info->fd);
    GlobusIXIOSystemFreeOperation(op_info);
}

static
void
globus_l_xio_system_select_wakeup(void)
{
    globus_ssize_t                      rc;
    char                                byte;
    GlobusXIOName(globus_l_xio_system_select_wakeup);

    GlobusXIOSystemDebugEnter();
    
    byte = 0;

    do
    {
        rc = write(globus_l_xio_system_wakeup_pipe[1], &byte, sizeof(byte));
    } while(rc < 0 && errno == EINTR);

    if(rc <= 0)
    {
        globus_panic(
            GLOBUS_XIO_SYSTEM_MODULE,
            GlobusXIOErrorSystemError("write", errno),
            _XIOSL("[%s:%d] Couldn't wakeup select"),
            _xio_name,
            __LINE__);
    }

    GlobusXIOSystemDebugExit();
}

static
void
globus_l_xio_system_handle_wakeup(void)
{
    char                                buf[64];
    globus_ssize_t                      done;
    GlobusXIOName(globus_l_xio_system_handle_wakeup);

    GlobusXIOSystemDebugEnter();

    do
    {
        done = read(globus_l_xio_system_wakeup_pipe[0], buf, sizeof(buf));
    } while(done < 0 && errno == EINTR);

    GlobusXIOSystemDebugExit();
}

static
globus_result_t
globus_l_xio_system_try_read(
    int                                 fd,
    void *                              buf,
    globus_size_t                       buflen,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc = 0;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_read);

    GlobusXIOSystemDebugEnterFD(fd);
    
    /* calls to this with buflen == 0 are requesting select only */
    if(buflen)
    {
        do
        {
            rc = read(fd, buf, buflen);
        } while(rc < 0 && errno == EINTR);
    
        if(rc < 0)
        {
            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                rc = 0;
            }
            else
            {
                result = GlobusXIOErrorSystemError("read", errno);
                goto error_errno;
            }
        }
        else if(rc == 0) /* what about UDP? */
        {
            result = GlobusXIOErrorEOF();
            goto error_eof;
        }
        
        GlobusXIOSystemDebugPrintf(
            GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
            (_XIOSL("[%s] Read %d bytes (buflen = %d)\n"), _xio_name, rc, buflen));
        
        GlobusXIOSystemDebugRawBuffer(rc, buf);
    }

    *nbytes = rc;

    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_try_readv(
    int                                 fd,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_readv);

    GlobusXIOSystemDebugEnterFD(fd);

    do
    {
        rc = readv(fd, iov, (iovc > IOV_MAX) ? IOV_MAX : iovc);
    } while(rc < 0 && errno == EINTR);

    if(rc < 0)
    {
        if(errno == EAGAIN || errno == EWOULDBLOCK)
        {
            rc = 0;
        }
        else
        {
            result = GlobusXIOErrorSystemError("readv", errno);
            goto error_errno;
        }
    }
    else if(rc == 0)
    {
        result = GlobusXIOErrorEOF();
        goto error_eof;
    }

    *nbytes = rc;
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        (_XIOSL("[%s] Read %d bytes\n"), _xio_name, rc));
    
    GlobusXIOSystemDebugRawIovec(rc, iov);
            
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_try_recv(
    int                                 fd,
    void *                              buf,
    globus_size_t                       buflen,
    int                                 flags,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc = 0;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_recv);

    GlobusXIOSystemDebugEnterFD(fd);

    if(buflen)
    {
        do
        {
            rc = recv(fd, buf, buflen, flags);
        } while(rc < 0 && errno == EINTR);
    
        if(rc < 0)
        {
            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                rc = 0;
            }
            else
            {
                result = GlobusXIOErrorSystemError("recv", errno);
                goto error_errno;
            }
        }
        else if(rc == 0)
        {
            result = GlobusXIOErrorEOF();
            goto error_eof;
        }
    
        GlobusXIOSystemDebugPrintf(
            GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
            (_XIOSL("[%s] Read %d bytes\n"), _xio_name, rc));
        
        GlobusXIOSystemDebugRawBuffer(rc, buf);
    }
    
    *nbytes = rc;
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_try_recvfrom(
    int                                 fd,
    void *                              buf,
    globus_size_t                       buflen,
    int                                 flags,
    globus_sockaddr_t *                 from,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc = 0;
    globus_result_t                     result;
    globus_socklen_t                    len;
    GlobusXIOName(globus_l_xio_system_try_recvfrom);

    GlobusXIOSystemDebugEnterFD(fd);
    
    if(buflen)
    {
        do
        {
            len = sizeof(globus_sockaddr_t);
            rc = recvfrom(
                fd,
                buf,
                buflen,
                flags,
                (struct sockaddr *) from,
                &len);
        } while(rc < 0 && errno == EINTR);
    
        if(rc < 0)
        {
            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                rc = 0;
            }
            else
            {
                result = GlobusXIOErrorSystemError("recvfrom", errno);
                goto error_errno;
            }
        }
        else if(rc == 0)
        {
            result = GlobusXIOErrorEOF();
            goto error_eof;
        }
    
        GlobusXIOSystemDebugPrintf(
            GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
            (_XIOSL("[%s] Read %d bytes\n"), _xio_name, rc));
        
        GlobusXIOSystemDebugRawBuffer(rc, buf);
    }
    
    *nbytes = rc;
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_try_recvmsg(
    int                                 fd,
    struct msghdr *                     msghdr,
    int                                 flags,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_recvmsg);

    GlobusXIOSystemDebugEnterFD(fd);

    do
    {
        rc = recvmsg(fd, msghdr, flags);
    } while(rc < 0 && errno == EINTR);

    if(rc < 0)
    {
        if(errno == EAGAIN || errno == EWOULDBLOCK)
        {
            rc = 0;
        }
        else
        {
            result = GlobusXIOErrorSystemError("recvmsg", errno);
            goto error_errno;
        }
    }
    else if(rc == 0)
    {
        result = GlobusXIOErrorEOF();
        goto error_eof;
    }

    *nbytes = rc;
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        (_XIOSL("[%s] Read %d bytes\n"), _xio_name, rc));
    
    GlobusXIOSystemDebugRawIovec(rc, msghdr->msg_iov);
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_try_write(
    int                                 fd,
    void *                              buf,
    globus_size_t                       buflen,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc = 0;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_write);

    GlobusXIOSystemDebugEnterFD(fd);
    
    /* calls to this with buflen == 0 are requesting select only */
    if(buflen)
    {
        do
        {
            rc = write(fd, buf, buflen);
        } while(rc < 0 && errno == EINTR);
    
        if(rc < 0)
        {
            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                rc = 0;
            }
            else
            {
                result = GlobusXIOErrorSystemError("write", errno);
                goto error_errno;
            }
        }
        
        GlobusXIOSystemDebugPrintf(
            GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
            (_XIOSL("[%s] Wrote %d bytes\n"), _xio_name, rc));
    
        GlobusXIOSystemDebugRawBuffer(rc, buf);
    }

    *nbytes = rc;
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_try_writev(
    int                                 fd,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_writev);

    GlobusXIOSystemDebugEnterFD(fd);

    do
    {
        rc = writev(fd, iov, (iovc > IOV_MAX) ? IOV_MAX : iovc);
    } while(rc < 0 && errno == EINTR);

    if(rc < 0)
    {
        if(errno == EAGAIN || errno == EWOULDBLOCK)
        {
            rc = 0;
        }
        else
        {
            result = GlobusXIOErrorSystemError("writev", errno);
            goto error_errno;
        }
    }

    *nbytes = rc;
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        (_XIOSL("[%s] Wrote %d bytes\n"), _xio_name, rc));
    
    GlobusXIOSystemDebugRawIovec(rc, iov);
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_try_send(
    int                                 fd,
    void *                              buf,
    globus_size_t                       buflen,
    int                                 flags,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc = 0;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_send);

    GlobusXIOSystemDebugEnterFD(fd);
    
    if(buflen)
    {
        do
        {
            rc = send(fd, buf, buflen, flags);
        } while(rc < 0 && errno == EINTR);
    
        if(rc < 0)
        {
            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                rc = 0;
            }
            else
            {
                result = GlobusXIOErrorSystemError("send", errno);
                goto error_errno;
            }
        }
    
        GlobusXIOSystemDebugPrintf(
            GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
            (_XIOSL("[%s] Wrote %d bytes\n"), _xio_name, rc));
        
        GlobusXIOSystemDebugRawBuffer(rc, buf);
    }
    
    *nbytes = rc;
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_try_sendto(
    int                                 fd,
    void *                              buf,
    globus_size_t                       buflen,
    int                                 flags,
    const globus_sockaddr_t *           to,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc = 0;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_sendto);

    GlobusXIOSystemDebugEnterFD(fd);
    
    if(buflen)
    {
        do
        {
            rc = sendto(
                fd,
                buf,
                buflen,
                flags,
                (const struct sockaddr *) to,
                GlobusLibcSockaddrLen(to));
        } while(rc < 0 && errno == EINTR);
    
        if(rc < 0)
        {
            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                rc = 0;
            }
            else
            {
                result = GlobusXIOErrorSystemError("sendto", errno);
                goto error_errno;
            }
        }
    
        GlobusXIOSystemDebugPrintf(
            GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
            (_XIOSL("[%s] Wrote %d bytes\n"), _xio_name, rc));
        
        GlobusXIOSystemDebugRawBuffer(rc, buf);
    }
    
    *nbytes = rc;
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_result_t
globus_l_xio_system_try_sendmsg(
    int                                 fd,
    struct msghdr *                     msghdr,
    int                                 flags,
    globus_size_t *                     nbytes)
{
    globus_ssize_t                      rc;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_sendmsg);

    GlobusXIOSystemDebugEnterFD(fd);

    do
    {
        rc = sendmsg(fd, msghdr, flags);
    } while(rc < 0 && errno == EINTR);

    if(rc < 0)
    {
        if(errno == EAGAIN || errno == EWOULDBLOCK)
        {
            rc = 0;
        }
        else
        {
            result = GlobusXIOErrorSystemError("sendmsg", errno);
            goto error_errno;
        }
    }

    *nbytes = rc;
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        (_XIOSL("[%s] Wrote %d bytes\n"), _xio_name, rc));
    
    GlobusXIOSystemDebugRawIovec(rc, msghdr->msg_iov);
    
    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

static
globus_bool_t
globus_l_xio_system_handle_read(
    int                                 fd)
{
    globus_bool_t                       handled_it;
    globus_l_operation_info_t *         read_info;
    globus_size_t                       nbytes;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_handle_read);

    GlobusXIOSystemDebugEnterFD(fd);

    handled_it = GLOBUS_FALSE;
    read_info = globus_l_xio_system_read_operations[fd];
    result = GLOBUS_SUCCESS;

    globus_xio_operation_refresh_timeout(read_info->op);

    if(read_info->state == GLOBUS_L_OPERATION_CANCELED)
    {
        /* error already set on info */
        goto error_canceled;
    }

    switch(read_info->type)
    {
      case GLOBUS_L_OPERATION_ACCEPT:
        {
            int                         new_fd;

            do
            {
                new_fd = accept(fd, GLOBUS_NULL, GLOBUS_NULL);
            } while(new_fd < 0 && errno == EINTR);

            if(new_fd < 0)
            {
                if(errno != ECONNABORTED &&
                    errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    result = GlobusXIOErrorSystemError("accept", errno);
                }
            }
            else
            {
                *read_info->sop.non_data.out_fd = new_fd;
                read_info->nbytes++;
                GlobusXIOSystemDebugPrintf(
                    GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                    (_XIOSL("[%s] Accepted new connection, fd=%d\n"),
                         _xio_name, new_fd));
            }
        }
        break;

      case GLOBUS_L_OPERATION_READ:
        result = globus_l_xio_system_try_read(
            fd,
            read_info->_sop_single.buf,
            read_info->_sop_single.bufsize,
            &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            read_info->_sop_single.buf = (char *)
                read_info->_sop_single.buf + nbytes;
            read_info->_sop_single.bufsize -= nbytes;
            read_info->nbytes += nbytes;
        }
        break;

      case GLOBUS_L_OPERATION_READV:
        result = globus_l_xio_system_try_readv(
            fd, read_info->_sop_iovec.iov, read_info->_sop_iovec.iovc, &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            read_info->nbytes += nbytes;
            GlobusIXIOUtilAdjustIovec(
                read_info->_sop_iovec.iov, read_info->_sop_iovec.iovc, nbytes);
        }
        break;

      case GLOBUS_L_OPERATION_RECV:
        result = globus_l_xio_system_try_recv(
            fd,
            read_info->_sop_single.buf,
            read_info->_sop_single.bufsize,
            read_info->_sop_single.ex.flags,
            &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            read_info->_sop_single.buf = (char *)
                read_info->_sop_single.buf + nbytes;
            read_info->_sop_single.bufsize -= nbytes;
            read_info->nbytes += nbytes;
        }
        break;

      case GLOBUS_L_OPERATION_RECVFROM:
        result = globus_l_xio_system_try_recvfrom(
            fd,
            read_info->_sop_single.buf,
            read_info->_sop_single.bufsize,
            read_info->_sop_single.ex.flags,
            read_info->_sop_single.ex.addr,
            &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            read_info->_sop_single.buf = (char *)
                read_info->_sop_single.buf + nbytes;
            read_info->_sop_single.bufsize -= nbytes;
            read_info->nbytes += nbytes;
        }
        break;

      case GLOBUS_L_OPERATION_RECVMSG:
        result = globus_l_xio_system_try_recvmsg(
            fd, read_info->_sop_msg.msghdr, read_info->_sop_msg.flags, &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            struct msghdr *             msghdr;

            read_info->nbytes += nbytes;
            msghdr = read_info->_sop_msg.msghdr;
            GlobusIXIOUtilAdjustIovec(
                msghdr->msg_iov, msghdr->msg_iovlen, nbytes);
        }
        break;

      case GLOBUS_L_OPERATION_CONNECT:
      case GLOBUS_L_OPERATION_WRITE:
      case GLOBUS_L_OPERATION_WRITEV:
      case GLOBUS_L_OPERATION_SEND:
      case GLOBUS_L_OPERATION_SENDTO:
      case GLOBUS_L_OPERATION_SENDMSG:
      default:
        globus_assert(0 && "Unexpected type for read operation");
        return GLOBUS_FALSE;
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
error_canceled:
        handled_it = GLOBUS_TRUE;
        read_info->state = GLOBUS_L_OPERATION_COMPLETE;

        globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
        {
            globus_l_xio_system_unregister_read(fd);
        }
        globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);

        result = globus_callback_register_oneshot(
            GLOBUS_NULL, GLOBUS_NULL, globus_l_xio_system_kickout, read_info);
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

    GlobusXIOSystemDebugExitFD(fd);
    return handled_it;
}

static
globus_bool_t
globus_l_xio_system_handle_write(
    int                                 fd)
{
    globus_bool_t                       handled_it;
    globus_l_operation_info_t *         write_info;
    globus_size_t                       nbytes;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_handle_write);

    GlobusXIOSystemDebugEnterFD(fd);

    handled_it = GLOBUS_FALSE;
    result = GLOBUS_SUCCESS;
    write_info = globus_l_xio_system_write_operations[fd];

    globus_xio_operation_refresh_timeout(write_info->op);

    if(write_info->state == GLOBUS_L_OPERATION_CANCELED)
    {
        /* error already set on info */
        goto error_canceled;
    }

    switch(write_info->type)
    {
      case GLOBUS_L_OPERATION_CONNECT:
        {
            int                         err;
            globus_socklen_t            errlen;

            errlen = sizeof(err);
            if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0)
            {
                err = errno;
            }

            if(err)
            {
                result = GlobusXIOErrorSystemError("connect", err);
            }
        }
        break;

      case GLOBUS_L_OPERATION_WRITE:
        result = globus_l_xio_system_try_write(
            fd,
            write_info->_sop_single.buf,
            write_info->_sop_single.bufsize,
            &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            write_info->_sop_single.buf = (char *)
                write_info->_sop_single.buf + nbytes;
            write_info->_sop_single.bufsize -= nbytes;
            write_info->nbytes += nbytes;
        }
        break;

      case GLOBUS_L_OPERATION_WRITEV:
        result = globus_l_xio_system_try_writev(
            fd,
            write_info->_sop_iovec.iov,
            write_info->_sop_iovec.iovc,
            &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            write_info->nbytes += nbytes;
            GlobusIXIOUtilAdjustIovec(
                write_info->_sop_iovec.iov, write_info->_sop_iovec.iovc, nbytes);
        }
        break;

      case GLOBUS_L_OPERATION_SEND:
        result = globus_l_xio_system_try_send(
            fd,
            write_info->_sop_single.buf,
            write_info->_sop_single.bufsize,
            write_info->_sop_single.ex.flags,
            &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            write_info->_sop_single.buf = (char *)
                write_info->_sop_single.buf + nbytes;
            write_info->_sop_single.bufsize -= nbytes;
            write_info->nbytes += nbytes;
        }
        break;

      case GLOBUS_L_OPERATION_SENDTO:
        result = globus_l_xio_system_try_sendto(
            fd,
            write_info->_sop_single.buf,
            write_info->_sop_single.bufsize,
            write_info->_sop_single.ex.flags,
            write_info->_sop_single.ex.addr,
            &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            write_info->_sop_single.buf = (char *)
                write_info->_sop_single.buf + nbytes;
            write_info->_sop_single.bufsize -= nbytes;
            write_info->nbytes += nbytes;
        }
        break;

      case GLOBUS_L_OPERATION_SENDMSG:
        result = globus_l_xio_system_try_sendmsg(
            fd,
            write_info->_sop_msg.msghdr,
            write_info->_sop_msg.flags,
            &nbytes);

        if(result == GLOBUS_SUCCESS)
        {
            struct msghdr *             msghdr;

            write_info->nbytes += nbytes;
            msghdr = write_info->_sop_msg.msghdr;
            GlobusIXIOUtilAdjustIovec(
                msghdr->msg_iov, msghdr->msg_iovlen, nbytes);
        }
        break;

      case GLOBUS_L_OPERATION_ACCEPT:
      case GLOBUS_L_OPERATION_READ:
      case GLOBUS_L_OPERATION_READV:
      case GLOBUS_L_OPERATION_RECV:
      case GLOBUS_L_OPERATION_RECVFROM:
      case GLOBUS_L_OPERATION_RECVMSG:
      default:
        globus_assert(0 && "Unexpected type for write operation");
        return GLOBUS_FALSE;
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
error_canceled:
        handled_it = GLOBUS_TRUE;
        write_info->state = GLOBUS_L_OPERATION_COMPLETE;

        globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
        {
            globus_l_xio_system_unregister_write(fd);
        }
        globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);

        result = globus_callback_register_oneshot(
            GLOBUS_NULL, GLOBUS_NULL, globus_l_xio_system_kickout, write_info);
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

    GlobusXIOSystemDebugExitFD(fd);
    return handled_it;
}

/**
 * one of these fds is bad, lock down the fdset and check them all
 * --- assumed to be called with cancel lock held after a select
 */
static
void
globus_l_xio_system_bad_apple(void)
{
    globus_l_operation_info_t *         op_info;
    int                                 fd;
    struct stat                         stat_buf;
    GlobusXIOName(globus_l_xio_system_bad_apple);

    GlobusXIOSystemDebugEnter();
    
    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
    {
        for(fd = 0; fd <= globus_l_xio_system_highest_fd; fd++)
        {
            if(FD_ISSET(fd, globus_l_xio_system_read_fds))
            {
                if(fstat(fd, &stat_buf) < 0 && errno == EBADF)
                {
                    GlobusXIOSystemDebugPrintf(
                        GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                        (_XIOSL("[%s] fd=%d, Canceling read bad apple\n"), 
                        _xio_name, fd));
                    
                    op_info = globus_l_xio_system_read_operations[fd];
                    if(op_info->state == GLOBUS_L_OPERATION_PENDING)
                    {
                        op_info->state = GLOBUS_L_OPERATION_CANCELED;
                        op_info->error = GlobusXIOErrorObjParameter("handle");
                        globus_list_insert(
                            &globus_l_xio_system_canceled_reads, (void *) fd);
                    }
                }
            }
            
            if(FD_ISSET(fd, globus_l_xio_system_write_fds))
            {
                if(fstat(fd, &stat_buf) < 0 && errno == EBADF)
                {
                    GlobusXIOSystemDebugPrintf(
                        GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                        (_XIOSL("[%s] fd=%d, Canceling write bad apple\n"),
                        _xio_name, fd));
                    
                    op_info = globus_l_xio_system_write_operations[fd];
                    if(op_info->state == GLOBUS_L_OPERATION_PENDING)
                    {
                        op_info->state = GLOBUS_L_OPERATION_CANCELED;
                        op_info->error = GlobusXIOErrorObjParameter("handle");
                        globus_list_insert(
                            &globus_l_xio_system_canceled_writes, (void *) fd);
                    }
                }
            }
        }
    }
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);
    
    GlobusXIOSystemDebugExit();
}

static
void
globus_l_xio_system_poll(
    void *                              user_args)
{
    globus_bool_t                       time_left_is_zero;
    globus_bool_t                       handled_something;
    GlobusXIOName(globus_l_xio_system_poll);

    GlobusXIOSystemDebugEnter();

    handled_something = GLOBUS_FALSE;

    do
    {
        globus_reltime_t                time_left;
        globus_bool_t                   time_left_is_infinity;
        int                             num;
        int                             nready;
        int                             fd;
        int                             save_errno;
        
        time_left_is_zero = GLOBUS_FALSE;
        time_left_is_infinity = GLOBUS_FALSE;

        globus_callback_get_timeout(&time_left);

        if(globus_reltime_cmp(&time_left, &globus_i_reltime_zero) == 0)
        {
            time_left_is_zero = GLOBUS_TRUE;
        }
        else if(globus_time_reltime_is_infinity(&time_left))
        {
            time_left_is_infinity = GLOBUS_TRUE;
        }

        globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
        {
            memcpy(
                globus_l_xio_system_ready_reads,
                globus_l_xio_system_read_fds,
                globus_l_xio_system_fd_allocsize);
            memcpy(
                globus_l_xio_system_ready_writes,
                globus_l_xio_system_write_fds,
                globus_l_xio_system_fd_allocsize);

            num = globus_l_xio_system_highest_fd + 1;
            globus_l_xio_system_select_active = GLOBUS_TRUE;
        }
        globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);
        
        GlobusXIOSystemDebugPrintf(
            GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
            (_XIOSL("[%s] Before select\n"), _xio_name));
                    
        nready = select(
            num,
            globus_l_xio_system_ready_reads,
            globus_l_xio_system_ready_writes,
            GLOBUS_NULL,
            (time_left_is_infinity ? GLOBUS_NULL : &time_left));
        save_errno = errno;
        
        GlobusXIOSystemDebugPrintf(
            GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
            (_XIOSL("[%s] After select\n"), _xio_name));
        
        globus_mutex_lock(&globus_l_xio_system_cancel_mutex);
        {
            globus_l_xio_system_select_active = GLOBUS_FALSE;
            
            if(nready > 0)
            {
                fd = globus_l_xio_system_wakeup_pipe[0];
                if(FD_ISSET(fd, globus_l_xio_system_ready_reads))
                {
                    globus_l_xio_system_handle_wakeup();
                    globus_l_xio_system_wakeup_pending = GLOBUS_FALSE;
                    FD_CLR(fd, globus_l_xio_system_ready_reads);
                    nready--;
                }
            }
            else if(nready == 0)
            {
                time_left_is_zero = GLOBUS_TRUE;
            }
            else
            {
                if(save_errno == EBADF)
                {
                    globus_l_xio_system_bad_apple();
                }
                
                /**
                 * can't really do anything about other errors
                 * so, set ready fds to known state in case there are things
                 * to be canceled
                 */
                nready = 0;
                memset(
                    globus_l_xio_system_ready_reads,
                    0,
                    globus_l_xio_system_fd_allocsize);
                memset(
                    globus_l_xio_system_ready_writes,
                    0,
                    globus_l_xio_system_fd_allocsize);
            }

            while(!globus_list_empty(globus_l_xio_system_canceled_reads))
            {
                fd = (int) globus_list_remove(
                    &globus_l_xio_system_canceled_reads,
                    globus_l_xio_system_canceled_reads);
                
                GlobusXIOSystemDebugPrintf(
                    GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                    (_XIOSL("[%s] fd=%d, Setting canceled read\n"), _xio_name, fd));
                    
                if(!FD_ISSET(fd, globus_l_xio_system_ready_reads))
                {
                    FD_SET(fd, globus_l_xio_system_ready_reads);
                    nready++;
                }
            }

            while(!globus_list_empty(globus_l_xio_system_canceled_writes))
            {
                fd = (int) globus_list_remove(
                    &globus_l_xio_system_canceled_writes,
                    globus_l_xio_system_canceled_writes);
                
                GlobusXIOSystemDebugPrintf(
                    GLOBUS_L_XIO_SYSTEM_DEBUG_INFO,
                    (_XIOSL("[%s] fd=%d, Setting canceled read\n"), _xio_name, fd));
                    
                if(!FD_ISSET(fd, globus_l_xio_system_ready_writes))
                {
                    FD_SET(fd, globus_l_xio_system_ready_writes);
                    nready++;
                }
            }

            for(fd = 0; nready; fd++)
            {
                if(FD_ISSET(fd, globus_l_xio_system_ready_reads))
                {
                    nready--;

                    if(globus_l_xio_system_handle_read(fd))
                    {
                        handled_something = GLOBUS_TRUE;
                    }
                }

                if(FD_ISSET(fd, globus_l_xio_system_ready_writes))
                {
                    nready--;

                    if(globus_l_xio_system_handle_write(fd))
                    {
                        handled_something = GLOBUS_TRUE;
                    }
                }
            }
        }
        globus_mutex_unlock(&globus_l_xio_system_cancel_mutex);

    } while(!handled_something &&
        !time_left_is_zero &&
        !globus_l_xio_system_shutdown_called);

    GlobusXIOSystemDebugExit();
}

globus_result_t
globus_xio_system_register_connect(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          fd,
    const globus_sockaddr_t *           addr,
    globus_xio_system_callback_t        callback,
    void *                              user_arg)
{
    globus_bool_t                       done;
    globus_result_t                     result;
    globus_l_operation_info_t *         op_info;
    GlobusXIOName(globus_xio_system_register_connect);

    GlobusXIOSystemDebugEnterFD(fd);

    done = GLOBUS_FALSE;
    while(!done && connect(
        fd, (const struct sockaddr *) addr, GlobusLibcSockaddrLen(addr)) < 0)
    {
        switch(errno)
        {
          case EINPROGRESS:
            done = GLOBUS_TRUE;
            break;

          case EINTR:
            /* retry */
            break;

          case ETIMEDOUT: /* this was in globus io.. not sure why */
            globus_thread_yield();
            break;

          default:
            result = GlobusXIOErrorSystemError("connect", errno);
            goto error_connect;
        }
    }

    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }

    op_info->type = GLOBUS_L_OPERATION_CONNECT;
    op_info->state = GLOBUS_L_OPERATION_NEW;
    op_info->op = op;
    op_info->fd = fd;
    op_info->user_arg = user_arg;
    op_info->sop.non_data.callback = callback;

    result = globus_l_xio_system_register_write(fd, op_info);

    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            _XIOSL("globus_l_xio_system_register_write"), result);
        goto error_register;

    }

    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
error_connect:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

globus_result_t
globus_xio_system_register_accept(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          listener_fd,
    globus_xio_system_native_handle_t * out_fd,
    globus_xio_system_callback_t        callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_operation_info_t *         op_info;
    GlobusXIOName(globus_xio_system_register_accept);

    GlobusXIOSystemDebugEnterFD(listener_fd);
    
    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }

    op_info->type = GLOBUS_L_OPERATION_ACCEPT;
    op_info->state = GLOBUS_L_OPERATION_NEW;
    op_info->op = op;
    op_info->fd = listener_fd;
    op_info->user_arg = user_arg;
    op_info->sop.non_data.callback = callback;
    op_info->sop.non_data.out_fd = out_fd;
    op_info->waitforbytes = 1;

    result = globus_l_xio_system_register_read(listener_fd, op_info);

    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            _XIOSL("globus_l_xio_system_register_read"), result);
        goto error_register;
    }

    GlobusXIOSystemDebugExitFD(listener_fd);
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
    GlobusXIOSystemDebugExitWithErrorFD(listener_fd);
    return result;
}

globus_result_t
globus_xio_system_register_read(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          fd,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_operation_info_t *         op_info;
    struct iovec *                      iov;
    GlobusXIOName(globus_xio_system_register_read);

    GlobusXIOSystemDebugEnterFD(fd);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        (_XIOSL("[%s] Waiting for %u bytes\n"), _xio_name, (unsigned) waitforbytes));
        
    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }

    if(u_iovc == 1)
    {
        op_info->type = GLOBUS_L_OPERATION_READ;
        op_info->_sop_single.buf = u_iov->iov_base;
        op_info->_sop_single.bufsize = u_iov->iov_len;
    }
    else
    {
        GlobusIXIOSystemAllocIovec(u_iovc, iov);
        if(!iov)
        {
            result = GlobusXIOErrorMemory("iov");
            goto error_iovec;
        }

        GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);

        op_info->type = GLOBUS_L_OPERATION_READV;
        op_info->_sop_iovecCom.start_iov = iov;
        op_info->_sop_iovec.iov = iov;
        op_info->_sop_iovecCom.start_iovc = u_iovc;
        op_info->_sop_iovec.iovc = u_iovc;
    }

    op_info->state = GLOBUS_L_OPERATION_NEW;
    op_info->op = op;
    op_info->fd = fd;
    op_info->user_arg = user_arg;
    op_info->sop.data.callback = callback;
    op_info->waitforbytes = waitforbytes;

    result = globus_l_xio_system_register_read(fd, op_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_system_register_read", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_register:
    if(u_iovc != 1)
    {
        GlobusIXIOSystemFreeIovec(u_iovc, iov);
    }

error_iovec:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

globus_result_t
globus_xio_system_register_read_ex(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          fd,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 from,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_operation_info_t *         op_info;
    struct iovec *                      iov;
    struct msghdr *                     msghdr;
    GlobusXIOName(globus_xio_system_register_read_ex);

    GlobusXIOSystemDebugEnterFD(fd);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        (_XIOSL("[%s] Waiting for %u bytes\n"), _xio_name, (unsigned) waitforbytes));
        
    if(!flags && !from)
    {
        return globus_xio_system_register_read(
            op, fd, u_iov, u_iovc, waitforbytes, callback, user_arg);
    }

    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }

    if(u_iovc == 1)
    {
        if(from)
        {
            op_info->type = GLOBUS_L_OPERATION_RECVFROM;
            op_info->_sop_single.ex.addr = from;
        }
        else
        {
            op_info->type = GLOBUS_L_OPERATION_RECV;
        }

        op_info->_sop_single.buf = u_iov->iov_base;
        op_info->_sop_single.bufsize = u_iov->iov_len;
        op_info->_sop_single.ex.flags = flags;
    }
    else
    {
        GlobusIXIOSystemAllocIovec(u_iovc, iov);
        if(!iov)
        {
            result = GlobusXIOErrorMemory("iov");
            goto error_iovec;
        }

        GlobusIXIOSystemAllocMsghdr(msghdr);
        if(!msghdr)
        {
            result = GlobusXIOErrorMemory("msghdr");
            goto error_msghdr;
        }

        GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);

        if(from)
        {
            msghdr->msg_name = from;
            msghdr->msg_namelen = sizeof(globus_sockaddr_t);
        }

        msghdr->msg_iov = iov;
        msghdr->msg_iovlen = u_iovc;

        op_info->type = GLOBUS_L_OPERATION_RECVMSG;
        op_info->_sop_iovecCom.start_iov = iov;
        op_info->_sop_iovecCom.start_iovc = u_iovc;
        op_info->_sop_msg.msghdr = msghdr;
        op_info->_sop_msg.flags = flags;
    }

    op_info->state = GLOBUS_L_OPERATION_NEW;
    op_info->op = op;
    op_info->fd = fd;
    op_info->user_arg = user_arg;
    op_info->sop.data.callback = callback;
    op_info->waitforbytes = waitforbytes;

    result = globus_l_xio_system_register_read(fd, op_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_system_register_read", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_register:
    if(u_iovc != 1)
    {
        GlobusIXIOSystemFreeMsghdr(msghdr);

error_msghdr:
        GlobusIXIOSystemFreeIovec(u_iovc, iov);
    }

error_iovec:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

globus_result_t
globus_xio_system_register_write(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          fd,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_operation_info_t *         op_info;
    struct iovec *                      iov;
    GlobusXIOName(globus_xio_system_register_write);

    GlobusXIOSystemDebugEnterFD(fd);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        (_XIOSL("[%s] Waiting for %u bytes\n"), _xio_name, (unsigned) waitforbytes));
        
    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }

    if(u_iovc == 1)
    {
        op_info->type = GLOBUS_L_OPERATION_WRITE;
        op_info->_sop_single.buf = u_iov->iov_base;
        op_info->_sop_single.bufsize = u_iov->iov_len;
    }
    else
    {
        GlobusIXIOSystemAllocIovec(u_iovc, iov);
        if(!iov)
        {
            result = GlobusXIOErrorMemory("iov");
            goto error_iovec;
        }

        GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);

        op_info->type = GLOBUS_L_OPERATION_WRITEV;
        op_info->_sop_iovecCom.start_iov = iov;
        op_info->_sop_iovec.iov = iov;
        op_info->_sop_iovecCom.start_iovc = u_iovc;
        op_info->_sop_iovec.iovc = u_iovc;
    }

    op_info->state = GLOBUS_L_OPERATION_NEW;
    op_info->op = op;
    op_info->fd = fd;
    op_info->user_arg = user_arg;
    op_info->sop.data.callback = callback;
    op_info->waitforbytes = waitforbytes;

    result = globus_l_xio_system_register_write(fd, op_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            _XIOSL("globus_l_xio_system_register_write"), result);
        goto error_register;
    }

    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_register:
    if(u_iovc != 1)
    {
        GlobusIXIOSystemFreeIovec(u_iovc, iov);
    }

error_iovec:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

globus_result_t
globus_xio_system_register_write_ex(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          fd,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    const globus_sockaddr_t *           u_to,
    globus_xio_system_data_callback_t   callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_operation_info_t *         op_info;
    struct iovec *                      iov;
    struct msghdr *                     msghdr;
    globus_sockaddr_t *                 to;
    GlobusXIOName(globus_xio_system_register_write_ex);

    GlobusXIOSystemDebugEnterFD(fd);
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        (_XIOSL("[%s] Waiting for %u bytes\n"), _xio_name, (unsigned) waitforbytes));
        
    if(!flags && !u_to)
    {
        return globus_xio_system_register_write(
            op, fd, u_iov, u_iovc, waitforbytes, callback, user_arg);
    }

    GlobusIXIOSystemAllocOperation(op_info);
    if(!op_info)
    {
        result = GlobusXIOErrorMemory("op_info");
        goto error_op_info;
    }

    if(u_to)
    {
        to = (globus_sockaddr_t *) globus_malloc(sizeof(globus_sockaddr_t));
        if(!to)
        {
            result = GlobusXIOErrorMemory("to");
            goto error_to;
        }
        GlobusLibcSockaddrCopy(*to, *u_to, sizeof(globus_sockaddr_t));
    }
    else
    {
        to = GLOBUS_NULL;
    }

    if(u_iovc == 1)
    {
        if(to)
        {
            op_info->type = GLOBUS_L_OPERATION_SENDTO;
            op_info->_sop_single.ex.addr = to;
        }
        else
        {
            op_info->type = GLOBUS_L_OPERATION_SEND;
        }

        op_info->_sop_single.buf = u_iov->iov_base;
        op_info->_sop_single.bufsize = u_iov->iov_len;
        op_info->_sop_single.ex.flags = flags;
    }
    else
    {
        GlobusIXIOSystemAllocIovec(u_iovc, iov);
        if(!iov)
        {
            result = GlobusXIOErrorMemory("iov");
            goto error_iovec;
        }

        GlobusIXIOSystemAllocMsghdr(msghdr);
        if(!msghdr)
        {
            result = GlobusXIOErrorMemory("msghdr");
            goto error_msghdr;
        }

        GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);

        if(to)
        {
            msghdr->msg_name = to;
            msghdr->msg_namelen = GlobusLibcSockaddrLen(to);
        }

        msghdr->msg_iov = iov;
        msghdr->msg_iovlen = u_iovc;

        op_info->type = GLOBUS_L_OPERATION_SENDMSG;
        op_info->_sop_iovecCom.start_iov = iov;
        op_info->_sop_iovecCom.start_iovc = u_iovc;
        op_info->_sop_msg.msghdr = msghdr;
        op_info->_sop_msg.flags = flags;
    }

    op_info->state = GLOBUS_L_OPERATION_NEW;
    op_info->op = op;
    op_info->fd = fd;
    op_info->user_arg = user_arg;
    op_info->sop.data.callback = callback;
    op_info->waitforbytes = waitforbytes;

    result = globus_l_xio_system_register_write(fd, op_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_system_register_write", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExitFD(fd);
    return GLOBUS_SUCCESS;

error_register:
    if(u_iovc != 1)
    {
        GlobusIXIOSystemFreeMsghdr(msghdr);

error_msghdr:
        GlobusIXIOSystemFreeIovec(u_iovc, iov);
    }

error_iovec:
    if(to)
    {
        globus_free(to);
    }

error_to:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
    GlobusXIOSystemDebugExitWithErrorFD(fd);
    return result;
}

globus_result_t
globus_xio_system_try_read(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_try_read);

    GlobusXIOSystemDebugEnter();

    if(iovc == 1)
    {
        result = globus_l_xio_system_try_read(
            handle, iov->iov_base, iov->iov_len, nbytes);
    }
    else
    {
        result = globus_l_xio_system_try_readv(handle, iov, iovc, nbytes);
    }

    GlobusXIOSystemDebugExit();
    return result;
}

globus_result_t
globus_xio_system_read(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_read);

    GlobusXIOSystemDebugEnter();

    result = globus_xio_system_read_ex(
        handle, iov, iovc, waitforbytes, 0, GLOBUS_NULL, nbytes);

    GlobusXIOSystemDebugExit();
    return result;
}

globus_result_t
globus_xio_system_try_read_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    int                                 flags,
    globus_sockaddr_t *                 from,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_try_read_ex);

    GlobusXIOSystemDebugEnter();

    if(!flags && !from)
    {
        result = globus_xio_system_try_read(handle, iov, iovc, nbytes);
    }
    else if(iovc == 1)
    {
        if(from)
        {
            result = globus_l_xio_system_try_recvfrom(
                handle, iov->iov_base, iov->iov_len, flags, from, nbytes);
        }
        else
        {
            result = globus_l_xio_system_try_recv(
                handle, iov->iov_base, iov->iov_len, flags, nbytes);
        }
    }
    else
    {
        struct msghdr                   msghdr;

        memset(&msghdr, 0, sizeof(msghdr));
        msghdr.msg_iov = (struct iovec *) iov;
        msghdr.msg_iovlen = iovc;
        if(from)
        {
            msghdr.msg_name = from;
            msghdr.msg_namelen = sizeof(globus_sockaddr_t);
        }

        result = globus_l_xio_system_try_recvmsg(
            handle, &msghdr, flags, nbytes);
    }

    GlobusXIOSystemDebugExit();
    return result;
}

globus_result_t
globus_xio_system_read_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    globus_sockaddr_t *                 from,
    globus_size_t *                     u_nbytes)
{
    globus_result_t                     result;
    int                                 rc;
    GlobusXIOName(globus_xio_system_read_ex);

    GlobusXIOSystemDebugEnter();

    result = globus_xio_system_try_read_ex(
        handle, u_iov, u_iovc, flags, from, u_nbytes);
    
    if(result == GLOBUS_SUCCESS && *u_nbytes < waitforbytes)
    {
        struct iovec *                  iov;
        int                             iovc;
        globus_size_t                   nbytes = *u_nbytes;
        globus_size_t                   total = nbytes;
        
        /**
         * XXX this is not thread safe... both reads and writes are mucking
         * with blocking status.
         * worst case, we read 0 bytes in the loop below, return, and xio
         * calls us again to finish up.
         */
        GlobusIXIOSystemRemoveNonBlocking(handle, rc);
        GlobusIXIOSystemAllocIovec(u_iovc, iov);
        if(!iov)
        {
            result = GlobusXIOErrorMemory("iov");
            goto error_iovec;
        }

        GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);
        u_iov = iov;
        iovc = u_iovc;
        
        do
        {
            if(total > 0)
            {
                /* only capture source first time around */
                from = GLOBUS_NULL;
            }
            
            GlobusIXIOUtilAdjustIovec(iov, iovc, nbytes);
            result = globus_xio_system_try_read_ex(
                handle, iov, iovc, flags, from, &nbytes);
            total += nbytes;
        } while(result == GLOBUS_SUCCESS && nbytes && total < waitforbytes);
        
        *u_nbytes = total;
    
        GlobusIXIOSystemFreeIovec(u_iovc, (globus_xio_iovec_t *) u_iov);
        GlobusIXIOSystemAddNonBlocking(handle, rc);
    }

    GlobusXIOSystemDebugExit();
    return result;

error_iovec:
    GlobusIXIOSystemAddNonBlocking(handle, rc);
    GlobusXIOSystemDebugExitWithError();
    return result;
}

globus_result_t
globus_xio_system_try_write(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_try_write);

    GlobusXIOSystemDebugEnter();

    if(iovc == 1)
    {
        result = globus_l_xio_system_try_write(
            handle, iov->iov_base, iov->iov_len, nbytes);
    }
    else
    {
        result = globus_l_xio_system_try_writev(handle, iov, iovc, nbytes);
    }

    GlobusXIOSystemDebugExit();
    return result;
}

globus_result_t
globus_xio_system_write(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t                       waitforbytes,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_write);

    GlobusXIOSystemDebugEnter();

    result = globus_xio_system_write_ex(
        handle, iov, iovc, waitforbytes, 0, GLOBUS_NULL, nbytes);

    GlobusXIOSystemDebugExit();
    return result;
}

globus_result_t
globus_xio_system_try_write_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    int                                 flags,
    const globus_sockaddr_t *           to,
    globus_size_t *                     nbytes)
{
    globus_result_t                     result;
    GlobusXIOName(globus_xio_system_try_write_ex);

    GlobusXIOSystemDebugEnter();

    if(!flags && !to)
    {
        result = globus_xio_system_try_write(handle, iov, iovc, nbytes);
    }
    else if(iovc == 1)
    {
        if(to)
        {
            result = globus_l_xio_system_try_sendto(
                handle, iov->iov_base, iov->iov_len, flags, to, nbytes);
        }
        else
        {
            result = globus_l_xio_system_try_send(
                handle, iov->iov_base, iov->iov_len, flags, nbytes);
        }
    }
    else
    {
        struct msghdr                   msghdr;

        memset(&msghdr, 0, sizeof(msghdr));
        msghdr.msg_iov = (struct iovec *) iov;
        msghdr.msg_iovlen = iovc;
        if(to)
        {
            msghdr.msg_name = (struct sockaddr *) to;
            msghdr.msg_namelen = GlobusLibcSockaddrLen(to);
        }

        result = globus_l_xio_system_try_sendmsg(
            handle, &msghdr, flags, nbytes);
    }

    GlobusXIOSystemDebugExit();
    return result;
}

globus_result_t
globus_xio_system_write_ex(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          u_iov,
    int                                 u_iovc,
    globus_size_t                       waitforbytes,
    int                                 flags,
    const globus_sockaddr_t *           to,
    globus_size_t *                     u_nbytes)
{
    globus_result_t                     result;
    int                                 rc;
    GlobusXIOName(globus_xio_system_write_ex);

    GlobusXIOSystemDebugEnter();

    result = globus_xio_system_try_write_ex(
        handle, u_iov, u_iovc, flags, to, u_nbytes);
    
    if(result == GLOBUS_SUCCESS && *u_nbytes < waitforbytes)
    {
        struct iovec *                  iov;
        int                             iovc;
        globus_size_t                   nbytes = *u_nbytes;
        globus_size_t                   total = nbytes;
        
        /**
         * XXX this is not thread safe... both reads and writes are mucking
         * with blocking status
         */
        GlobusIXIOSystemRemoveNonBlocking(handle, rc);
        GlobusIXIOSystemAllocIovec(u_iovc, iov);
        if(!iov)
        {
            result = GlobusXIOErrorMemory("iov");
            goto error_iovec;
        }

        GlobusIXIOUtilTransferIovec(iov, u_iov, u_iovc);
        u_iov = iov;
        iovc = u_iovc;
        
        do
        {
            GlobusIXIOUtilAdjustIovec(iov, iovc, nbytes);
            result = globus_xio_system_try_write_ex(
                handle, iov, iovc, flags, to, &nbytes);
            total += nbytes;
        } while(result == GLOBUS_SUCCESS && nbytes && total < waitforbytes);
        
        *u_nbytes = total;
    
        GlobusIXIOSystemFreeIovec(u_iovc, (globus_xio_iovec_t *) u_iov);
        GlobusIXIOSystemAddNonBlocking(handle, rc);
    }

    GlobusXIOSystemDebugExit();
    return result;

error_iovec:
    GlobusIXIOSystemAddNonBlocking(handle, rc);
    GlobusXIOSystemDebugExitWithError();
    return result;
}
