
#include "globus_common.h"
#include "globus_i_xio.h"
#include "globus_xio_system.h"
#include "globus_xio_driver.h"

GlobusDebugDefine(GLOBUS_XIO_SYSTEM);

#define GlobusXIOSystemDebugPrintf(level, message)                          \
    GlobusDebugPrintf(GLOBUS_XIO_SYSTEM, level, message)

#define GlobusXIOSystemDebugEnter()                                         \
    GlobusXIOSystemDebugPrintf(                                             \
        GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE,                                    \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOSystemDebugExit()                                          \
    GlobusXIOSystemDebugPrintf(                                             \
        GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE,                                    \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIOSystemDebugExitWithError()                                 \
    GlobusXIOSystemDebugPrintf(                                             \
        GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE,                                    \
        ("[%s] Exiting with error\n", _xio_name))

enum globus_l_xio_error_levels
{
    GLOBUS_L_XIO_SYSTEM_DEBUG_TRACE     = 1,
    GLOBUS_L_XIO_SYSTEM_DEBUG_DATA      = 2
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
        int                         _fd;                                    \
        int                         _flags;                                 \
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
        int                         _fd;                                    \
        int                         _flags;                                 \
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
    globus_l_operation_type_t                   type;
    globus_l_operation_state_t                  state;
    globus_xio_operation_t                      op;
    int                                         fd;
    globus_result_t                             result;
    void *                                      user_arg;
    /* used for reads/writes, 0 for others. here to simplify some things */
    globus_size_t                               nbytes;
    globus_size_t                               waitforbytes;

    union
    {
        /* non data ops -- connect, accept */
        struct
        {
            globus_xio_system_callback_t        callback;
            int *                               out_fd;
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
                    void *                      buf;
                    globus_size_t               bufsize;

                    /* extra data used for recv[from] and send[to] */
                    struct
                    {
                        globus_sockaddr_t *     addr;
                        int                     flags;
                    } ex;
                } single;

                /* ops involving iovecs  -- readv, writev, recvmsg, sendmsg */
                struct
                {
                    struct iovec *              start_iov;
                    int                         start_iovc;

                    union
                    {
                        /* for readv and writev */
                        struct
                        {
                            struct iovec *      iov;
                            int                 iovc;
                        } plain;

                        /* for recvmsg and sendmsg */
                        struct
                        {
                            struct msghdr *     msghdr;
                            int                 flags;
                        } ex;
                    } cont;
                } iovec;
            } buf;
        } data;
    } sop;
} globus_l_operation_info_t;

static globus_cond_t                globus_l_xio_system_cond;
static globus_mutex_t               globus_l_xio_system_fdset_mutex;
static globus_mutex_t               globus_l_xio_system_cancel_mutex;
static globus_bool_t                globus_l_xio_system_select_active;
static globus_bool_t                globus_l_xio_system_wakeup_pending;
static globus_bool_t                globus_l_xio_system_shutdown_called;
static int                          globus_l_xio_system_highest_fd;
static int                          globus_l_xio_system_fd_allocsize;
static fd_set *                     globus_l_xio_system_read_fds;
static fd_set *                     globus_l_xio_system_write_fds;
static fd_set *                     globus_l_xio_system_ready_reads;
static fd_set *                     globus_l_xio_system_ready_writes;
static globus_list_t *              globus_l_xio_system_canceled_reads;
static globus_list_t *              globus_l_xio_system_canceled_writes;
static globus_l_operation_info_t ** globus_l_xio_system_read_operations;
static globus_l_operation_info_t ** globus_l_xio_system_write_operations;
static globus_memory_t              globus_l_xio_system_op_info_memory;
static globus_memory_t              globus_l_xio_system_iov_memory;
static globus_memory_t              globus_l_xio_system_msghdr_memory;
static globus_bool_t                globus_l_xio_system_memory_initialized = 0;
static int                          globus_l_xio_system_wakeup_pipe[2];
static globus_callback_handle_t     globus_l_xio_system_poll_handle;

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
int
globus_l_xio_system_activate(void)
{
    int                                 i;
    char *                              block;
    GlobusXIOName(globus_l_xio_system_activate);

    GlobusDebugInit(GLOBUS_XIO_SYSTEM, TRACE DATA);
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

    globus_l_xio_system_highest_fd = -1;

    /*
     * On some machines (SGI Irix at least), the fd_set structure isn't
     * necessarily large enough to hold the maximum number of open file
     * descriptors.  This ensures that it will be.
     */
    globus_l_xio_system_fd_allocsize = sizeof(fd_set);
    if(globus_l_xio_system_fd_allocsize * 8 < GLOBUS_L_OPEN_MAX)
    {
        /* Conservatively round up to 64 bits */
        globus_l_xio_system_fd_allocsize =
            ((GLOBUS_L_OPEN_MAX + 63) & ~63) / 8;
    }

    i = globus_l_xio_system_fd_allocsize;
    block = (char *) globus_calloc(4, i);
    if(!block)
    {
        goto error_fdsets;
    }
    globus_l_xio_system_read_fds         = (fd_set *) block;
    globus_l_xio_system_write_fds        = (fd_set *) (block + i * 1);
    globus_l_xio_system_ready_reads      = (fd_set *) (block + i * 2);
    globus_l_xio_system_ready_writes     = (fd_set *) (block + i * 3);

    globus_l_xio_system_canceled_reads   = GLOBUS_NULL;
    globus_l_xio_system_canceled_writes  = GLOBUS_NULL;

    globus_l_xio_system_read_operations = (globus_l_operation_info_t **)
        globus_calloc(
            GLOBUS_L_OPEN_MAX * 2, sizeof(globus_l_operation_info_t *));
    if(!globus_l_xio_system_read_operations)
    {
        goto error_operations;
    }
    globus_l_xio_system_write_operations =
        globus_l_xio_system_read_operations + GLOBUS_L_OPEN_MAX;

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
    else
    {
        globus_result_t                 result;
        globus_reltime_t                period;

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
    }

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
    GlobusXIOName(globus_l_xio_system_unregister_periodic_cb);

    GlobusXIOSystemDebugEnter();

    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
    {
        globus_l_xio_system_shutdown_called = GLOBUS_FALSE;
        globus_cond_signal(&globus_l_xio_system_cond);
    }
    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);

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
        globus_l_xio_system_shutdown_called = GLOBUS_TRUE;
        globus_callback_unregister(
            globus_l_xio_system_poll_handle,
            globus_l_xio_system_unregister_periodic_cb,
            GLOBUS_NULL,
            GLOBUS_NULL);
        globus_l_xio_system_select_wakeup();

        while(globus_l_xio_system_shutdown_called == GLOBUS_TRUE)
        {
            globus_cond_wait(
                &globus_l_xio_system_cond, &globus_l_xio_system_fdset_mutex);
        }
    }
    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);

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

static
void
globus_l_xio_system_cancel_cb(
    globus_xio_operation_t              op,
    void *                              user_arg)
{
    globus_l_operation_info_t *         op_info;
    GlobusXIOName(globus_l_xio_system_cancel_cb);

    GlobusXIOSystemDebugEnter();

    op_info = (globus_l_operation_info_t *) user_arg;

    globus_mutex_lock(&globus_l_xio_system_cancel_mutex);
    {
        if(op_info->state != GLOBUS_L_OPERATION_COMPLETE)
        {
            globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
            {
                globus_bool_t           pend;

                if(op_info->state == GLOBUS_L_OPERATION_NEW)
                {
                    op_info->state = GLOBUS_L_OPERATION_CANCELED;
                }
                else
                {
                    if(globus_l_xio_system_select_active)
                    {
                        op_info->state = GLOBUS_L_OPERATION_CANCELED;

                        /* pend the cancel for after select wakes up */
                        if(!globus_l_xio_system_wakeup_pending)
                        {
                            globus_l_xio_system_select_wakeup();
                        }

                        pend = GLOBUS_TRUE;
                    }
                    else
                    {
                        globus_result_t     result;

                        op_info->state = GLOBUS_L_OPERATION_COMPLETE;

                        /* unregister and kickout now */
                        op_info->result = GlobusXIOErrorCanceled();

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
                                "[%s:%d] Couldn't register callback",
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
                        op_info->type == GLOBUS_L_OPERATION_RECVMSG)
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
    globus_bool_t                       canceled;
    GlobusXIOName(globus_l_xio_system_register_read);

    GlobusXIOSystemDebugEnter();

    /* I have to do this outside the lock because of lock inversion issues */
    GlobusXIODriverEnableCancel(
        read_info->op, canceled, globus_l_xio_system_cancel_cb, read_info);
    if(canceled)
    {
        result = GlobusXIOErrorCanceled();
        goto error_cancel_enable;
    }

    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
    {
        /* this really shouldnt be possible, but to be thorough ... */
        if(read_info->state == GLOBUS_L_OPERATION_CANCELED)
        {
            result = GlobusXIOErrorCanceled();
            goto error_canceled;
        }

        if(fd >= GLOBUS_L_OPEN_MAX)
        {
            result = GlobusXIOErrorSystemResource("too many fds");
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
            globus_l_xio_system_select_wakeup();
        }

        read_info->state = GLOBUS_L_OPERATION_PENDING;
    }
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_canceled:
error_already_registered:
error_too_many_fds:
    read_info->state = GLOBUS_L_OPERATION_COMPLETE;
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);
    GlobusXIODriverDisableCancel(read_info->op);

error_cancel_enable:
    GlobusXIOSystemDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_xio_system_register_write(
    int                                 fd,
    globus_l_operation_info_t *         write_info)
{
    globus_result_t                     result;
    globus_bool_t                       canceled;
    GlobusXIOName(globus_l_xio_system_register_write);

    GlobusXIOSystemDebugEnter();

    /* I have to do this outside the lock because of lock inversion issues */
    GlobusXIODriverEnableCancel(
        write_info->op, canceled, globus_l_xio_system_cancel_cb, write_info);
    if(canceled)
    {
        result = GlobusXIOErrorCanceled();
        goto error_cancel_enable;
    }

    globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
    {
        /* this really shouldnt be possible, but to be thorough ... */
        if(write_info->state == GLOBUS_L_OPERATION_CANCELED)
        {
            result = GlobusXIOErrorCanceled();
            goto error_canceled;
        }

        if(fd >= GLOBUS_L_OPEN_MAX)
        {
            result = GlobusXIOErrorSystemResource("too many fds");
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
            globus_l_xio_system_select_wakeup();
        }

        write_info->state = GLOBUS_L_OPERATION_PENDING;
    }
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_canceled:
error_already_registered:
error_too_many_fds:
    write_info->state = GLOBUS_L_OPERATION_COMPLETE;
    globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);
    GlobusXIODriverDisableCancel(write_info->op);

error_cancel_enable:
    GlobusXIOSystemDebugExitWithError();
    return result;
}

/* called locked */
static
void
globus_l_xio_system_unregister_read(
    int                                 fd)
{
    GlobusXIOName(globus_l_xio_system_unregister_read);

    GlobusXIOSystemDebugEnter();

    globus_assert(FD_ISSET(fd, globus_l_xio_system_read_fds));
    FD_CLR(fd, globus_l_xio_system_read_fds);
    globus_l_xio_system_read_operations[fd] = GLOBUS_NULL;

    GlobusXIOSystemDebugExit();
}

/* called locked */
static
void
globus_l_xio_system_unregister_write(
    int                                 fd)
{
    GlobusXIOName(globus_l_xio_system_unregister_write);

    GlobusXIOSystemDebugEnter();

    globus_assert(FD_ISSET(fd, globus_l_xio_system_write_fds));
    FD_CLR(fd, globus_l_xio_system_write_fds);
    globus_l_xio_system_write_operations[fd] = GLOBUS_NULL;

    GlobusXIOSystemDebugExit();
}

static
void
globus_l_xio_system_kickout(
    void *                              user_arg)
{
    globus_l_operation_info_t *         op_info;
    GlobusXIOName(globus_l_xio_system_kickout);

    GlobusXIOSystemDebugEnter();

    op_info = (globus_l_operation_info_t *) user_arg;

    GlobusXIODriverDisableCancel(op_info->op);

    switch(op_info->type)
    {
      case GLOBUS_L_OPERATION_CONNECT:
      case GLOBUS_L_OPERATION_ACCEPT:
        op_info->sop.non_data.callback(
            op_info->result,
            op_info->user_arg);
        break;

      default:
        op_info->sop.data.callback(
            op_info->result,
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

          case GLOBUS_L_OPERATION_RECVFROM:
          case GLOBUS_L_OPERATION_SENDTO:
            globus_free(op_info->_sop_single.ex.addr);
            break;

          default:
            break;
        }

        break;
    }

    GlobusIXIOSystemFreeOperation(op_info);

    GlobusXIOSystemDebugExit();
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

    if(rc > 0)
    {
        globus_l_xio_system_wakeup_pending = GLOBUS_TRUE;
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

    globus_l_xio_system_wakeup_pending = GLOBUS_FALSE;

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
    globus_ssize_t                      rc;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_read);

    GlobusXIOSystemDebugEnter();

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
    else if(rc == 0)
    {
        result = GlobusXIOErrorEOF();
        goto error_eof;
    }

    *nbytes = rc;

    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Read %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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

    GlobusXIOSystemDebugEnter();

    do
    {
        rc = readv(fd, iov, iovc);
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
        ("[%s] Read %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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
    globus_ssize_t                      rc;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_recv);

    GlobusXIOSystemDebugEnter();

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

    *nbytes = rc;
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Read %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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
    globus_ssize_t                      rc;
    globus_result_t                     result;
    globus_size_t                       len;
    GlobusXIOName(globus_l_xio_system_try_recvfrom);

    GlobusXIOSystemDebugEnter();

    do
    {
        len = sizeof(globus_sockaddr_t);
        rc = recvfrom(
            fd,
            buf,
            buflen,
            flags,
            (struct sockaddr *) &from,
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

    *nbytes = rc;
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Read %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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

    GlobusXIOSystemDebugEnter();

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
        ("[%s] Read %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
error_eof:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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
    globus_ssize_t                      rc;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_write);

    GlobusXIOSystemDebugEnter();

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

    *nbytes = rc;
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Wrote %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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

    GlobusXIOSystemDebugEnter();

    do
    {
        rc = writev(fd, iov, iovc);
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
        ("[%s] Wrote %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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
    globus_ssize_t                      rc;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_send);

    GlobusXIOSystemDebugEnter();

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

    *nbytes = rc;
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Wrote %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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
    globus_ssize_t                      rc;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_system_try_sendto);

    GlobusXIOSystemDebugEnter();

    do
    {
        rc = sendto(
            fd,
            buf,
            buflen,
            flags,
            (const struct sockaddr *) to,
            sizeof(globus_sockaddr_t));
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

    *nbytes = rc;
    
    GlobusXIOSystemDebugPrintf(
        GLOBUS_L_XIO_SYSTEM_DEBUG_DATA,
        ("[%s] Wrote %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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

    GlobusXIOSystemDebugEnter();

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
        ("[%s] Wrote %d bytes\n", _xio_name, rc));

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_errno:
    *nbytes = 0;
    GlobusXIOSystemDebugExitWithError();
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

    GlobusXIOSystemDebugEnter();

    handled_it = GLOBUS_FALSE;
    read_info = globus_l_xio_system_read_operations[fd];
    result = GLOBUS_SUCCESS;

    GlobusXIOOperationRefreshTimeout(read_info->op);

    if(read_info->state == GLOBUS_L_OPERATION_CANCELED)
    {
        result = GlobusXIOErrorCanceled();
        goto error_canceled;
    }

    switch(read_info->type)
    {
      case GLOBUS_L_OPERATION_ACCEPT:
        {
            globus_sockaddr_t           addr;
            globus_size_t               addrlen;
            int                         new_fd;

            do
            {
                addrlen = sizeof(globus_sockaddr_t);
                new_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
            } while(new_fd < 0 && errno == EINTR);

            if(new_fd < 0)
            {
                result = GlobusXIOErrorSystemError("accept", errno);
            }
            else
            {
                int                     rc;

                GlobusIXIOSystemAddNonBlocking(new_fd, rc);
                if(rc < 0)
                {
                    result = GlobusXIOErrorSystemError("fcntl", errno);
                    GlobusIXIOSystemCloseFd(new_fd);
                }
                else
                {
                    *read_info->sop.non_data.out_fd = new_fd;
                }
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

    /* always true for accept operations */
    if(read_info->nbytes >= read_info->waitforbytes ||
        result != GLOBUS_SUCCESS)
    {
error_canceled:
        handled_it = GLOBUS_TRUE;
        read_info->result = result;
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
                "[%s:%d] Couldn't register callback",
                _xio_name,
                __LINE__);
        }
    }

    GlobusXIOSystemDebugExit();
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

    GlobusXIOSystemDebugEnter();

    handled_it = GLOBUS_FALSE;
    result = GLOBUS_SUCCESS;
    write_info = globus_l_xio_system_write_operations[fd];

    GlobusXIOOperationRefreshTimeout(write_info->op);

    if(write_info->state == GLOBUS_L_OPERATION_CANCELED)
    {
        result = GlobusXIOErrorCanceled();
        goto error_canceled;
    }

    switch(write_info->type)
    {
      case GLOBUS_L_OPERATION_CONNECT:
        {
            int                         err;
            globus_size_t               errlen;

            errlen = sizeof(err);
            if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0)
            {
                err = errno;
            }

            if(err)
            {
                result = GlobusXIOErrorSystemError("getsockopt", err);
                GlobusIXIOSystemCloseFd(fd);
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
        result = globus_l_xio_system_try_recvmsg(
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

    /* always true for connect operations */
    if(write_info->nbytes >= write_info->waitforbytes ||
        result != GLOBUS_SUCCESS)
    {
error_canceled:
        handled_it = GLOBUS_TRUE;
        write_info->result = result;
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
                "[%s:%d] Couldn't register callback",
                _xio_name,
                __LINE__);
        }
    }

    GlobusXIOSystemDebugExit();
    return handled_it;
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
        int                             select_errno;
        int                             fd;

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

        nready = select(
            num,
            globus_l_xio_system_ready_reads,
            globus_l_xio_system_ready_writes,
            GLOBUS_NULL,
            (time_left_is_infinity ? GLOBUS_NULL : &time_left));
        select_errno = errno;

        globus_mutex_lock(&globus_l_xio_system_cancel_mutex);
        {
            globus_mutex_lock(&globus_l_xio_system_fdset_mutex);
            {
                globus_l_xio_system_select_active = GLOBUS_FALSE;
            }
            globus_mutex_unlock(&globus_l_xio_system_fdset_mutex);

            if(nready > 0)
            {
                fd = globus_l_xio_system_wakeup_pipe[0];
                if(FD_ISSET(fd, globus_l_xio_system_ready_reads))
                {
                    globus_l_xio_system_handle_wakeup();
                    FD_CLR(fd, globus_l_xio_system_ready_reads);
                    nready--;
                }
            }
            else if(nready == 0 || select_errno != EINTR)
            {
                time_left_is_zero = GLOBUS_TRUE;
                nready = 0;
            }

            while(!globus_list_empty(globus_l_xio_system_canceled_reads))
            {
                fd = (int) globus_list_remove(
                    &globus_l_xio_system_canceled_reads,
                    globus_l_xio_system_canceled_reads);

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

typedef struct
{
    int                                 fd;
    globus_xio_system_callback_t        callback;
    void *                              user_arg;
} globus_l_xio_system_open_close_info_t;

static
void
globus_l_xio_system_open_close_kickout(
    void *                              user_arg)
{
    globus_l_xio_system_open_close_info_t * info;
    GlobusXIOName(globus_l_xio_system_open_close_kickout);

    GlobusXIOSystemDebugEnter();

    info = (globus_l_xio_system_open_close_info_t *) user_arg;

    info->callback(GLOBUS_SUCCESS, info->user_arg);

    globus_free(info);

    GlobusXIOSystemDebugExit();
}

globus_result_t
globus_xio_system_register_open(
    globus_xio_operation_t              op,
    const char *                        pathname,
    int                                 flags,
    int                                 mode,
    globus_xio_system_handle_t *        out_fd,
    globus_xio_system_callback_t        callback,
    void *                              user_arg)
{
    int                                 fd;
    globus_result_t                     result;
    globus_l_xio_system_open_close_info_t *  open_info;
    GlobusXIOName(globus_xio_system_register_open);

    GlobusXIOSystemDebugEnter();

    do
    {
        fd = open(pathname, flags | O_NONBLOCK, mode);
    } while(fd < 0 && errno == EINTR);

    if(fd < 0)
    {
        result = GlobusXIOErrorSystemError("open", errno);
        goto error_open;
    }

    open_info = (globus_l_xio_system_open_close_info_t *)
        globus_malloc(sizeof(globus_l_xio_system_open_close_info_t));
    if(!open_info)
    {
        result = GlobusXIOErrorMemory("open_info");
        goto error_open_info;
    }

    open_info->callback = callback;
    open_info->user_arg = user_arg;

    result = globus_callback_register_oneshot(
        GLOBUS_NULL,
        GLOBUS_NULL,
        globus_l_xio_system_open_close_kickout,
        open_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        goto error_register;
    }

    *out_fd = fd;

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    globus_free(open_info);

error_open_info:
    GlobusIXIOSystemCloseFd(fd);

error_open:
    GlobusXIOSystemDebugExitWithError();
    return result;
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
    int                                 rc;
    globus_result_t                     result;
    globus_l_operation_info_t *         op_info;
    GlobusXIOName(globus_xio_system_register_connect);

    GlobusXIOSystemDebugEnter();

    GlobusIXIOSystemAddNonBlocking(fd, rc);
    if(rc < 0)
    {
        result = GlobusXIOErrorSystemError("fcntl", errno);
        goto error_nonblocking;
    }

    done = GLOBUS_FALSE;
    while(!done && connect(
        fd, (const struct sockaddr *) addr, sizeof(globus_sockaddr_t)) < 0)
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
            "globus_l_xio_system_register_write", result);
        goto error_register;

    }

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
error_connect:
error_nonblocking:
    GlobusIXIOSystemCloseFd(fd);
    GlobusXIOSystemDebugExitWithError();
    return result;
}

globus_result_t
globus_xio_system_register_accept(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          listener_fd,
    globus_xio_system_handle_t *        out_fd,
    globus_xio_system_callback_t        callback,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_operation_info_t *         op_info;
    GlobusXIOName(globus_xio_system_register_accept);

    GlobusXIOSystemDebugEnter();

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

    result = globus_l_xio_system_register_read(listener_fd, op_info);

    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_system_register_read", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
    GlobusXIOSystemDebugExitWithError();
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

    GlobusXIOSystemDebugEnter();

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

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    if(u_iovc != 1)
    {
        GlobusIXIOSystemFreeIovec(u_iovc, iov);
    }

error_iovec:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
    GlobusXIOSystemDebugExitWithError();
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

    GlobusXIOSystemDebugEnter();

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

    GlobusXIOSystemDebugExit();
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
    GlobusXIOSystemDebugExitWithError();
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

    GlobusXIOSystemDebugEnter();

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
            "globus_l_xio_system_register_write", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    if(u_iovc != 1)
    {
        GlobusIXIOSystemFreeIovec(u_iovc, iov);
    }

error_iovec:
    GlobusIXIOSystemFreeOperation(op_info);

error_op_info:
    GlobusXIOSystemDebugExitWithError();
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

    GlobusXIOSystemDebugEnter();

    if(!flags && !to)
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
            GlobusXIOErrorMemory("to");
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
            msghdr->msg_namelen = sizeof(globus_sockaddr_t);
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

    GlobusXIOSystemDebugExit();
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
    GlobusXIOSystemDebugExitWithError();
    return result;
}

globus_result_t
globus_xio_system_register_close(
    globus_xio_operation_t              op,
    globus_xio_system_handle_t          fd,
    globus_xio_system_callback_t        callback,
    void *                              user_arg)
{
    globus_l_xio_system_open_close_info_t *  close_info;
    globus_result_t                     result;
    int                                 rc;
    GlobusXIOName(globus_xio_system_register_close);

    GlobusXIOSystemDebugEnter();

    do
    {
        rc = close(fd);
    } while(rc < 0 && errno == EINTR);

    if(rc < 0)
    {
        result = GlobusXIOErrorSystemError("close", errno);
        goto error_close;
    }

    close_info = (globus_l_xio_system_open_close_info_t *)
        globus_malloc(sizeof(globus_l_xio_system_open_close_info_t));
    if(!close_info)
    {
        result = GlobusXIOErrorMemory("close_info");
        goto error_close_info;
    }

    close_info->callback = callback;
    close_info->user_arg = user_arg;

    result = globus_callback_register_oneshot(
        GLOBUS_NULL,
        GLOBUS_NULL,
        globus_l_xio_system_open_close_kickout,
        close_info);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_callback_register_oneshot", result);
        goto error_register;
    }

    GlobusXIOSystemDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    globus_free(close_info);

error_close_info:
error_close:
    GlobusXIOSystemDebugExitWithError();
    return result;
}

globus_result_t
globus_xio_system_try_read(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t *                     nbytes)
{
    GlobusXIOName(globus_xio_system_try_read);

    GlobusXIOSystemDebugEnter();

    if(iovc == 1)
    {
        return globus_l_xio_system_try_read(
            handle, iov->iov_base, iov->iov_len, nbytes);
    }
    else
    {
        return globus_l_xio_system_try_readv(handle, iov, iovc, nbytes);
    }

    GlobusXIOSystemDebugExit();
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
    GlobusXIOName(globus_xio_system_try_read_ex);

    GlobusXIOSystemDebugEnter();

    if(!flags && !from)
    {
        return globus_xio_system_try_read(handle, iov, iovc, nbytes);
    }

    if(iovc == 1)
    {
        if(from)
        {
            return globus_l_xio_system_try_recvfrom(
                handle, iov->iov_base, iov->iov_len, flags, from, nbytes);
        }
        else
        {
            return globus_l_xio_system_try_recv(
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

        return globus_l_xio_system_try_recvmsg(handle, &msghdr, flags, nbytes);
    }

    GlobusXIOSystemDebugExit();
}

globus_result_t
globus_xio_system_try_write(
    globus_xio_system_handle_t          handle,
    const globus_xio_iovec_t *          iov,
    int                                 iovc,
    globus_size_t *                     nbytes)
{
    GlobusXIOName(globus_xio_system_try_write);

    GlobusXIOSystemDebugEnter();

    if(iovc == 1)
    {
        return globus_l_xio_system_try_write(
            handle, iov->iov_base, iov->iov_len, nbytes);
    }
    else
    {
        return globus_l_xio_system_try_writev(handle, iov, iovc, nbytes);
    }

    GlobusXIOSystemDebugExit();
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
    GlobusXIOName(globus_xio_system_try_write_ex);

    GlobusXIOSystemDebugEnter();

    if(!flags && !to)
    {
        return globus_xio_system_try_write(handle, iov, iovc, nbytes);
    }

    if(iovc == 1)
    {
        if(to)
        {
            return globus_l_xio_system_try_sendto(
                handle, iov->iov_base, iov->iov_len, flags, to, nbytes);
        }
        else
        {
            return globus_l_xio_system_try_send(
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
            msghdr.msg_namelen = sizeof(globus_sockaddr_t);
        }

        return globus_l_xio_system_try_sendmsg(handle, &msghdr, flags, nbytes);
    }

    GlobusXIOSystemDebugExit();
}
