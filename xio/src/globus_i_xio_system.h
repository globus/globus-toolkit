#ifndef GLOBUS_I_XIO_SYSTEM_INCLUDE
#define GLOBUS_I_XIO_SYSTEM_INCLUDE

#include "globus_common.h"

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_SYSTEM_ERROR(func, errno)             \
    globus_error_put(                                                       \
        globus_error_wrap_errno_error(                                      \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            (errno),                                                        \
            GLOBUS_XIO_SYSTEM_ERROR_SYSTEM_ERROR,                           \
            "[%s] System error",                                            \
            (func))

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_TOO_MANY_FDS(func)                    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_TOO_MANY_FDS,                           \
            "[%s] Too many open fds",                                       \
            (func)))

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_ALREADY_REGISTERED(func)              \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_ALREADY_REGISTERED,                     \
            "[%s] Operation already registered",                            \
            (func)))

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_OPERATION_CANCELED(func)              \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_OPERATION_CANCELED,                     \
            "[%s] Operation was canceled",                                  \
            (func)))

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_NOT_REGISTERED(func)                  \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_NOT_REGISTERED,                         \
            "[%s] Operation not registered",                                \
            (func)))

#define GLOBUS_L_XIO_SYSTEM_CONSTRUCT_MEMORY_ALLOC(func, alloc)             \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_MEMORY_ALLOC,                           \
            "[%s] Could not allocate memory for %s",                        \
            (func),                                                         \
            (alloc)))

#define GlobusIXIOSystemAllocOperation(op_info)                             \
    do                                                                      \
    {                                                                       \
        globus_l_operation_info_t *     _op_info;                           \
                                                                            \
        _op_info = (globus_l_operation_info_t *)                            \
            globus_memory_pop_node(&globus_l_op_info_memory);               \
        if(_op_info)                                                        \
        {                                                                   \
            memset(_op_info, 0, sizeof(globus_l_operation_info_t));         \
        }                                                                   \
        (op_info) = _op_info;                                               \
    } while(0)

#define GlobusIXIOSystemFreeOperation(op_info)                              \
    (globus_memory_push_node(&globus_l_op_info_memory, (op_info)))

#define GlobusIXIOSystemAllocIovec(count, iovec)                            \
    do                                                                      \
    {                                                                       \
        int                             _count;                             \
                                                                            \
        _count = (count);                                                   \
                                                                            \
        if(_count < 10)                                                     \
        {                                                                   \
            (iovec) = (struct iovec *)                                      \
                globus_memory_pop_node(&globus_l_iov_memory);               \
        }                                                                   \
        else                                                                \
        {                                                                   \
            (iovec) = (struct iovec *)                                      \
                globus_malloc(sizeof(struct iovec) * _count);               \
        }                                                                   \
    } while(0)

#define GlobusIXIOSystemFreeIovec(count, iovec)                             \
    do                                                                      \
    {                                                                       \
        if((count) < 10)                                                    \
        {                                                                   \
            globus_memory_push_node(&globus_l_iov_memory, (iovec));         \
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
            globus_memory_pop_node(&globus_l_msghdr_memory);                \
        if(_msghdr)                                                         \
        {                                                                   \
            memset(_msghdr, 0, sizeof(struct msghdr));                      \
        }                                                                   \
        (msghdr) = _msghdr;                                                 \
    } while(0)

#define GlobusIXIOSystemFreeMsghdr(msghdr)                                  \
    (globus_memory_push_node(&globus_l_msghdr_memory, (msghdr)))

#define GlobusIXIOSystemTransferIovec(iovec, xiovec, iovc)                  \
    do                                                                      \
    {                                                                       \
        int                             _i;                                 \
        globus_xio_iovec_t *            _xiovec;                            \
        struct iovec *                  _iov;                               \
        int                             _iovc;                              \
                                                                            \
        _xiovec = (xiovec);                                                 \
        _iovec = (iovec);                                                   \
        _iovc = (iovc);                                                     \
                                                                            \
        for(_i = 0; _i < _iovc; _i++)                                       \
        {                                                                   \
            _iovec[_i].iov_base = _xiovec[_i].iov_base;                     \
            _iovec[_i].iov_len = _xiovec[_i].iov_len;                       \
        }                                                                   \
    } while(0)

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
                                                                            \
        (fd) = -1;                                                          \
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

#define GlobusIXIOSystemAdjustIovec(iov, iovc, nbytes)                      \
    do                                                                      \
    {                                                                       \
        globus_ssize_t                  _n;                                 \
        struct iovec *                  _iov;                               \
        int                             _iovc;                              \
        int                             _i;                                 \
                                                                            \
        _iov = (iov);                                                       \
        _iovc = (iovc);                                                     \
                                                                            \
        /* skip all completely filled iovecs */                             \
        for(_i = 0, _n = (nbytes);                                          \
            _i < _iovc &&  _n >= _iov[_i].iov_len;                          \
            _n -= _iov[_i].iov_len, _i++);                                  \
                                                                            \
        if(_i < _iovc)                                                      \
        {                                                                   \
            _iov[_i].iov_base = (char *) _iov[_i].iov_base + _n;            \
            _iov[_i].iov_len -= _n;                                         \
            (iov) += _i;                                                    \
            (iovc) -= _i;                                                   \
        }                                                                   \
    } while(0)

#define GlobusIXIOSystemTransferAdjustedIovec(                              \
    new_iov, new_iovc, iov, iovc, nbytes)                                   \
    do                                                                      \
    {                                                                       \
        globus_ssize_t                  _n;                                 \
        struct iovec *                  _iov;                               \
        int                             _iovc;                              \
        struct iovec *                  _new_iov;                           \
        int                             _i;                                 \
        int                             _j;                                 \
        int                             _k;                                 \
                                                                            \
        _iov = (iov);                                                       \
        _iovc = (iovc);                                                     \
        _new_iov = (new_iov);                                               \
                                                                            \
        /* skip all completely filled iovecs */                             \
        for(_i = 0, _n = (nbytes);                                          \
            _i < _iovc &&  _n >= _iov[_i].iov_len;                          \
            _n -= _iov[_i].iov_len, _i++);                                  \
                                                                            \
        /* copy remaining */                                                \
        for(_k = 0, _j = _i; _j < _iovc; _k++, _j++)                        \
        {                                                                   \
            _new_iov[_k].iov_base = _iov[_j].iov_base;                      \
            _new_iov[_k].iov_len = _iov[_j].iov_len;                        \
        }                                                                   \
                                                                            \
        _new_iov[0].iov_base = (char *) _iov[_i].iov_base + _n;             \
        _new_iov[0].iov_len -= _n;                                          \
        (new_iovc) = _iovc - _i;                                            \
    } while(0)

#endif
