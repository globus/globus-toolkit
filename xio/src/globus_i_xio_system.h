#ifndef GLOBUS_I_XIO_SYSTEM_INCLUDE
#define GLOBUS_I_XIO_SYSTEM_INCLUDE

#include "globus_common.h"

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_SYSTEM_ERROR(_func, _errno)           \
    globus_error_put(                                                       \
        globus_error_wrap_errno_error(                                      \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            (_errno),                                                       \
            GLOBUS_XIO_SYSTEM_ERROR_SYSTEM_ERROR,                           \
            "[%s] System error",                                            \
            (_func))

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_TOO_MANY_FDS(_func)                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_TOO_MANY_FDS,                           \
            "[%s] Too many open fds",                                       \
            (_func)))

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_ALREADY_REGISTERED(_func)             \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_ALREADY_REGISTERED,                     \
            "[%s] Operation already registered",                            \
            (_func)))

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_OPERATION_CANCELED(_func)             \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_OPERATION_CANCELED,                     \
            "[%s] Operation was canceled",                                  \
            (_func)))

#define GLOBUS_I_XIO_SYSTEM_CONSTRUCT_NOT_REGISTERED(_func)                 \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_NOT_REGISTERED,                         \
            "[%s] Operation not registered",                                \
            (_func)))

#define GLOBUS_L_XIO_SYSTEM_CONSTRUCT_MEMORY_ALLOC(_func, _alloc)           \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_SYSTEM_MODULE,                                       \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_SYSTEM_ERROR_MEMORY_ALLOC,                           \
            "[%s] Could not allocate memory for %s",                        \
            (_func),                                                        \
            (_alloc)))

#define GlobusLXIOAllocOperation(_op_info)                                  \
    do                                                                      \
    {                                                                       \
        globus_l_operation_info_t *     _l_op_info;                         \
                                                                            \
        _l_op_info = (globus_l_operation_info_t *)                          \
            globus_memory_pop_node(&globus_l_op_info_memory);               \
        if(_l_op_info)                                                      \
        {                                                                   \
            memset(_l_op_info, 0, sizeof(globus_l_operation_info_t));       \
        }                                                                   \
        (_op_info) = _l_op_info;                                            \
    } while(0)

#define GlobusLXIOFreeOperation(_op_info)                                   \
    (globus_memory_push_node(&globus_l_op_info_memory, (_op_info)))

#define GlobusLXIOAllocIovec(_count, _iovec)                                \
    do                                                                      \
    {                                                                       \
        if((_count) < 10)                                                   \
        {                                                                   \
            (_iovec) = (struct iovec *)                                     \
                globus_memory_pop_node(&globus_l_iov_memory);               \
        }                                                                   \
        else                                                                \
        {                                                                   \
            (_iovec) = (struct iovec *)                                     \
                globus_malloc(sizeof(struct iovec) * iovc);                 \
        }                                                                   \
    } while(0)

#define GlobusLXIOFreeIovec(_count, _iovec)                                 \
    do                                                                      \
    {                                                                       \
        if((_count) < 10)                                                   \
        {                                                                   \
            globus_memory_push_node(&globus_l_iov_memory, (_iovec));        \
        }                                                                   \
        else                                                                \
        {                                                                   \
            globus_free((_iovec));                                          \
        }                                                                   \
    } while(0)

#define GlobusLXIOAllocMsghdr(_msghdr)                                      \
    do                                                                      \
    {                                                                       \
        struct msghdr *                 _l_msghdr;                          \
                                                                            \
        _l_msghdr = (struct msghdr *)                                       \
            globus_memory_pop_node(&globus_l_msghdr_memory);                \
        if(_l_msghdr)                                                       \
        {                                                                   \
            memset(_l_msghdr, 0, sizeof(struct msghdr));                    \
        }                                                                   \
        (_msghdr) = _l_msghdr;                                              \
    } while(0)

#define GlobusLXIOFreeMsghdr(_msghdr)                                       \
    (globus_memory_push_node(&globus_l_msghdr_memory, (_msghdr)))

#define GlobusLXIOTransferIovec(_iovec, _xiovec, _iovc)                     \
    do                                                                      \
    {                                                                       \
        int                             i;                                  \
                                                                            \
        for(i = 0; i < (_iovc); i++)                                        \
        {                                                                   \
            (_iovec)[i].iov_base = (_xiovec)[i].iov_base;                   \
            (_iovec)[i].iov_len = (_xiovec)[i].iov_len;                     \
        }                                                                   \
    } while(0)

#define GlobusLXIOCloseFd(_fd)                                              \
    do                                                                      \
    {                                                                       \
        int                             _rc;                                \
                                                                            \
        do                                                                  \
        {                                                                   \
            _rc = close((_fd));                                             \
        } while(_rc < 0 && errno == EINTR);                                 \
                                                                            \
        (_fd) = -1;                                                         \
    } while(0)

#define GlobusLXIOAddNonBlocking(_fd, _rc)                                  \
    do                                                                      \
    {                                                                       \
        int                         _l_fd;                                  \
        int                         _l_flags;                               \
                                                                            \
        _l_fd = (_fd);                                                      \
        _l_flags = fcntl(_l_fd, F_GETFL);                                   \
        if(_l_flags < 0)                                                    \
        {                                                                   \
            (_rc) = _l_flags;                                               \
        }                                                                   \
        else                                                                \
        {                                                                   \
             _l_flags |= O_NONBLOCK;                                        \
            (_rc) = fcntl(_l_fd, F_SETFL, _l_flags);                        \
        }                                                                   \
    } while(0)

#define GlobusLXIORemoveNonBlocking(_fd, _rc)                               \
    do                                                                      \
    {                                                                       \
        int                         _l_fd;                                  \
        int                         _l_flags;                               \
                                                                            \
        _l_fd = (_fd);                                                      \
        _l_flags = fcntl(_l_fd, F_GETFL);                                   \
        if(_l_flags < 0)                                                    \
        {                                                                   \
            (_rc) = _l_flags;                                               \
        }                                                                   \
        else                                                                \
        {                                                                   \
             _l_flags &= ~O_NONBLOCK;                                       \
            (_rc) = fcntl(_l_fd, F_SETFL, _l_flags);                        \
        }                                                                   \
    } while(0)

#define GlobusLAdjustIovec(_iov, _iovc, _nbytes)                            \
    do                                                                      \
    {                                                                       \
        globus_ssize_t                  _n;                                 \
        struct iovec *                  _l_iov;                             \
        int                             _l_iovc;                            \
        int                             _i;                                 \
                                                                            \
        _n = (_nbytes);                                                     \
        _l_iov = (_iov);                                                    \
        _l_iovc = (_iovc);                                                  \
                                                                            \
        /* skip all completely filled iovecs */                             \
        for(_i = 0, _n = rc;                                                \
            _i < _l_iovc &&  _n >= _l_iov[_i].iov_len;                      \
            _n -= _l_iov[_i].iov_len, _i++);                                \
                                                                            \
        if(_i < _l_iovc)                                                    \
        {                                                                   \
            _l_iov[_i].iov_base = (char *) _l_iov[_i].iov_base + _n;        \
            _l_iov[_i].iov_len -= _n;                                       \
            (_iov) += _i;                                                   \
            (_iovc) -= _i;                                                  \
        }                                                                   \
    } while(0)

#endif
