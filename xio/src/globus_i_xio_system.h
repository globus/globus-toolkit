#ifndef GLOBUS_I_XIO_SYSTEM_INCLUDE
#define GLOBUS_I_XIO_SYSTEM_INCLUDE

#include "globus_common.h"

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

#endif
