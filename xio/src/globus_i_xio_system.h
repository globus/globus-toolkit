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

#endif
