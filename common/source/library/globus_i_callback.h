#ifndef GLOBUS_INCLUDE_GLOBUS_I_CALLBACK
#define GLOBUS_INCLUDE_GLOBUS_I_CALLBACK

#include "globus_error.h"
#include "globus_error_generic.h"

/* common error objects */

#define GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_CALLBACK_HANDLE(func)           \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_INVALID_CALLBACK_HANDLE,                  \
            "[%s] Invalid callback handle",                                 \
            (func)))

#define GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_SPACE(func)                     \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_INVALID_SPACE,                            \
            "[%s] Invalid space handle",                                    \
            (func)))

#define GLOBUS_L_CALLBACK_CONSTRUCT_MEMORY_ALLOC(func, alloc)               \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_MEMORY_ALLOC,                             \
            "[%s] Could not allocate memory for %s",                        \
            (func),                                                         \
            (alloc)))

#define GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(func, argument)        \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_INVALID_ARGUMENT,                         \
            "[%s] Invalid argument: %s",                                    \
            (func),                                                         \
            (argument)))

#define GLOBUS_L_CALLBACK_CONSTRUCT_ALREADY_CANCELED(func)                  \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_ALREADY_CANCELED,                         \
            "[%s] Callback previoulsy unregistered",                        \
            (func)))

#define GLOBUS_L_CALLBACK_CONSTRUCT_NO_ACTIVE_CALLBACK(func)                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_NO_ACTIVE_CALLBACK,                       \
            "[%s] No cuurently running callback",                           \
            (func)))

#endif
