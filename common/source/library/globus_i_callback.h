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

#define GlobusICallbackReadyInit(queue)                                     \
    do {                                                                    \
        (queue)->head = GLOBUS_NULL;                                        \
        (queue)->tail = &(queue)->head;                                     \
    } while(0)
    
#define GlobusICallbackReadyEnqueue(queue, callback_info)                   \
    do {                                                                    \
        (callback_info)->next = GLOBUS_NULL;                                \
        *(queue)->tail = callback_info;                                     \
        (queue)->tail = &callback_info->next;                               \
    } while(0)
    
#define GlobusICallbackReadyDequeue(queue, callback_info)                   \
    do {                                                                    \
        (callback_info) = (queue)->head;                                    \
        if((callback_info))                                                 \
        {                                                                   \
            (queue)->head = (callback_info)->next;                          \
            if(!(queue)->head)                                              \
            {                                                               \
                (queue)->tail = &(queue)->head;                             \
            }                                                               \
        }                                                                   \
    } while(0)

#define GlobusICallbackReadyPeak(queue, callback_info)                      \
    do {                                                                    \
        (callback_info) = (queue)->head;                                    \
    } while(0)

#define GlobusICallbackReadyRemove(queue, callback_info)                    \
    do {                                                                    \
        globus_l_callback_info_t **     tmp;                                \
                                                                            \
        tmp = &(queue)->head;                                               \
        while(*tmp && *tmp != (callback_info))                              \
        {                                                                   \
            tmp = &(*tmp)->next;                                            \
        }                                                                   \
                                                                            \
        if(*tmp)                                                            \
        {                                                                   \
            if(!(callback_info)->next)                                      \
            {                                                               \
                (queue)->tail = tmp;                                        \
            }                                                               \
            *tmp = (*tmp)->next;                                            \
        }                                                                   \
    } while(0)
    
#endif
