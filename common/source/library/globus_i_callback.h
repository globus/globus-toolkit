/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
            __FILE__,                                                       \
            (func),                                                         \
            __LINE__,                                                       \
            "Invalid callback handle"))

#define GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_SPACE(func)                     \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_INVALID_SPACE,                            \
            __FILE__,                                                       \
            (func),                                                         \
            __LINE__,                                                       \
            "Invalid space handle"))

#define GLOBUS_L_CALLBACK_CONSTRUCT_MEMORY_ALLOC(func, alloc)               \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_MEMORY_ALLOC,                             \
            __FILE__,                                                       \
            (func),                                                         \
            __LINE__,                                                       \
            "Could not allocate memory for %s",                             \
            (alloc)))

#define GLOBUS_L_CALLBACK_CONSTRUCT_INVALID_ARGUMENT(func, argument)        \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_INVALID_ARGUMENT,                         \
            __FILE__,                                                       \
            (func),                                                         \
            __LINE__,                                                       \
            "Invalid argument: %s",                                         \
            (argument)))

#define GLOBUS_L_CALLBACK_CONSTRUCT_ALREADY_CANCELED(func)                  \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_ALREADY_CANCELED,                         \
            __FILE__,                                                       \
            (func),                                                         \
            __LINE__,                                                       \
            "Callback previoulsy unregistered"))

#define GLOBUS_L_CALLBACK_CONSTRUCT_NO_ACTIVE_CALLBACK(func)                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_CALLBACK_MODULE,                                         \
            GLOBUS_NULL,                                                    \
            GLOBUS_CALLBACK_ERROR_NO_ACTIVE_CALLBACK,                       \
            __FILE__,                                                       \
            (func),                                                         \
            __LINE__,                                                       \
            "No cuurently running callback"))

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

#define GlobusICallbackReadyEnqueueFirst(queue, callback_info)              \
    do {                                                                    \
        (callback_info)->next = (queue)->head;                              \
        if(!(queue)->head)                                                  \
        {                                                                   \
            (queue)->tail = &callback_info->next;                           \
        }                                                                   \
        (queue)->head = (callback_info);                                    \
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
