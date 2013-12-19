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

/*
 * @file globus_thread_common.h Common Thread Interface
 */

#ifndef GLOBUS_THREAD_COMMON_H
#define GLOBUS_THREAD_COMMON_H

#include "globus_common_include.h"
#include "globus_module.h"
#include "globus_callback.h"


#ifdef __cplusplus
extern "C" {
#endif

extern globus_module_descriptor_t       globus_i_thread_common_module;

#define GLOBUS_THREAD_COMMON_MODULE     (&globus_i_thread_common_module)

typedef int                                   globus_thread_callback_index_t;

/* function prototypes */
typedef
void
(*globus_thread_blocking_func_t)(
    globus_thread_callback_index_t      ndx,
    globus_callback_space_t             space,
    void *                              user_args);

#define globus_thread_blocking_callback_push(f, u, i)                       \
    globus_thread_blocking_space_callback_push(                             \
        (f), (u), GLOBUS_CALLBACK_GLOBAL_SPACE, (i))
        
int
globus_thread_blocking_space_callback_push(
    globus_thread_blocking_func_t       func,
    void *                              user_args,
    globus_callback_space_t             space,
    globus_thread_callback_index_t *    i);

int
globus_thread_blocking_callback_pop(
    globus_thread_callback_index_t *    i);

int 
globus_thread_blocking_callback_enable(
    globus_thread_callback_index_t *    i);


int 
globus_thread_blocking_callback_disable(
    globus_thread_callback_index_t *    i);

#define globus_thread_blocking_will_block()                             \
    globus_thread_blocking_space_will_block(GLOBUS_CALLBACK_GLOBAL_SPACE)

int 
globus_thread_blocking_space_will_block(
    globus_callback_space_t             blocking_space);

void
globus_thread_blocking_reset();

void thread_print(char * s, ...);


#ifdef __cplusplus
}
#endif

#endif
