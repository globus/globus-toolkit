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

/** @file globus_thread_rmutex.h Recursive Mutex */

#ifndef GLOBUS_THREAD_RMUTEX_H
#define GLOBUS_THREAD_RMUTEX_H

#include "globus_common_include.h"
#include "globus_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Recursive Mutex
 * @ingroup globus_mutex
 * 
 * @see globus_rmutex_init(), globus_rmutex_destroy(), globus_rmutex_lock(), globus_rmutex_unlock()
 */
typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_thread_t			thread_id;
    int					level;
    int                                 waiting;
} globus_rmutex_t;

/**
 * @brief Recursive mutex attribute
 * @ingroup globus_mutex
 */
typedef int                             globus_rmutexattr_t;

int
globus_rmutex_init(
    globus_rmutex_t *                   rmutex,
    globus_rmutexattr_t *               attr);

int
globus_rmutex_lock(
    globus_rmutex_t *                   rmutex);

int
globus_rmutex_unlock(
    globus_rmutex_t *                   rmutex);

int
globus_rmutex_destroy(
    globus_rmutex_t *                   rmutex);


#ifdef __cplusplus
}
#endif
#endif /* GLOBUS_THREAD_RMUTEX_H */
