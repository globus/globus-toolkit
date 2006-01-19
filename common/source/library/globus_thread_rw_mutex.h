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


#ifndef GLOBUS_INCLUDE_GLOBUS_RW_MUTEX
#define GLOBUS_INCLUDE_GLOBUS_RW_MUTEX 1

#include "globus_common_include.h"
#include GLOBUS_THREAD_INCLUDE

#ifndef BUILD_LITE

EXTERN_C_BEGIN

typedef struct
{
    globus_mutex_t                      mutex;
    struct globus_i_rw_mutex_waiter_s * waiters;
    struct globus_i_rw_mutex_waiter_s ** tail;
    struct globus_i_rw_mutex_waiter_s * idle;
    globus_bool_t                       writing;
    int                                 readers;
} globus_rw_mutex_t;

typedef int globus_rw_mutexattr_t;

int
globus_rw_mutex_init(
    globus_rw_mutex_t *                 rw_lock,
    globus_rw_mutexattr_t *             attr);

int
globus_rw_mutex_readlock(
    globus_rw_mutex_t *                 rw_lock);

int
globus_rw_mutex_writelock(
    globus_rw_mutex_t *                 rw_lock);

int
globus_rw_mutex_readunlock(
    globus_rw_mutex_t *                 rw_lock);

int
globus_rw_mutex_writeunlock(
    globus_rw_mutex_t *                 rw_lock);

int
globus_rw_mutex_destroy(
    globus_rw_mutex_t *                 rw_lock);

/**
 * In order to use the following cond_wait calls safeley, either the call to
 * one of the wait calls or the call to cond_signal/broadcast or both MUST be
 * called from within a WRITElock.
 *
 * It turns out that you normally only signal/broadcast after making some
 * modification anyway,  so the simple rule to remember is:
 *
 * Always call globus_cond_signal/broadcast from within a WRITElock.
 */
int
globus_rw_cond_wait(
    globus_cond_t *                     cond,
    globus_rw_mutex_t *                 rw_lock);

int
globus_rw_cond_timedwait(
    globus_cond_t *                     cond,
    globus_rw_mutex_t *                 rw_lock,
    globus_abstime_t *                  abstime);

EXTERN_C_END

#else

typedef int globus_rw_mutex_t;
typedef int globus_rw_mutexattr_t;

#define globus_rw_mutex_init(M,A) (*(M) = 0, 0)
#define globus_rw_mutex_readlock(M) (*(M) = 1, 0)
#define globus_rw_mutex_writelock(M) (*(M) = 1, 0)
#define globus_rw_mutex_readunlock(M) (*(M) = 0, 0)
#define globus_rw_mutex_writeunlock(M) (*(M) = 0, 0)
#define globus_rw_mutex_destroy(M) (*(M) = 0, 0)

#define globus_rw_cond_wait(C,M) globus_cond_wait((C),(M))
#define globus_rw_cond_timedwait(C,M,A) globus_cond_timedwait((C),(M),(A))

#endif

#endif

