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


#include "globus_thread_rmutex.h"

/**
 * @name Recursive Mutex
 */
/* @{ */

/**
 * @brief Initialize a recursive mutex
 * @ingroup globus_mutex
 *
 * @details
 *     The globus_rmutex_init() function initializes a recursive mutex,
 *     that is, one which may be locked multiple times by a single thread
 *     without causing deadlock.
 * @param rmutex
 *     A pointer to the mutex to initialize
 * @param rattr
 *     IGNORED
 *
 * @return
 *     On success, globus_rmutex_init() initializes the mutex and returns
 *     GLOBUS_SUCCESS; otherwise, it returns a non-zero error code.
 */
int
globus_rmutex_init(
    globus_rmutex_t *                   rmutex,
    globus_rmutexattr_t *               rattr)
{
    int                                 rc;
    
    rc = globus_mutex_init(&rmutex->mutex, GLOBUS_NULL);
    if(rc)
    {
        goto err_init;
        
    }
    rc = globus_cond_init(&rmutex->cond, GLOBUS_NULL);
    if(rc)
    {
        goto err_cond;
        
    }
    
    rmutex->level = 0;
    memset(&rmutex->thread_id,0,sizeof(rmutex->thread_id));
    rmutex->waiting = 0;
    
    return 0;

err_cond:
    globus_mutex_destroy(&rmutex->mutex);
err_init:
    return rc;
}

/**
 * @brief Lock a recursive mutex
 * @ingroup globus_mutex
 *
 * @details
 *     The globus_rmutex_lock() function acquires the lock controlled by
 *     @a rmutex. This may be called multiple times in a single thread without 
 *     causing deadlock, provided that a call to globus_rmutex_unlock() is
 *     called the same number of times as globus_rmutex_lock(). Once acquired,
 *     all other threads calling this function will be blocked until the
 *     mutex is completely unlocked.
 * 
 * @param rmutex
 *     A pointer to the mutex to lock
 *
 * @return
 *     On success, globus_rmutex_init() increases the lock level for the
 *     mutex, blocks other threads trying to acquire the same mutex, and
 *     returns GLOBUS_SUCCESS; otherwise, it returns a non-zero error code.
 */
int
globus_rmutex_lock(
    globus_rmutex_t *                   rmutex)
{
    globus_thread_t                     thread_id;
    
    thread_id = globus_thread_self();
    
    globus_mutex_lock(&rmutex->mutex);
    {
        globus_assert(rmutex->level >= 0);
        
        if(rmutex->level > 0 &&
            !globus_thread_equal(rmutex->thread_id, thread_id))
        {
            rmutex->waiting++;
            do
            {
                globus_cond_wait(&rmutex->cond, &rmutex->mutex);
            } while(rmutex->level > 0);
            rmutex->waiting--;
        }

        rmutex->level++;
        rmutex->thread_id = thread_id;
    }
    globus_mutex_unlock(&rmutex->mutex);
    
    return 0;
}

/**
 * @brief Unlock a recursive mutex
 * @ingroup globus_mutex
 *
 * @details
 *     The globus_rmutex_unlock() function decrements the lock count for
 *     the lock pointed to by @a rmutex. If the lock count is reduced to
 *     zero, it also unblocks a thread which is trying to acquire the lock
 *     if there is one.
 *
 * @param rmutex
 *     Mutex to unlock
 *
 * @return GLOBUS_SUCCESS
 */
int
globus_rmutex_unlock(
    globus_rmutex_t *                   rmutex)
{
    globus_mutex_lock(&rmutex->mutex);
    {
        /* I don't fail here because this is being used with libtool and it
         * unlocks a mutex that was never locked
         */
        if(rmutex->level > 0)
        {
            globus_assert(
                globus_thread_equal(rmutex->thread_id, globus_thread_self()));
    
            rmutex->level--;
            if(rmutex->level == 0)
            {
                memset(&rmutex->thread_id,0,sizeof(rmutex->thread_id));
                if(rmutex->waiting)
                {
                    globus_cond_signal(&rmutex->cond);
                }
            }
        }
    }
    globus_mutex_unlock(&rmutex->mutex);
    
    return 0;
}

/**
 * @brief Destroy a recursive mutex
 * @ingroup globus_mutex
 *
 * @details
 *     The globus_rmutex_destroy() function destroys a recursive mutex
 *     If the mutex is currently locked, behavior is undefined.
 *
 * @param rmutex
 *     Mutex to unlock
 *
 * @return GLOBUS_SUCCESS
 */
int
globus_rmutex_destroy(
    globus_rmutex_t *                   rmutex)
{
    globus_mutex_destroy(&rmutex->mutex);
    globus_cond_destroy(&rmutex->cond);
    
    return 0;
}
/* @} */
