#include "globus_thread_rw_mutex.h"

#ifndef BUILD_LITE

void
globus_rw_mutex_init(
    globus_rw_mutex_t *                 rw_lock,
    globus_rw_mutexattr_t *             attr)
{
    globus_mutex_init(&rw_lock->mutex, GLOBUS_NULL);
    globus_cond_init(&rw_lock->writeable, GLOBUS_NULL);
    globus_cond_init(&rw_lock->readable, GLOBUS_NULL);
    rw_lock->writing = GLOBUS_FALSE;
    rw_lock->readers = 0;
    rw_lock->write_waiting = 0;
}

void
globus_rw_mutex_readlock(
    globus_rw_mutex_t *                 rw_lock)
{
    globus_mutex_lock(&rw_lock->mutex);
    {
        if(rw_lock->writing || rw_lock->write_waiting > 0)
        {
            do
            {
                globus_cond_wait(&rw_lock->readable, &rw_lock->mutex);
            } while(rw_lock->writing);
        }
        rw_lock->readers++;
    }
    globus_mutex_unlock(&rw_lock->mutex);
}

void
globus_rw_mutex_writelock(
    globus_rw_mutex_t *                 rw_lock)
{
    globus_mutex_lock(&rw_lock->mutex);
    {
        rw_lock->write_waiting++;
        while(rw_lock->readers > 0 || rw_lock->writing)
        {
            globus_cond_wait(&rw_lock->writeable, &rw_lock->mutex);
        }
        rw_lock->write_waiting--;
        rw_lock->writing = GLOBUS_TRUE;
    }
    globus_mutex_unlock(&rw_lock->mutex);
}

void
globus_rw_mutex_readunlock(
    globus_rw_mutex_t *                 rw_lock)
{
    globus_mutex_lock(&rw_lock->mutex);
    {
        rw_lock->readers--;
        if(rw_lock->readers == 0 && rw_lock->write_waiting > 0)
        {
            globus_cond_signal(&rw_lock->writeable);
        }
    }
    globus_mutex_unlock(&rw_lock->mutex);
}

void
globus_rw_mutex_writeunlock(
    globus_rw_mutex_t *                 rw_lock)
{
    globus_mutex_lock(&rw_lock->mutex);
    {
        rw_lock->writing = GLOBUS_FALSE;
        if(rw_lock->write_waiting > 0)
        {
            globus_cond_signal(&rw_lock->readable);
            globus_cond_signal(&rw_lock->writeable);
        }
        else
        {
            globus_cond_broadcast(&rw_lock->readable);
        }
    }
    globus_mutex_unlock(&rw_lock->mutex);
}

void
globus_rw_mutex_destroy(
    globus_rw_mutex_t *                 rw_lock)
{
    globus_mutex_destroy(&rw_lock->mutex);
    globus_cond_destroy(&rw_lock->writeable);
    globus_cond_destroy(&rw_lock->readable);
}

#endif

