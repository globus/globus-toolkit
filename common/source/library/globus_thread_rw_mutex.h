
#ifndef GLOBUS_INCLUDE_GLOBUS_RW_MUTEX
#define GLOBUS_INCLUDE_GLOBUS_RW_MUTEX 1

#ifndef BUILD_LITE

#include "globus_common.h"

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

#else

typedef int globus_rw_mutex_t;
typedef int globus_rw_mutexattr_t;

#define globus_rw_mutex_init(M,A) (*(M) = 0, 0)
#define globus_rw_mutex_readlock(M) (*(M) = 1, 0)
#define globus_rw_mutex_writelock(M) (*(M) = 1, 0)
#define globus_rw_mutex_readunlock(M) (*(M) = 0, 0)
#define globus_rw_mutex_writeunlock(M) (*(M) = 0, 0)
#define globus_rw_mutex_destroy(M) (*(M) = 0, 0)

#endif

#endif

