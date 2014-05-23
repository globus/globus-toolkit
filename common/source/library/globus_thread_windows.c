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

/** @file globus_thread_windows.c Windows Threads Bindings */

#include "globus_i_common_config.h"
#include "globus_thread.h"
#include "globus_common_include.h"
#include <windows.h>
#include "globus_thread_common.h"
#include "globus_i_thread.h"
#include "globus_libc.h"
#include "globus_common.h"
#include "version.h"

enum
{
    GLOBUS_THREAD_ONCE_CALLED=1
};
enum globus_l_winthread_event_e
{
    SINGLE_NOTIFICATION_EVENT = 0,
    BROADCAST_EVENT
};


/* We will wrap the user's function call in an internal
 * function call that matches the prototype specified by Windows:
 *   typedef unsigned int ( __stdcall *globus_thread_func_t)(void *user_arg); 
 *
 * Unfortunately, we cannot pass any return value from the user's
 * function back to the system when the thread ends because of the
 * incompatability between the return types (unsigned int vs.
 * void *)
 */
typedef struct UserFunctionInfo
{
	globus_thread_func_t userFunction;
	void * userArg;
} UserFunctionInfo;

// Global data
globus_list_t * internalThreadList= GLOBUS_NULL;
globus_mutex_t internalMutex;

/******************************************************************************
                              Module definition
******************************************************************************/

static
void *
globus_l_winthread_get_impl(void);

/*
 * Since globus_module depends on threads and globus_thread depends on
 * globus_module, we need this bootstrapping function.
 * 
 */
static
int
globus_l_winthread_pre_activate(void)
{
    return GLOBUS_SUCCESS;
}

/*
 * globus_l_thread_activate()
 */
static
int
globus_l_winthread_activate(void)
{
    int rc;

    rc = globus_mutex_init(&internalMutex, NULL);
    internalThreadList = NULL;
    if ( rc != GLOBUS_SUCCESS )
    {
        return rc;
    }

    return globus_module_activate(GLOBUS_THREAD_COMMON_MODULE);
}
/* globus_l_winthread_activate() */


/*
 * globus_l_thread_deactivate()
 */
static
int
globus_l_winthread_deactivate(void)
{
    globus_mutex_destroy( &internalMutex );
    globus_list_free(internalThreadList);

    return globus_module_deactivate(GLOBUS_THREAD_COMMON_MODULE);
}
/* globus_l_thread_deactivate() */

GlobusExtensionDefineModule(globus_thread_windows) =
{
    "globus_thread_windows",
    globus_l_winthread_activate,
    globus_l_winthread_deactivate,
    NULL,
    globus_l_winthread_get_impl,
    &local_version
};

typedef struct
{
    unsigned long threadID;
    UserFunctionInfo userFunctionInfo;
    globus_list_t * dataDestructionKeyList;
}
globus_i_thread_t;

/* THREAD FUNCTIONS */

int globus_l_thread_key_matches( void * current_key, 
	void * targetKey )
{
	// validate parameters
	if ( current_key == NULL || targetKey == NULL )
		return 0;

	// the current_key is of type globus_thread_key_t
	// the targetKey is of type DWORD
	if ( ((globus_thread_key_t *)current_key)->windows.TLSIndex == 
		(* (DWORD *)targetKey ) )
		return 1;

	return 0;
} /* globus_l_thread_key_matches */

int globus_l_thread_ithread_matches( void * current_ithread, 
	void * targetThreadID )
{
	// validate parameters
	if ( current_ithread == NULL || targetThreadID == NULL )
		return 0;

	// the current_ithread is of type globus_i_thread_t
	// the targetThreadID is of type unsigned long
	if ( ((globus_i_thread_t *)current_ithread)->threadID == 
		(* (unsigned long *)targetThreadID ) )
		return 1;

	return 0;
} /* globus_l_thread_ithread_matches */

unsigned int __stdcall UserFunctionLauncher( void * arg )
{
	globus_i_thread_t * internalThread;
	globus_list_t * subList;
	globus_thread_key_t * key;
	void * datum;

	internalThread= (globus_i_thread_t *)arg;

	// call the user function
	(*internalThread->userFunctionInfo.userFunction)(
	 internalThread->userFunctionInfo.userArg );

	while ( !globus_list_empty( 
	 internalThread->dataDestructionKeyList ) )
	{
		// get the first item in the list
		key= (globus_thread_key_t *)
		 globus_list_first( internalThread->dataDestructionKeyList );

		// get the data associated with the key
		// NOTE: There is no need to validate TLSIndex at this point
		// because it was already validated at the time it was added
		// to the list in globus_thread_setspecific()
		datum= TlsGetValue(key->windows.TLSIndex);

		// set the TLS value to null (not that this will do much good)
		TlsSetValue(key->windows.TLSIndex, NULL);

		// call the destructor function only if the data is non-NULL
		if ( datum )
			(*key->windows.destructorFunction)( datum );

		// remove the item from the list
		globus_list_remove( &internalThread->dataDestructionKeyList,
		 internalThread->dataDestructionKeyList );

		// deallocate it
		free( key );
	}

	// remove the internal thread object from the global list
	globus_mutex_lock( &internalMutex );
	subList= globus_list_search_pred( internalThreadList,
	 globus_l_thread_ithread_matches, &internalThread->threadID );
	globus_list_remove( &internalThreadList, subList ); 
	globus_mutex_unlock( &internalMutex );

	// delete the internal thread object associated with this thread
	free( internalThread );

	return 0;
} /* UserFunctionLauncher */


/*
 * globus_thread_create
 */
static
int
globus_l_winthread_thread_create( 
    globus_thread_t *                   thread,
    globus_threadattr_t *               attr, 
    globus_thread_func_t                func,
    void *                              user_arg)
{
    unsigned long threadHandle;
    unsigned threadID;
    globus_i_thread_t * internalThread;
    int rc = GLOBUS_SUCCESS;

    /* validate the data */
    if ( func == NULL )
    {
        return EINVAL;
    }

    // block all other threads
    if ( (rc = globus_mutex_lock( &internalMutex )) != 0 )
    {
        return rc;
    }

    // create an internal thread object
    internalThread = malloc(sizeof(globus_i_thread_t));
    if ( internalThread == NULL )
    {
        globus_mutex_unlock( &internalMutex );
        return ENOMEM;
    }
    // initialize it
    internalThread->userFunctionInfo.userFunction = func;
    internalThread->userFunctionInfo.userArg = user_arg;
    internalThread->dataDestructionKeyList = NULL;

    /* call _beginthreadex to create the thread */
    threadHandle = _beginthreadex(NULL, 0, UserFunctionLauncher, internalThread, 0, (unsigned *)&threadID );

    if ( threadHandle == 0 )
    {
        free( internalThread );
        if ( thread != NULL )
        {
            thread->windows = 0;
        }

        globus_mutex_unlock( &internalMutex );

        return errno;
    }

    // while we still have a pointer to the internal thread, set the
    // thread ID
    internalThread->threadID= threadID;

    // add the internal thread to the list of internal threads
    globus_list_insert( &internalThreadList, internalThread );

    globus_mutex_unlock( &internalMutex );

    /* we have to close the handle, otherwise a memory leak will occur */
    CloseHandle( (HANDLE)threadHandle );

    // if the user passed in a globus thread object, store the
    // thread ID in it
    if ( thread != NULL )
    {
        thread->windows = threadID;
    }

    return 0;
}
/* globus_l_winthread_thread_create */

/*
 * globus_thread_exit()
 */
/* NOTE: Windows does not support the return of the exit code to the 
 *  calling thread and consequently it will not be able to support
 *  the status parameter unless we supply an enormous hack
 */
static
void
globus_l_winthread_thread_exit(void * status)
{
    _endthreadex( 0 );
}
/* globus_l_winthread_thread_exit() */

static
void
globus_l_winthread_thread_yield(void)
{
    Sleep(0);
}
/* globus_l_winthread_thread_yield() */


static
globus_bool_t
globus_l_winthread_i_am_only_thread(void)
{
    return GLOBUS_FALSE;
}
/* globus_l_winthread_i_am_only_thread() */
 
static
globus_thread_t
globus_l_winthread_thread_self(void)
{
    globus_thread_t                     rc;
    rc.windows = GetCurrentThreadId();
    return rc;
}
/* globus_l_winthread_thread_self() */


static
int
globus_l_winthread_thread_equal(
    globus_thread_t                     t1,
    globus_thread_t                     t2)
{
    return (t1.windows == t2.windows);
}
/* globus_l_winthread_thread_equal() */


static
globus_bool_t
globus_l_winthread_preemptive_threads(void)
{
    return GLOBUS_TRUE;
}
/* globus_l_winthread_preemptive_threads() */
static
int
globus_l_winthread_thread_once(
    globus_thread_once_t *              once_control,
    void                                (*init_routine)(void))
{
    int                                 rc = GLOBUS_SUCCESS;

    /* validate the data */
    if ( once_control == NULL || init_routine == NULL )
    {
        rc = EINVAL;
        goto out;
    }

    /* block all other threads */
    if ((rc = globus_mutex_lock(&internalMutex)) != 0 )
    {
        goto out;
    }

    if (once_control->windows == GLOBUS_THREAD_ONCE_CALLED)
    {
        goto done;
    }

    init_routine();

    once_control->windows = GLOBUS_THREAD_ONCE_CALLED;

done:
    globus_mutex_unlock( &internalMutex );

out:
    return rc;
}
/* globus_l_winthread_thread_once() */


/* THREAD LOCAL STORAGE FUNCTIONS */

static
int
globus_l_winthread_thread_key_create(
    globus_thread_key_t *               key,
    globus_thread_key_destructor_func_t destructor_func)
{
    int rc;
    /* validate the data */
    if ( key == NULL )
    {
        rc = EINVAL;

        goto out;
    }

    key->windows.TLSIndex = TlsAlloc();
    if (key->windows.TLSIndex == TLS_OUT_OF_INDEXES)
    {
        key->windows.destructorFunction = NULL;
        return -1; /* per the documentation on our website */
    }

    // insert the destructor function pointer into the key so
    // it will be available when the user calls 
    // globus_thread_setspecific()
    key->windows.destructorFunction = destructor_func;

    rc = GLOBUS_SUCCESS;
out:
    return rc;
}
/* globus_l_winthread_thread_key_create() */


/* WARNING! This function should never be called unless the key was created by
 * a DLL that is detaching from the process
 */
static
int
globus_l_winthread_thread_key_delete(
    globus_thread_key_t                 key)
{
    int rc;
    globus_list_t *                     threadList;
    globus_i_thread_t *                 internalThread;
    globus_list_t *                     dataDestructionKeyList;
    
    rc = TlsFree(key.windows.TLSIndex);

    // block all other threads
    globus_mutex_lock( &internalMutex );

    // remove all references to this key from the all of the thread
    // objects in their data destruction lists
    // iterate through the list of threads
    for( threadList= internalThreadList; 
         !globus_list_empty( threadList);
         threadList= globus_list_rest( threadList ))
    {
        // for each thread, check whether the key exists in the data
        // destruction key list; if so, remove that entry
        internalThread = globus_list_first( threadList );
        dataDestructionKeyList = globus_list_search_pred(
                internalThread->dataDestructionKeyList,
                globus_l_thread_key_matches, &key.windows.TLSIndex);
        if (dataDestructionKeyList != NULL) // remove the entry
        {
            globus_list_remove(
                    &internalThread->dataDestructionKeyList,
                    dataDestructionKeyList );
        }
    }
    globus_mutex_unlock( &internalMutex );

    // reset the data so that it appears to be invalid
    key.windows.TLSIndex = TLS_OUT_OF_INDEXES;
    key.windows.destructorFunction = NULL;

    if ( rc == 0 ) /* operation failed */
    {
        return GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;
}
/* globus_thread_key_delete() */


static
int
globus_l_winthread_thread_setspecific(
    globus_thread_key_t                 key,
    void *                              value)
{
    int rc;
    globus_thread_key_t * keyCopy;
    unsigned long threadID;
    globus_list_t * subList;
    globus_i_thread_t * internalThread;

    /* validate the data */
    if ( key.windows.TLSIndex == TLS_OUT_OF_INDEXES )
    {
        return EINVAL;
    }

    rc = TlsSetValue(key.windows.TLSIndex, value);
    if ( rc == 0 ) /* operation failed */
    {
        return GetLastError();
    }

    if ( key.windows.destructorFunction == NULL )
    {
        return GLOBUS_SUCCESS;
    }

    // if this key has not yet been stored in the data destruction list
    // for this thread, add it to the list

    // get the current thread ID
    threadID = GetCurrentThreadId();

    // find the thread object associated with the current thread
    // get the internal thread object associated with this thread
    globus_mutex_lock( &internalMutex );
    subList = globus_list_search_pred(
            internalThreadList, globus_l_thread_ithread_matches, &threadID );
    globus_mutex_unlock( &internalMutex );
    if (subList == NULL) // thread not in list- definitely a bad sign
    {
        return GLOBUS_FAILURE;
    }

    internalThread = globus_list_first( subList );

    // check whether this key is already in the data destruction list
    subList= globus_list_search_pred(
            internalThread->dataDestructionKeyList,
            globus_l_thread_key_matches, &key.windows.TLSIndex );
    if( subList != NULL ) // already exists- nothing to do
    {
        return GLOBUS_SUCCESS;
    }

    // create a copy of the key
    keyCopy = malloc( sizeof(globus_thread_key_t) );
    if ( keyCopy == NULL )
    {
        return GLOBUS_FAILURE;
    }

    // store the data in the copy
    keyCopy->windows.TLSIndex = key.windows.TLSIndex;
    keyCopy->windows.destructorFunction = key.windows.destructorFunction;

    // store the key in the internal thread object
    globus_list_insert(&internalThread->dataDestructionKeyList, keyCopy );

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_thread_setspecific() */


static
void *
globus_l_winthread_thread_getspecific(
    globus_thread_key_t                 key)
{
    return TlsGetValue(key.windows.TLSIndex);
}
/* globus_l_winthread_thread_getspecific() */


/* MUTEX FUNCTIONS */
static
int
globus_l_winthread_mutexattr_init(
    globus_mutexattr_t *                attr)
{
    if ( attr == NULL )
    {
        return EINVAL;
    }
	
    attr->windows.securityAttributes = NULL;
    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_mutexattr_init() */

static
int
globus_l_winthread_mutexattr_destroy(
    globus_mutexattr_t *                attr)
{
    if ( attr == NULL )
    {
        return EINVAL;
    }
    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_mutexattr_destroy() */

static
int
globus_l_winthread_mutex_init(
    globus_mutex_t *                    mut,
    globus_mutexattr_t *                attr)
{
    if ( mut == NULL )
    {
        return EINVAL;
    }

    mut->windows = CreateMutex(
            attr ? attr->windows.securityAttributes : NULL,
            FALSE,
            NULL);
    if (mut->windows == NULL)
    {
        return (int) GetLastError();
    }

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_mutex_init() */

static
int
globus_l_winthread_mutex_destroy(
    globus_mutex_t *                    mut)
{
	int rc; 

    if ( mut == NULL )
    {
        return EINVAL;
    }

    rc = CloseHandle( mut->windows );
    if ( rc == 0 )
    {
        return (int) GetLastError();
    }

    return GLOBUS_SUCCESS;
}
/* globus_mutex_destroy() */

static
int
globus_l_winthread_mutex_lock(
    globus_mutex_t *                    mut)
{
    int rc;

    if ( mut == NULL )
    {
        return EINVAL;
    }

    rc = WaitForSingleObject( mut->windows, INFINITE );
    if (rc == WAIT_ABANDONED)
    {
        return GLOBUS_SUCCESS;
    }
    if ( rc == WAIT_FAILED )
    {
        return GetLastError();
    }

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_mutex_lock() */


static
int
globus_l_winthread_mutex_trylock(
    globus_mutex_t *                    mut)
{
    int rc;

    if ( mut == NULL )
    {
        return EINVAL;
    }

    rc = WaitForSingleObject(mut->windows, 0 );
    if ( rc != WAIT_OBJECT_0 )
    {
        return GetLastError();
    }

    return GLOBUS_SUCCESS;
}

static
int
globus_l_winthread_mutex_unlock(
    globus_mutex_t *                    mut)
{
    int rc;

    if ( mut == NULL )
    {
        return EINVAL;
    }

    rc = ReleaseMutex(mut->windows);
    if ( rc == 0 )
    {
        return GetLastError();
    }

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_mutex_unlock() */


/* CONDITION VARIABLE FUNCTIONS */

static
int
globus_l_winthread_condattr_init(
    globus_condattr_t *                 attr)
{
    if ( attr == NULL )
    {
        return EINVAL;
    }
    
    attr->windows.securityAttributes = NULL;

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread__condattr_init() */

static
int
globus_l_winthread_condattr_destroy(
    globus_condattr_t *                 attr)
{
    if ( attr == NULL )
    {
        return EINVAL;
    }
    
    return GLOBUS_SUCCESS;
} /* globus_condattr_destroy() */

static
int
globus_l_winthread_cond_init(
    globus_cond_t *                     cv,
    globus_condattr_t *                 attr)
{
    if ( cv == NULL )
    {
        return EINVAL;
    }

    cv->windows.events[SINGLE_NOTIFICATION_EVENT]= CreateEvent(
            attr ? attr->windows.securityAttributes : NULL, FALSE, FALSE, NULL);
    if (cv->windows.events[SINGLE_NOTIFICATION_EVENT] == NULL)
    {
        return GLOBUS_FAILURE;
    }
    cv->windows.events[BROADCAST_EVENT]= CreateEvent(
            attr ? attr->windows.securityAttributes : NULL, TRUE, FALSE, NULL );
    cv->windows.numberOfWaiters= 0;

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_cond_init() */

static
int
globus_l_winthread_cond_destroy(
    globus_cond_t *                     cv)
{
    int rc; 

    if ( cv == NULL )
    {
        return EINVAL;
    }

    rc = CloseHandle(cv->windows.events[SINGLE_NOTIFICATION_EVENT]);
    if ( rc == 0 )
    {
        return GLOBUS_FAILURE;
    }

    rc= CloseHandle( cv->windows.events[BROADCAST_EVENT] );
    if ( rc == 0 )
    {
        return GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_cond_destroy() */

static
int
globus_l_winthread_cond_timedwait_rel(
    globus_cond_t *                     cv, 
    globus_mutex_t *                    mut,
    long                                milliseconds )
{
    DWORD rc;

    /* validate the data */
    if ( cv == NULL || mut == NULL )
    {
        return EINVAL;
    }

    /* cause a new thread to be created for callbacks */
    globus_thread_blocking_will_block();

    /* increment the waiter count; if the broadcast event is signaled we will
     * use this count to determine when to reset the event
     */
    cv->windows.numberOfWaiters++;

    /* release the mutex */
    /* ordinarily, we would check the return value, but because the user
     * expects that the mutex will be locked when this function returns, we
     * should not bail before attempting to reacquire the mutex
     */
    globus_l_winthread_mutex_unlock(mut);

    /* wait on the events */
    /* don't check for errors before reacquiring the mutex */
    rc= WaitForMultipleObjects( 2, cv->windows.events, FALSE, milliseconds );

    /* reacquire the mutex */
    if (globus_l_winthread_mutex_lock(mut) != 0)
    {
        return GLOBUS_FAILURE;
    }

    /* check whether the wait timed out */
    if ( rc == WAIT_TIMEOUT )
    {
        return WSAETIMEDOUT;
    }

    /* decrement the waiter count */
    /* check to make sure the wait returned successfully before changing the
     * waiter count
     */
    if ( rc == WAIT_OBJECT_0 || rc == WAIT_OBJECT_0 + 1 )
    {
        cv->windows.numberOfWaiters--;
    }

    /* determine whether the event signaled was the broadcast event */
    if ( rc - WAIT_OBJECT_0 == BROADCAST_EVENT ) 
    {
        if ( cv->windows.numberOfWaiters == 0 )
        {
            rc= ResetEvent( cv->windows.events[BROADCAST_EVENT] ); 
        }
    }

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_cond_timedwait_rel() */

static
int
globus_l_winthread_cond_wait(
    globus_cond_t *                     cv,
    globus_mutex_t *                    mut)
{
    return globus_l_winthread_cond_timedwait_rel(cv, mut, INFINITE);
} /* globus_cond_wait() */

/* UNIX uses absolute time stamps for its condition wait functionality, while
 * Windows uses relative time. To accommodate this difference, the absolute
 * time will be converted to relative time and the function mapped to a new
 * function, globus_l_winthread_cond_timedwait_rel()	
 */
static
int
globus_l_winthread_cond_timedwait(
    globus_cond_t *                     cv,
    globus_mutex_t *                    mut,
    globus_abstime_t *                  abstime )
{
    long milliseconds;
    int rc;

    /* validate the data */
    if ( cv == NULL || mut == NULL || abstime == NULL )
    {
        return EINVAL;
    }

    /* if the number of seconds is not "INFINITE" (0xFFFFFFFF)*/
    /* convert the absolute time in seconds and nanoseconds to the number of
     *  milliseconds from now when the specified absolute time will occur
     */
    milliseconds= abstime->tv_sec;
    if ( milliseconds != INFINITE )
    {
        globus_abstime_t now;

        globus_reltime_t relativeTime;
        GlobusTimeAbstimeGetCurrent(now);
        GlobusTimeAbstimeDiff( relativeTime, *abstime, now );
        GlobusTimeReltimeToMilliSec(milliseconds, relativeTime);
    }
    rc = globus_l_winthread_cond_timedwait_rel(cv, mut, milliseconds);
    return rc;
}
/* globus_l_winthread_cond_timedwait() */

static
int
globus_l_winthread_cond_signal(
    globus_cond_t *                     cv)
{
    int rc;

    /* validate the data */
    if ( cv == NULL )
    {
        return EINVAL;
    }

    rc= SetEvent( cv->windows.events[SINGLE_NOTIFICATION_EVENT] );
    if ( rc == 0 )
    {
        return GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_cond_signal () */


static
int
globus_l_winthread_cond_broadcast(
    globus_cond_t *                     cv)
{
    int rc;

    /* validate the data */
    if ( cv == NULL )
    {
        return EINVAL;
    }

    rc = SetEvent(cv->windows.events[BROADCAST_EVENT]);
    if ( rc == 0 )
    {
        return GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;
}
/* globus_l_winthread_cond_broadcast() */


static
globus_thread_impl_t globus_l_winthread_impl =
{
    globus_l_winthread_mutex_init,
    globus_l_winthread_mutex_destroy,
    globus_l_winthread_mutex_lock,
    globus_l_winthread_mutex_unlock,
    globus_l_winthread_mutex_trylock,
    globus_l_winthread_cond_init,
    globus_l_winthread_cond_destroy,
    globus_l_winthread_cond_wait,
    globus_l_winthread_cond_timedwait,
    globus_l_winthread_cond_signal,
    globus_l_winthread_cond_broadcast,
    globus_l_winthread_mutexattr_init,
    globus_l_winthread_mutexattr_destroy,
    globus_l_winthread_condattr_init,
    globus_l_winthread_condattr_destroy,
    NULL /*globus_l_winthread_condattr_setspace*/,
    NULL /*globus_l_winthread_condattr_getspace*/,
    globus_l_winthread_thread_create,
    globus_l_winthread_thread_key_create,
    globus_l_winthread_thread_key_delete,
    globus_l_winthread_thread_once,
    globus_l_winthread_thread_getspecific,
    globus_l_winthread_thread_setspecific,
    globus_l_winthread_thread_yield,
    globus_l_winthread_thread_exit,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    globus_l_winthread_thread_self,
    globus_l_winthread_thread_equal,
    globus_l_winthread_preemptive_threads,
    globus_l_winthread_i_am_only_thread,
    NULL,
    globus_l_winthread_pre_activate
};

static
void *
globus_l_winthread_get_impl(void)
{
    return &globus_l_winthread_impl;
}

