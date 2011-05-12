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

#include "gaa.h"
#include "gaa_private.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
struct gaaint_mutex_callback {
    gaacore_mutex_create_func create;
    gaacore_mutex_destroy_func destroy;
    gaacore_mutex_lock_func lock;
    gaacore_mutex_unlock_func unlock;
    gaacore_tsdata_create_func tscreate;
    gaacore_tsdata_setspecific_func tsset;
    gaacore_tsdata_getspecific_func tsget;
    void *params;
};

typedef struct gaaint_mutex_callback gaaint_mutex_callback;

static gaaint_mutex_callback *mutex_callback = 0;
#endif

/**
 *
 * @ingroup gaa_core
 *  Sets the mutex callback functions.
 *
 *  @param create
 *     input function to create a mutex.  Should return a mutex on success, 0
 *     on failure.
 *  @param destroy
 *     input function to destroy a mutex created by "create".
 *  @param lock
 *     input function to lock a mutex created by "create".  Should return 0
 *     on success, nonzero on failure.
 *  @param unlock
 *     input function to lock a mutex locked by "lock".  Should return 0
 *     on success, nonzero on failure.
 *  @param tscreate
 *     input function to create a key for thread-specific data.  Should return
 *     0 on success, nonzero on failure.
 *  @param tsset
 *     input function to set the value of thread-specific data.  The key argument
 *     should be the same type as the key set by tscreate (in its tsdata->key
 *     argument).
 *  @param tsget
 *     input function to get the value of thread-specific data.  The argument
 *     should be the same type as the key set by tscreate (in its tsdata->key
 *     argument).
 *  @param params
 *     input parameter passed to create, destroy, lock, unlock, tscreate,
 *     tsset, and tsget whenever they're called.
 *
 *  @note
 *     This function does not bother trying to free the old mutex
 *     callback.  This function will probably only be called once
 *     (in which case there is no old callback to free) or twice
 *     (in which case there is one to free, and we're wasting a few
 *     bytes).
 */
gaa_status
gaacore_set_mutex_callback(gaacore_mutex_create_func	create,
			   gaacore_mutex_destroy_func 	destroy,
			   gaacore_mutex_lock_func 	lock,
			   gaacore_mutex_unlock_func 	unlock,
			   gaacore_tsdata_create_func 	tscreate,
			   gaacore_tsdata_setspecific_func 	tsset,
			   gaacore_tsdata_getspecific_func 	tsget,
			   void *			params)
{
    gaaint_mutex_callback *new_callback;

    if ((new_callback =
	 (gaaint_mutex_callback *)malloc(sizeof(gaaint_mutex_callback))) == 0)
	return(GAA_S_SYSTEM_ERR);
    new_callback->create = create;
    new_callback->destroy = destroy;
    new_callback->lock = lock;
    new_callback->unlock = unlock;
    new_callback->tscreate = tscreate;
    new_callback->tsset = tsset;
    new_callback->tsget = tsget;
    new_callback->params = params;
    mutex_callback = new_callback;
    return(GAA_S_SUCCESS);
}

/**
 *
 * @ingroup gaa_core
 *  Calls the mutex lock callback to lock a mutex.
 *
 *  @param mutex
 *     input/output mutex to lock
 *
 *  @retval GAA_S_SUCCESS
 *     success (or no mutex lock callback was installed)
 *  @retval GAA_S_SYSTEM_ERR
 *     the mutex lock callback returned a nonzero status
 */
gaa_status
gaacore_mutex_lock(void *mutex)
{
    if (! (mutex_callback && mutex_callback->lock))
	return(GAA_S_SUCCESS);
    if (mutex_callback->lock(mutex, mutex_callback->params))
	return(GAA_S_SYSTEM_ERR);
    return(GAA_S_SUCCESS);
}

/**
 *
 * @ingroup gaa_core
 *  Calls the mutex unlock callback to unlock a mutex.
 *
 *  @param mutex
 *     input/output mutex to unlock
 *
 *  @retval GAA_S_SUCCESS
 *     success (or no mutex unlock callback was installed)
 *  @retval GAA_S_SYSTEM_ERR
 *     the mutex unlock callback returned a nonzero status
 */
gaa_status
gaacore_mutex_unlock(void *mutex)
{
    if (! (mutex_callback && mutex_callback->unlock))
	return(GAA_S_SUCCESS);
    if (mutex_callback->unlock(mutex, mutex_callback->params))
	return(GAA_S_SYSTEM_ERR);
    return(GAA_S_SUCCESS);
}

/**
 *
 * @ingroup gaa_core
 *  Calls the mutex create callback to create a mutex.
 *
 *  @param mutex_ptr
 *     input/output pointer to a mutex to create.  This argument should
 *     should be a pointer to an object that has been initialized to 0
 *     and is of the type expected by the mutex lock callback.
 *
 *  @retval GAA_S_SUCCESS
 *     success (or no mutex create callback was installed)
 *  @retval GAA_S_SYSTEM_ERR
 *     the mutex lock callback returned a nonzero status
 */
gaa_status
gaacore_mutex_create(void **mutex_ptr)
{
    if (! (mutex_callback && mutex_callback->create))
	return(GAA_S_SUCCESS);
    if (! mutex_ptr)
	return(GAA_S_INTERNAL_ERR);
    if (mutex_callback->create(mutex_ptr, mutex_callback->params))
	return(GAA_S_SYSTEM_ERR);
    return(GAA_S_SUCCESS);
}

/**
 * @ingroup gaa_core
 *
 *  Calls the mutex destroy callback to destroy a mutex.
 *
 *  @param mutex
 *     input/output mutex to destroy
 *
 */
void
gaacore_mutex_destroy(void *mutex)
{
    if (mutex && mutex_callback && mutex_callback->destroy)
	mutex_callback->destroy(mutex, mutex_callback->params);
}

/**
 * @ingroup gaa_core
 *
 *  Calls the mutex tscreate callback to create a key to be used for subsequent
 *  calls to the tsget and tsset callbacks.
 *
 *  @param tsdata
 *     input/output tsdata to create.  The elements of this structure
 *     should be initialized to 0.
 *  @param freedata
 *     input function to be used (by the underlying thread mechanism)
 *     to free the thread-specific data when the thread exits.
 *
 *  @retval GAA_S_SUCCESS
 *     success (or no tscreate callback was installed)
 *  @retval GAA_S_SYSTEM_ERR
 *     the tscreate callback returned a nonzero status
 */
gaa_status
gaacore_tsdata_create(gaacore_tsdata *tsdata, gaa_freefunc freedata)
{
    if (tsdata == 0)
	return(GAA_S_INTERNAL_ERR);
    if (! (mutex_callback && mutex_callback->tscreate))
	return(GAA_S_SUCCESS);
    if (mutex_callback->tscreate(tsdata, freedata, mutex_callback->params))
	return(GAA_S_SYSTEM_ERR);
    return(GAA_S_SUCCESS);
}

/**
 * @ingroup gaa_core
 *
 *  Calls the mutex tsset callback to set thread-specific data.
 *
 *  @param tsdata
 *     input tsdata, which should have been initialized with a call
 *     to gaacore_tsdata_create().
 *  @param data
 *     input value to set the thread-specific data to.
 *
 *  @retval GAA_S_SUCCESS
 *     success (or no tsset callback was installed)
 *  @retval GAA_S_SYSTEM_ERR
 *     the tsset callback returned a nonzero status
 */
gaa_status
gaacore_tsdata_set(gaacore_tsdata *tsdata, void *data)
{
    if (tsdata == 0)
	return(GAA_S_INTERNAL_ERR);
    if (! (mutex_callback && mutex_callback->tsset))
	return(GAA_S_SUCCESS);
    if (mutex_callback->tsset(tsdata->key, data, mutex_callback->params))
	return(GAA_S_SYSTEM_ERR);
    return(GAA_S_SUCCESS);
}

/**
 * @ingroup gaa_core
 *
 *  Calls the mutex tsget callback to get thread-specific data.
 *
 *  @param tsdata
 *     input tsdata, which should have been initialized with a call
 *     to gaacore_tsdata_create().
 *
 *  @retval <data>
 *     success
 *  @retval 0
 *     either there was an error, or the actual data is 0.
 */
void *
gaacore_tsdata_get(gaacore_tsdata *tsdata)
{
    if (! (tsdata && mutex_callback && mutex_callback->tsget))
	return(0);
    return(mutex_callback->tsget(tsdata->key, mutex_callback->params));
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 *
 *  Check to see whether thread-specific callbacks have been installed.
 *
 *  @retval 1
 *     A tscreate callback has been installed.
 *  @retval 0
 *     No tscreate callback has been installed.
 */
gaa_i_tsdata_supported()
{
    return(mutex_callback && mutex_callback->tscreate);
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
