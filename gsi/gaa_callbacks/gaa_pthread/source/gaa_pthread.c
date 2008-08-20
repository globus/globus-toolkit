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
#include "gaa_core.h"
#include <pthread.h>

gaa_pthread_mutex_create(void **mutex_ptr, void *params)
{
    static pthread_mutex_t		create_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t *			newmutex;

    if (mutex_ptr == 0)
	return(-1);
    if ((newmutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t))) == 0)
	return(-1);
    if (pthread_mutex_init(newmutex, 0))
	return(-1);
    if (pthread_mutex_lock(&create_mutex))
    {
	free(newmutex);
	return(-1);
    }
    if (*(pthread_mutex_t **)mutex_ptr == 0)
	*mutex_ptr = newmutex;
    pthread_mutex_unlock(&create_mutex);
    if (*mutex_ptr != (void *)newmutex)
    {
	pthread_mutex_destroy(newmutex);
	free(newmutex);
    }
    return(0);
}

void
gaa_pthread_mutex_destroy(void *mutex, void *params)
{
    if (mutex == 0)
	return;
    pthread_mutex_destroy(mutex);
    free(mutex);
}

gaa_pthread_mutex_lock(void *mutex, void *params)
{
    if (mutex == 0)
	return(0);
    return(pthread_mutex_lock((pthread_mutex_t *)mutex));
}

gaa_pthread_mutex_unlock(void *mutex, void *params)
{
    if (mutex == 0)
	return(0);
    return(pthread_mutex_unlock((pthread_mutex_t *)mutex));
}

gaa_pthread_tsdata_create(gaacore_tsdata *tsdata,
			  gaa_freefunc    freedata,
			  void *          params)
{       
    static pthread_mutex_t		lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_key_t *			key_ptr = 0;
    int					retval = 0;

    if (tsdata == 0)
	return(-1);		/* bad argument */
    if (tsdata->initted)
	return(0);		/* nothing to do */
    if ((key_ptr = (pthread_key_t *)malloc(sizeof(pthread_key_t))) == 0)
	return(-1);

    if (pthread_mutex_lock(&lock))
    {
	free(key_ptr);
	return(-1);		/* lock failed */
    }
    if (! (tsdata->initted))
    {
	if (pthread_key_create(key_ptr, freedata))
	    retval = -1;
	else
	{
	    tsdata->key = key_ptr;
	    (tsdata->initted)++;
	}
    }
    if (pthread_mutex_unlock(&lock))
	retval = -1;
    return(retval);
}

gaa_pthread_tsdata_setspecific(void *   key,
			       void *   data,
			       void *   params)
{       
    if (key == 0)
	return(-1);
    return(pthread_setspecific(*(pthread_key_t *)key, data));
}

void *
gaa_pthread_tsdata_getspecific(void *   key,
			       void *   params)
{       
    if (key == 0)
	return(0);
    return(pthread_getspecific(*(pthread_key_t *)key));
}
