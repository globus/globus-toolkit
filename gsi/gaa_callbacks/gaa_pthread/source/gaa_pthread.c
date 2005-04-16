/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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
