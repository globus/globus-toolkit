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

#include "gaa_core.h"

extern 
gaa_pthread_mutex_create(void **mutex_ptr, void *params);

extern void
gaa_pthread_mutex_destroy(void *mutex, void *params);

extern int
gaa_pthread_mutex_lock(void *mutex, void *params);

extern int
gaa_pthread_mutex_unlock(void *mutex, void *params);

extern int
gaa_pthread_tsdata_create(gaacore_tsdata *tsdata,
			  gaa_freefunc    freedata,
			  void *          params);

extern int
gaa_pthread_tsdata_setspecific(void *   key,
			       void *   data,
			       void *   params);

extern void *
gaa_pthread_tsdata_getspecific(void *   key,
			       void *   params);
