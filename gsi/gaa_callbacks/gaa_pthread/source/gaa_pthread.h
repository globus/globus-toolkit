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
