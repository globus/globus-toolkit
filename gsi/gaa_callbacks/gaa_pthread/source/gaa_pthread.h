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
