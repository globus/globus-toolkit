
#ifndef GLOBUS_OBJECT_CACHE_H
#define GLOBUS_OBJECT_CACHE_H

#include "globus_common_include.h"
#include "globus_fifo.h"
#include "globus_list.h"
#include "globus_hashtable.h"

#include "globus_object.h"
 
EXTERN_C_BEGIN

/**********************************************************************
 * Object Cache API Types
 *   globus_object_cache_t          --   container
 **********************************************************************/

typedef struct globus_object_cache_s {
  globus_hashtable_t   handlemap;
  globus_fifo_t        handles;  /* in case we add a cache list function */
  unsigned long        capacity_limit;
  unsigned long        entry_count;
} globus_object_cache_t;


/**********************************************************************
 * Object Cache API
 **********************************************************************/

extern void
globus_object_cache_init (globus_object_cache_t * cache);
/* does nothing if cache is NULL */

extern void
globus_object_cache_destroy (globus_object_cache_t * cache);
/* does nothing if cache is  NULL */

extern void
globus_object_cache_insert (globus_object_cache_t * cache,
			    void *                  new_handle,
			    globus_object_t *       new_object);
/* does nothing if cache is NULL, or new_handle is already mapped in cache,
 * or new_object is NULL */

extern globus_object_t * 
globus_object_cache_lookup (globus_object_cache_t * cache,
			    void *                  handle);
/* returns object stored in cache with handle, or 
 * returns NULL if not mapped or if cache is NULL */

extern globus_object_t *
globus_object_cache_remove (globus_object_cache_t * cache,
			    void *                  handle);
/* returns object removed from cache with handle, or
 * returns NULL if not mapped or if cache is NULL */

extern globus_fifo_t *
globus_object_cache_list (globus_object_cache_t * cache);
/* returns fifo containing existing handles in order inserted, or
 * returns NULL if cache is NULL */


EXTERN_C_END

#endif /* GLOBUS_OBJECT_CACHE_H */




