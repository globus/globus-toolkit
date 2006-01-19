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


#include "globus_object_cache.h"
#include "globus_libc.h"

/**********************************************************************
 * Object Creation API
 **********************************************************************/

void 
globus_object_cache_init (globus_object_cache_t * cache)
{
  if ( cache == NULL ) return;

  globus_hashtable_init (&(cache->handlemap),
			 65 /* default size */,
			 globus_hashtable_voidp_hash,
			 globus_hashtable_voidp_keyeq);
  globus_fifo_init (&(cache->handles));

  cache->capacity_limit = 65;
  cache->entry_count = 0;
}


void
globus_object_cache_destroy (globus_object_cache_t * cache)
{
    globus_object_t *                       obj;
    if(cache == NULL) return;

    while(!globus_fifo_empty(&(cache->handles)))
    {
        obj = globus_object_cache_remove(
                cache,
                globus_fifo_peek(&(cache->handles)));

        globus_object_free(obj);
    }
    globus_hashtable_destroy(&(cache->handlemap));
    globus_fifo_destroy (&(cache->handles));
}

void 
globus_object_cache_insert (globus_object_cache_t * cache,
			    void *                  new_handle,
			    globus_object_t *       new_object)
{
  if ( (cache == NULL)
       || (globus_object_cache_lookup (cache, new_handle) != NULL)
       || (new_object == NULL) ) return;

  if ( cache->entry_count > cache->capacity_limit ) {
    globus_object_t * spilled_element;
    spilled_element = globus_object_cache_remove ( 
				  cache,
				  globus_fifo_peek ( &(cache->handles) ) );
    /* FIXME? should we return this rather than destroy internally? */
    globus_object_free ( spilled_element );
  }

  globus_hashtable_insert (&(cache->handlemap),
			   new_handle, 
			   (void *) new_object);
  globus_fifo_enqueue (&(cache->handles), new_handle);

  cache->entry_count += 1;
}


globus_object_t *
globus_object_cache_lookup (globus_object_cache_t * cache,
			    void *                  handle)
{
  if ( cache == NULL ) return NULL;

  return globus_hashtable_lookup (&(cache->handlemap), handle);
}


globus_object_t *
globus_object_cache_remove (globus_object_cache_t * cache,
			    void *                  handle)
{
  globus_object_t * object;

  if ( cache == NULL ) return NULL;

  object = globus_hashtable_remove (&(cache->handlemap), handle);
  globus_fifo_remove (&(cache->handles), handle);
  if ( object != NULL ) cache->entry_count -= 1;

  return object;
}


globus_fifo_t *
globus_object_cache_list (globus_object_cache_t * cache)
{
  if ( cache == NULL ) return NULL;

  return globus_fifo_copy (&(cache->handles));
}



