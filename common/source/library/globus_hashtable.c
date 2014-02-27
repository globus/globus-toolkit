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


/********************************************************************
 *
 * This file implements the hashtable_t type, a lightweight chaining hashtable
 *
 ********************************************************************/

#include "globus_hashtable.h"
#include "globus_libc.h"
#include "globus_memory.h"

#define GlobusLInsertNodeBefore(_node, _before)                             \
    do                                                                      \
    {                                                                       \
        (_node)->prev = (_before)->prev;                                    \
        if((_before)->prev)                                                 \
        {                                                                   \
            (_node)->prev->next = (_node);                                  \
        }                                                                   \
                                                                            \
        (_node)->next = (_before);                                          \
        (_before)->prev = (_node);                                          \
    } while(0)

typedef struct globus_l_hashtable_bucket_entry_s
{
    void *                              key;
    void *                              datum;
    struct globus_l_hashtable_bucket_entry_s * prev;
    struct globus_l_hashtable_bucket_entry_s * next;
} globus_l_hashtable_bucket_entry_t;

typedef struct globus_l_hashtable_bucket_s
{
    globus_l_hashtable_bucket_entry_t * first;
    globus_l_hashtable_bucket_entry_t * last;
} globus_l_hashtable_bucket_t;

typedef struct globus_l_hashtable_s
{
    int                                 size;
    int                                 load;
    globus_l_hashtable_bucket_t *       buckets;
    globus_l_hashtable_bucket_entry_t * first;
    globus_l_hashtable_bucket_entry_t * last;
    globus_l_hashtable_bucket_entry_t * current;
    globus_hashtable_hash_func_t        hash_func;
    globus_hashtable_keyeq_func_t       keyeq_func;
    globus_memory_t                     memory;
} globus_l_hashtable_t;

/**
 * @brief Initialize a hash table
 * @ingroup globus_hashtable
 * @details
 * Initializes a generic chaining hashtable to represent an empty mapping and
 * returns zero, or returns non-zero on failure. The size parameter specifies
 * the number of chains with which to represent the mapping. This defines the
 * maximum possible number of mappings that can be represented without conflict
 * given a perfect hash, and therefore affects performance as hash conflicts
 * will be resolved by linear chains.
 *
 * The hash_func and keyeq_func anonymous functions will be used by the table
 * to manipulate the user's keys.
 */
int
globus_hashtable_init(
    globus_hashtable_t *                table,
    int                                 size,
    globus_hashtable_hash_func_t        hash_func,
    globus_hashtable_keyeq_func_t       keyeq_func)
{
    globus_l_hashtable_t *              itable;
    
    if(table == GLOBUS_NULL || 
        hash_func == GLOBUS_NULL || 
        keyeq_func == GLOBUS_NULL || 
        size <= 0)
    {
        goto error_parm;
    }
    
    itable = (globus_l_hashtable_t *)   
        globus_malloc(sizeof(globus_l_hashtable_t));
    if(!itable)
    {
        goto error_malloc_table;
    }
    
    itable->buckets = (globus_l_hashtable_bucket_t *)
        globus_malloc(sizeof(globus_l_hashtable_bucket_t) * size);
    if(!itable->buckets)
    {
        goto error_malloc_buckets;
    }
    
    if(!globus_memory_init(
        &itable->memory, sizeof(globus_l_hashtable_bucket_entry_t), 16))
    {
        goto error_memory_init;
    }
    
    itable->size = size;
    itable->load = 0;
    itable->first = GLOBUS_NULL;
    itable->last = GLOBUS_NULL;
    itable->current = GLOBUS_NULL;
    itable->hash_func = hash_func;
    itable->keyeq_func = keyeq_func;
    
    while(size--)
    {
        itable->buckets[size].first = GLOBUS_NULL;
        itable->buckets[size].last = GLOBUS_NULL;
    }
    
    *table = itable;
    return GLOBUS_SUCCESS;

error_memory_init:
    globus_free(itable->buckets);
    
error_malloc_buckets:
    globus_free(itable);
    
error_malloc_table:
error_parm:
    if(table)
    {
        *table = GLOBUS_NULL;
    }
    globus_assert(0 && "globus_hashtable_init failed");
    return GLOBUS_FAILURE;
}

/* XXX if there is a failure mid copy, cant free user's datum */
int
globus_hashtable_copy(
    globus_hashtable_t *                dest_table,
    globus_hashtable_t *                src_table,
    globus_hashtable_copy_func_t        copy_func)
{
    globus_l_hashtable_t *              src_itable;
    globus_l_hashtable_t *              dest_itable;
    int                                 i;
    int                                 size;
    globus_l_hashtable_bucket_entry_t * list;
    globus_l_hashtable_bucket_entry_t   dummy_entry;
    
    if(dest_table == GLOBUS_NULL || 
        src_table == GLOBUS_NULL || 
        *src_table == GLOBUS_NULL)
    {
        goto error_parm;
    }
    
    src_itable = *src_table;
    
    if(globus_hashtable_init(
        dest_table,
        src_itable->size,
        src_itable->hash_func,
        src_itable->keyeq_func) != GLOBUS_SUCCESS)
    {
        goto error_init;
    }
    
    dest_itable = *dest_table;
    size = src_itable->size;
    dest_itable->load = src_itable->load;
    
    dummy_entry.next = GLOBUS_NULL;
    list = &dummy_entry;
    for(i = 0; i < size; i++)
    {
        if(src_itable->buckets[i].first)
        {
            globus_l_hashtable_bucket_entry_t * src_entry;
            globus_l_hashtable_bucket_entry_t * dest_entry;
            globus_l_hashtable_bucket_entry_t ** bucket_first;
            
            src_entry = src_itable->buckets[i].first;
            bucket_first = &list->next;
            do
            {
                dest_entry = (globus_l_hashtable_bucket_entry_t *)
                    globus_memory_pop_node(&dest_itable->memory);
                if(!dest_entry)
                {
                    goto error_alloc;
                }
                
                if(copy_func)
                {
                    copy_func(
                        &dest_entry->key,
                        &dest_entry->datum,
                        src_entry->key,
                        src_entry->datum);
                }
                else
                {
                    dest_entry->key = src_entry->key;
                    dest_entry->datum = src_entry->datum;
                }
                
                dest_entry->prev = list;
                dest_entry->next = GLOBUS_NULL;
                list->next = dest_entry;
                list = dest_entry;
                
                src_entry = src_entry->next;
            } while(
                src_entry && src_entry->prev != src_itable->buckets[i].last);
            
            dest_itable->buckets[i].first = *bucket_first;
            dest_itable->buckets[i].last = dest_entry;
            dest_itable->last = dest_entry;
        }
    }
    
    if(dummy_entry.next)
    {
        dest_itable->first = dummy_entry.next;
        dummy_entry.next->prev = GLOBUS_NULL;
    }
    
    return GLOBUS_SUCCESS;

error_alloc:
    globus_hashtable_destroy(dest_table);
    
error_init:
    *dest_table = GLOBUS_NULL;
    
error_parm:
    return GLOBUS_FAILURE;
}
    
static
globus_l_hashtable_bucket_entry_t *
globus_l_hashtable_search_bucket(
    globus_l_hashtable_bucket_t *       bucket,
    globus_hashtable_keyeq_func_t       keyeq_func,
    void *                              key)
{
    globus_l_hashtable_bucket_entry_t * i;
    globus_l_hashtable_bucket_entry_t * end;
    
    if(bucket->first)
    {
        i = bucket->first;
        end = bucket->last->next;
        
        do
        {
            if(keyeq_func(i->key, key))
            {
                return i;
            }
            
            i = i->next;
        } while(i != end);
    }
    
    return GLOBUS_NULL;
}

/**
 * @brief Insert a datum into a hash table
 * @ingroup globus_hashtable
 * @details
 * The routine globus_hashtable_insert adds a new mapping to the table,
 * returning zero on success or non-zero on failure. Any previous mapping for
 * the same key (where equality is defined by the keyeq_func provided at table
 * initialization) is lost.
 *
 * It is an error to call this routine on an uninitialized table.
 */
int
globus_hashtable_insert(
    globus_hashtable_t *                table,
    void *                              key,
    void *                              datum)
{
    globus_l_hashtable_t *              itable;
    globus_l_hashtable_bucket_t *       bucket;
    globus_l_hashtable_bucket_entry_t * entry;
    
    if(!table || !*table || !datum)
    {
        globus_assert(0 && "globus_hashtable_insert bad parms");
        goto error_param;
    }
    
    itable = *table;
    bucket = &itable->buckets[itable->hash_func(key, itable->size)];
    
    /* make sure it doesn't already exist */
    if(globus_l_hashtable_search_bucket(bucket, itable->keyeq_func, key))
    {
        goto error_exists;
    }
    
    entry = (globus_l_hashtable_bucket_entry_t *)
        globus_memory_pop_node(&itable->memory);
    if(!entry)
    {
        goto error_alloc;
    }
    
    entry->key = key;
    entry->datum = datum;
    
    if(bucket->first)
    {
        if(bucket->first == itable->first)
        {
            itable->first = entry;
        }
        GlobusLInsertNodeBefore(entry, bucket->first);
    }
    else
    {
        if(itable->first)
        {
            GlobusLInsertNodeBefore(entry, itable->first);
        }
        else
        {
            entry->prev = GLOBUS_NULL;
            entry->next = GLOBUS_NULL;
            itable->last = entry;
        }
        
        itable->first = entry;
        bucket->last = entry;
    }
    
    bucket->first = entry;
    itable->load++;
    
    return GLOBUS_SUCCESS;

error_alloc:
error_exists:
error_param:
    return GLOBUS_FAILURE;
}

/**
 * @brief Update a hash table mapping
 * @ingroup globus_hashtable
 * @details
 * Update an existing key -> datum association with new values for both, key
 * and datum.  The old datum is returned.  If key is non-scalar (eg, string), 
 * it should be part of datum so its resources may be recovered.  If old key
 * does not exist, NULL is returned.
 */
void *
globus_hashtable_update(
    globus_hashtable_t *                table,
    void *                              key,
    void *                              datum)
{
    globus_l_hashtable_t *              itable;
    globus_l_hashtable_bucket_t *       bucket;
    globus_l_hashtable_bucket_entry_t * entry;
    void *                              old_datum;
    
    if(!table || !*table || !datum)
    {
        globus_assert(0 && "globus_hashtable_update bad parms");
        goto error_param;
    }
    
    itable = *table;
    bucket = &itable->buckets[itable->hash_func(key, itable->size)];
    
    entry = globus_l_hashtable_search_bucket(bucket, itable->keyeq_func, key);
    if(!entry)
    {
        goto error_notfound;
    }
    
    old_datum = entry->datum;
    entry->datum = datum;
    entry->key = key;
    
    return old_datum;
    
error_notfound:
error_param:
    return GLOBUS_NULL;
}

/**
 * @brief Look up a datum in a hash table
 * @ingroup globus_hashtable
 * @details
 * The globus_hashtable_lookup routine returns the datum mapped to the given key
 * in the table, or NULL if the key is not mapped.
 *
 * It is an error to call this routine on an uninitialized or empty table.
 */
void *
globus_hashtable_lookup(
    globus_hashtable_t *                table,
    void *                              key)
{
    globus_l_hashtable_t *              itable;
    globus_l_hashtable_bucket_t *       bucket;
    globus_l_hashtable_bucket_entry_t * entry;
    
    if(!table || !*table)
    {
        globus_assert(0 && "globus_hashtable_lookup bad parms");
        goto error_param;
    }
    
    itable = *table;
    bucket = &itable->buckets[itable->hash_func(key, itable->size)];
    
    entry = globus_l_hashtable_search_bucket(bucket, itable->keyeq_func, key);
    if(!entry)
    {
        goto error_notfound;
    }
    
    return entry->datum;
    
error_notfound:
error_param:
    return GLOBUS_NULL;
}

/**
 * @brief Remove a datum from a hash table
 * @ingroup globus_hashtable
 * @details
 * The globus_hashtable_remove() function removes the mapping of key in the
 * table, or does nothing if no such mapping exists.
 *
 * It is an error to call this routine on an uninitialized or empty table.
 */
void *
globus_hashtable_remove(
    globus_hashtable_t *                table,
    void *                              key)
{
    globus_l_hashtable_t *              itable;
    globus_l_hashtable_bucket_t *       bucket;
    globus_l_hashtable_bucket_entry_t * entry;
    void *                              datum;
    
    if(!table || !*table)
    {
        globus_assert(0 && "globus_hashtable_remove bad parms");
        goto error_param;
    }
    
    itable = *table;
    bucket = &itable->buckets[itable->hash_func(key, itable->size)];
    
    entry = globus_l_hashtable_search_bucket(bucket, itable->keyeq_func, key);
    if(!entry)
    {
        goto error_notfound;
    }
    
    if(entry == bucket->first)
    {
        if(entry == bucket->last)
        {
            bucket->first = GLOBUS_NULL;
            bucket->last = GLOBUS_NULL;
            
        }
        else
        {
            bucket->first = entry->next;
        }
    }
    else if(entry == bucket->last)
    {
        bucket->last = entry->prev;
    }
    
    if(entry->prev)
    {
        entry->prev->next = entry->next;
    }
    else
    {
        itable->first = entry->next;
    }
    
    if(entry->next)
    {
        entry->next->prev = entry->prev;
    }
    else
    {
        itable->last = entry->prev;
    }
    
    if(entry == itable->current)
    {
        itable->current = entry->next;
    }
    
    datum = entry->datum;
    globus_memory_push_node(&itable->memory, entry);
    itable->load--;
    
    return datum;

error_notfound:
error_param:
    return GLOBUS_NULL;
}

/**
 * @brief Create a list of all datums in a hash table
 * @ingroup globus_hashtable
 */
int
globus_hashtable_to_list(
    globus_hashtable_t *                table,
    globus_list_t **                    list)
{
    globus_l_hashtable_t *              itable;
    globus_l_hashtable_bucket_entry_t * entry;
    
    if(!table || !*table || !list)
    {
        globus_assert(0 && "globus_hashtable_to_list bad parms");
        goto error_param;
    }
    
    itable = *table;
    entry = itable->first;
    *list = GLOBUS_NULL;
    
    while(entry)
    {
        globus_list_insert(list, entry->datum);
        entry = entry->next;
    }

    return GLOBUS_SUCCESS;
    
error_param:
    return GLOBUS_FAILURE;   
}

/**
 * @brief Test hash table emptiness
 * @ingroup globus_hashtable
 * @details
 * @return GLOBUS_TRUE if hashtable is empty, GLOBUS_FALSE otherwise
 */
globus_bool_t
globus_hashtable_empty(
    globus_hashtable_t *                table)
{
    return ((!table || !*table || 
        (*table)->first == GLOBUS_NULL) ? GLOBUS_TRUE : GLOBUS_FALSE);
}

/**
 * @brief Hash table size
 * @ingroup globus_hashtable
 * @return Number of entries in hashtable
 */
int
globus_hashtable_size(
    globus_hashtable_t *                table)
{
    if(!table || !*table)
    {
        globus_assert(0 && "globus_hashtable_size bad parms");
        return 0;
    }
    
    return (*table)->load;
}

/**
 * @brief Initialize iterator to first hash table entry
 * @ingroup globus_hashtable_iterators
 * @details
 * Set iterator to first entry and return datum, NULL if empty 
 */
void *
globus_hashtable_first(
    globus_hashtable_t *                table)
{
    globus_l_hashtable_t *              itable;
    
    if(!table || !*table)
    {
        globus_assert(0 && "globus_hashtable_first bad parms");
        goto error_param;
    }
    
    itable = *table;
    itable->current = itable->first;
    
    return (itable->current ? itable->current->datum : GLOBUS_NULL);
    
error_param:
    return GLOBUS_NULL;
}

/**
 * @brief Increment hash table iterator
 * @ingroup globus_hashtable_iterators
 * @details
 * Set iterator to next entry and return datum, NULL if at end 
 */
void *
globus_hashtable_next(
    globus_hashtable_t *                table)
{
    globus_l_hashtable_t *              itable;
    
    if(!table || !*table)
    {
        globus_assert(0 && "globus_hashtable_next bad parms");
        goto error_param;
    }
    
    itable = *table;
    if(itable->current)
    {
        itable->current = itable->current->next;
    }
    
    return (itable->current ? itable->current->datum : GLOBUS_NULL);
    
error_param:
    return GLOBUS_NULL;
}

/**
 * @brief Initialize iterator to last hash table entry
 * @ingroup globus_hashtable_iterators
 * @details
 * Set iterator to last entry and return datum, NULL if empty 
 */
void *
globus_hashtable_last(
    globus_hashtable_t *                table)
{
    globus_l_hashtable_t *              itable;
    
    if(!table || !*table)
    {
        globus_assert(0 && "globus_hashtable_last bad parms");
        goto error_param;
    }
    
    itable = *table;
    itable->current = itable->last;
    
    return (itable->current ? itable->current->datum : GLOBUS_NULL);
    
error_param:
    return GLOBUS_NULL;
}

/**
 * @brief Decrement hash table iterator
 * @ingroup globus_hashtable_iterators
 * @details
 * Set iterator to the previous entry and return datum, NULL if at end 
 */
void *
globus_hashtable_prev(
    globus_hashtable_t *                table)
{
    globus_l_hashtable_t *              itable;
    
    if(!table || !*table)
    {
        globus_assert(0 && "globus_hashtable_prev bad parms");
        goto error_param;
    }
    
    itable = *table;
    if(itable->current)
    {
        itable->current = itable->current->prev;
    }
    
    return (itable->current ? itable->current->datum : GLOBUS_NULL);
    
error_param:
    return GLOBUS_NULL;
}

/**
 * @brief Destroy a hash table
 * @ingroup globus_hashtable
 * Destroys a hashtable representation, releasing any resources used to
 * represent the mappings (abandoning any data in the queue). After this call,
 * a hashtable is no longer considered initialized.
 *
 * It is an error to destroy a hashtable that is not initialized.
 * @param table
 *     Hash table to destroy.
 */
int
globus_hashtable_destroy(
    globus_hashtable_t *                table)
{
    globus_l_hashtable_t *              itable;
    globus_l_hashtable_bucket_entry_t * entry;
    
    if(!table || !*table)
    {
        globus_assert(0 && "globus_hashtable_destroy bad parms");
        goto error_param;
    }
    
    itable = *table;
    entry = itable->first;
    
    while(entry)
    {
        globus_l_hashtable_bucket_entry_t * save;
        
        save = entry->next;
        globus_memory_push_node(&itable->memory, entry);
        entry = save;
    }
    
    globus_memory_destroy(&itable->memory);
    globus_free(itable->buckets);
    globus_free(itable);
    *table = GLOBUS_NULL;
    
    return GLOBUS_SUCCESS;
    
error_param:
    return GLOBUS_FAILURE;
}

void
globus_hashtable_destroy_all(
    globus_hashtable_t *                table,
    globus_hashtable_destructor_func_t  element_free)
{
    globus_l_hashtable_t *              itable;
    globus_l_hashtable_bucket_entry_t * entry;
    
    if(!table || !*table || !element_free)
    {
        globus_assert(0 && "globus_hashtable_destroy_all bad parms");
        goto error_param;
    }
    
    itable = *table;
    entry = itable->first;
    
    while(entry)
    {
        element_free(entry->datum);
        entry = entry->next;
    }
    
    globus_hashtable_destroy(table);
    return;
    
error_param:
    return;
}

/**
 * @brief Null-terminated string hash function
 * @ingroup globus_hashtable
 * @details
 * A decent hash function for null-terminated character arrays.
 */
int
globus_hashtable_string_hash(
    void *                              string,
    int                                 limit)
{
    unsigned long                       h = 0;
    char *                              key;

    key = (char *) string;
    
    while(*key)
    {
        h = 131 * h + *key++;
    }
    
    return h % limit;
}

/**
 * @brief Null-terminated string equality predicate
 * @ingroup globus_hashtable
 */
int
globus_hashtable_string_keyeq(
    void *                              string1,
    void *                              string2)
{
    if(string1 == string2 || 
        (string1 && string2 && strcmp(string1, string2) == 0))
    {
        return 1;
    }

    return 0;
}

/**
 * @brief Void pointer hash function
 * @ingroup globus_hashtable
 * @details
 * A decent hash function for void pointers. This routine goes to some effort
 * to distribute the information from the address into the hash index by XORing
 * the upper and lower halves of the pointer into one accumulator and
 * calculating the index as the remainder of dividing the accumulator by the
 * table size.
 */
int
globus_hashtable_voidp_hash(
    void *                              voidp,
    int                                 limit)
{
    unsigned long                       key;
    
    key = (unsigned long) (uintptr_t) voidp;
    
    /* swap left and right halves portably */
    return (key << ((sizeof(unsigned long) * 4)) ^ 
        (key >> (sizeof(unsigned long) * 4))) % limit;
}

/**
 * @brief Void pointer equality predicate
 * @ingroup globus_hashtable
 */
int
globus_hashtable_voidp_keyeq(
    void *                              voidp1,
    void *                              voidp2)
{
    return (voidp1 == voidp2);
}

/**
 * @brief Integer hash function
 * @ingroup globus_hashtable
 * @details
 * A pathetic hash function for integers, calculating the index as the
 * remainder of dividing the integer by the table size.
 *
 * Your pet gerbil could probably design a better hash function for your
 * integer keys, but you might as well use this one if you were going to use
 * modular division anyway.
 */
int
globus_hashtable_int_hash(
    void *                              integer,
    int                                 limit)
{
    return (intptr_t) integer % limit;
}

/**
 * @brief Integer equality predicate
 * @ingroup globus_hashtable
 */
int
globus_hashtable_int_keyeq(
    void *                              integer1,
    void *                              integer2)
{
    return (integer1 == integer2);
}

int
globus_hashtable_ulong_hash(
    void *                              integer,
    int                                 limit)
{
    return (unsigned long) integer % limit;
}

int
globus_hashtable_ulong_keyeq(
    void *                              integer1,
    void *                              integer2)
{
    return (integer1 == integer2);
}
