
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
    *table = GLOBUS_NULL;
    globus_assert(0 && "globus_hashtable_init failed");
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

globus_bool_t
globus_hashtable_empty(
    globus_hashtable_t *                table)
{
    return ((!table || !*table || 
        (*table)->first == GLOBUS_NULL) ? GLOBUS_TRUE : GLOBUS_FALSE);
}

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

/* set iterator to first entry and return datum, NULL if empty */
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

/* set iterator to next entry and return datum, NULL if at end */
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

/* set iterator to last entry and return datum, NULL if empty */
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

/* set iterator to prev entry and return datum, NULL if at beginning */
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

int
globus_hashtable_destroy(
    globus_hashtable_t *                table)
{
    globus_l_hashtable_t *              itable;
    
    if(!table || !*table)
    {
        globus_assert(0 && "globus_hashtable_destroy bad parms");
        goto error_param;
    }
    
    itable = *table;
    
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
 * hashpjw() is derived from an algorithm found in Aho, Sethi and Ullman's
 * {Compilers: Principles, Techniques and Tools}, published by Addison-Wesley. 
 * This algorithm comes from P.J. Weinberger's C compiler. 
 */
int
globus_hashtable_string_hash(
    void *                              string,
    int                                 limit)
{
    unsigned long                       h = 0;
    unsigned long                       g;
    char *                              key;

    key = (char *) string;

    while(*key)
    {
        h = (h << 4) + *key++;
        if((g = (h & 0xF0UL)))
        {
            h ^= g >> 24;
            h ^= g;
        }
    }
    
    return h % limit;
}

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

int
globus_hashtable_voidp_hash(
    void *                              voidp,
    int                                 limit)
{
    unsigned long                       key;
    
    key = (unsigned long) voidp;
    
    /* swap left and right halves portably */
    return (key << ((sizeof(unsigned long) * 4)) ^ 
        (key >> (sizeof(unsigned long) * 4))) % limit;
}

int
globus_hashtable_voidp_keyeq(
    void *                              voidp1,
    void *                              voidp2)
{
    return (voidp1 == voidp2);
}

int
globus_hashtable_int_hash(
    void *                              integer,
    int                                 limit)
{
    return (long) integer % limit;
}

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
