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


#ifndef GLOBUS_COMMON_HASHTABLE_H
#define GLOBUS_COMMON_HASHTABLE_H

/********************************************************************
 *
 * This file defines the globus_hashtable_t type,
 * a lightweight chaining hashtable
 *
 *
 ********************************************************************/
#include "globus_common_include.h"
#include "globus_list.h"

EXTERN_C_BEGIN

/**
 * Hash function.  User result must be modulo limit
 */
typedef int
(*globus_hashtable_hash_func_t)(
    void *                              key,
    int                                 limit);

/**
 * Comparator function. 0 if not equal, non-zero if equal
 */
typedef int
(*globus_hashtable_keyeq_func_t)(
    void *                              key1,
    void *                              key2);

/**
 * datum copy func
 */
typedef void
(*globus_hashtable_copy_func_t)(
    void **                             dest_key,
    void **                             dest_datum,
    void *                              src_key,
    void *                              src_datum);


/**
 * Destructor callback for use with globus_hashtable_destroy_all
 */
typedef void
(*globus_hashtable_destructor_func_t)(
    void *                              datum);

typedef struct globus_l_hashtable_s *     globus_hashtable_t;

/**
 * Initialize hashtable with a bucket count of size, using hash_func for
 * hashing and keyeq_func for comparison
 */
int
globus_hashtable_init(
    globus_hashtable_t *                table,
    int                                 size,
    globus_hashtable_hash_func_t        hash_func,
    globus_hashtable_keyeq_func_t       keyeq_func);

/**
 * Initialize dest_table and copy src_table into it. copy_func is called for
 * each datum in src_table. if copy_func is null, dest will contain same
 * values as src.  does not duplicate ordering of entries in src_table.
 */
int
globus_hashtable_copy(
    globus_hashtable_t *                dest_table,
    globus_hashtable_t *                src_table,
    globus_hashtable_copy_func_t        copy_func);
    
/**
 * Lookup datum associated with key.  NULL if not found
 */
void *
globus_hashtable_lookup(
    globus_hashtable_t *                table,
    void *                              key);

/**
 * Insert new key->datum association.  key must not already exist and datum
 * must be non-null.  If key is non-scalar (ie, string), it should be part of
 * datum so its resources may be recovered.
 */
int
globus_hashtable_insert(
    globus_hashtable_t *                table,
    void *                              key,
    void *                              datum);

/**
 * Update an existing key->datum association with new values for both, key and
 * datum.  The old datum is returned.  If key is non-scalar (ie, string), 
 * it should be part of datum so its resources may be recovered.  If old key
 * does not exist, NULL is returned.
 */
void *
globus_hashtable_update(
    globus_hashtable_t *                table,
    void *                              key,
    void *                              datum);

/**
 * Remove entry associated with key.  Old datum is returned.  NULL if not found
 */
void *
globus_hashtable_remove(
    globus_hashtable_t *                table,
    void *                              key);

/**
 * Create a list of all datums in hashtable
 */
int
globus_hashtable_to_list(
    globus_hashtable_t *                table,
    globus_list_t **                    list);

/**
 * GLOBUS_TRUE if hashtable is empty, GLOBUS_FALSE otherwise
 */
globus_bool_t
globus_hashtable_empty(
    globus_hashtable_t *                table);

/**
 * returns number of entries in hashtable
 */
int
globus_hashtable_size(
    globus_hashtable_t *                table);

/**
 * For the following, the iterator is initially NULL until one of 
 * globus_hashtable_first or globus_hashtable_last has been called.  All other
 * calls have no effect on iterator except for globus_hashtable_remove.  If
 * the iterator points at the entry being removed, the iterator is moved to
 * the next entry.
 * 
 * Once an 'end' has been reached with globus_hashtable_next or
 * globus_hashtable_prev, the iterator must again be reset with 
 * globus_hashtable_first or globus_hashtable_last
 */

/**
 * set iterator to first entry and return datum, NULL if empty 
 */
void *
globus_hashtable_first(
    globus_hashtable_t *                table);

/**
 * set iterator to next entry and return datum, NULL if at end 
 */
void *
globus_hashtable_next(
    globus_hashtable_t *                table);

/** 
 * set iterator to last entry and return datum, NULL if empty 
 */
void *
globus_hashtable_last(
    globus_hashtable_t *                table);

/** 
 * set iterator to prev entry and return datum, NULL if at beginning 
 */
void *
globus_hashtable_prev(
    globus_hashtable_t *                table);

/**
 * Free all memory allocated by hashtable.  If the datums that were inserted
 * are non-scalar, you should use globus_hashtable_destroy_all to allow freeing
 * of any remaining entries.
 */
int
globus_hashtable_destroy(
    globus_hashtable_t *                table);
    
/**
 * Free all memory associated with hashtable.  element_free will be called on
 * each remaining datum in the table.
 */
void
globus_hashtable_destroy_all(
    globus_hashtable_t *                table,
    globus_hashtable_destructor_func_t  element_free);

/**
 * Predefined hash/eq functions for common data types
 */
int
globus_hashtable_string_hash(
    void *                              string,
    int                                 limit);

int
globus_hashtable_string_keyeq(
    void *                              string1,
    void *                              string2);

int
globus_hashtable_voidp_hash(
    void *                              voidp,
    int                                 limit);

int
globus_hashtable_voidp_keyeq(
    void *                              voidp1,
    void *                              voidp2);

int
globus_hashtable_int_hash(
    void *                              integer,
    int                                 limit);

int
globus_hashtable_int_keyeq(
    void *                              integer1,
    void *                              integer2);

int
globus_hashtable_ulong_hash(
    void *                              integer,
    int                                 limit);

int
globus_hashtable_ulong_keyeq(
    void *                              integer1,
    void *                              integer2);

EXTERN_C_END

#endif /* GLOBUS_COMMON_HASHTABLE_H */
