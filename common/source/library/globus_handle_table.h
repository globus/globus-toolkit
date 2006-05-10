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

/******************************************************************************
globus_handle_table.h

Description:
    This header defines a reference-counting handle table structure.

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef GLOBUS_INCLUDE_HANDLE_TABLE_H
#define GLOBUS_INCLUDE_HANDLE_TABLE_H

#include "globus_common_include.h"


EXTERN_C_BEGIN

typedef struct globus_l_handle_table_s * globus_handle_table_t;

typedef int globus_handle_t;

typedef 
void 
(*globus_handle_destructor_t)(
    void *                              datum);

#define GLOBUS_NULL_HANDLE 0
#define GLOBUS_HANDLE_TABLE_NO_HANDLE 0

/**
 *  Initialize a table of unique reference counted handles.
 * 
 *  @param  handle_table
 *          the table of unique handles we want to use.
 *
 */
int
globus_handle_table_init(
    globus_handle_table_t *             handle_table,
    globus_handle_destructor_t          destructor);

/**
 *  Destroy a handle table
 */
int
globus_handle_table_destroy(
    globus_handle_table_t *             handle_table);

/**
 *  insert a piece of memory into the table for reference counting
 * 
 *  @param  handle_table
 *          the table of unique handles we want to use.
 *          
 *  @param  value
 *          the piece of memory to reference count
 * 
 *  @param  initial_refs
 *          the intial reference count of this piece of memory.
 */
globus_handle_t
globus_handle_table_insert(
    globus_handle_table_t *             handle_table,
    void *                              datum,
    int                                 initial_refs);

/**
 * add a reference to a handle table entry.
 * 
 *  @param  handle_table
 *          the table of unique handles we want to use.
 *          
 *  @param  handle       
 *          the handle that we want to increment
 * 
 * Returns:  GLOBUS_TRUE if the handle is still referenced.
 *
 */
globus_bool_t
globus_handle_table_increment_reference(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle);

/**
 *  increment the reference count by inc
 * 
 *  @param  handle_table
 *          the table of unique handles we want to use.
 *          
 *  @param  handle       
 *          the handle that we want to increment
 * 
 * Returns:  GLOBUS_TRUE if the handle is still referenced.
 *
 */
globus_bool_t
globus_handle_table_increment_reference_by(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle,
    unsigned int                        inc);

/**
 *  Remove a reference to a handle table entry,
 *              deleting the entry if no more references
 *              exist.
 * 
 *  @param  handle_table
 *          the table of unique handles we want to use.
 *          
 *  @param  handle       
 *          the handle that we want to decrement
 * 
 *  Returns  GLOBUS_TRUE if the handle is still referenced.
 *
 */
globus_bool_t
globus_handle_table_decrement_reference(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle);

/**
 * Find the void * corresponding to a unique
 *              handle. Does not update the reference count.
 * 
 *  @param  handle_table
 *          the table of unique handles we want to use
 *                  
 *  @param  handle
 *          the handle that we want to look up
 * 
 * Returns:  the data value associated with the handle
 *
 */
void *
globus_handle_table_lookup(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_HANDLE_TABLE_H */
