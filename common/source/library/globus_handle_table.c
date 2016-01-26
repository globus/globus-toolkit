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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_handle_table.c
 * @brief A reference-counting handle table structure
 */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#include "globus_i_common_config.h"
#include "globus_handle_table.h"
#include "globus_libc.h"

#define GLOBUS_L_HANDLE_TABLE_BLOCK_SIZE 100

/******************************************************************************
                           local data structures
******************************************************************************/

typedef struct globus_l_handle_entry_s
{
    int                                 index;
    int                                 ref;
    void *                              value;
    struct globus_l_handle_entry_s *    pnext;
} globus_l_handle_entry_t;

typedef struct globus_l_handle_table_s
{
    struct globus_l_handle_entry_s **   table;
    int                                 next_slot;
    int                                 table_size;
    struct globus_l_handle_entry_s *    inactive;
    globus_handle_destructor_t          destructor;
} globus_l_handle_table_t;

/**
 * Initialize a table of unique reference counted handles.
 * @ingroup globus_handle_table
 * @param  handle_table
 *         the table of unique handles we want to use.
 * @param  destructor
 *         Function to call to free the data associated with
 *         a handle when the handle's reference count reaches
 *         0 or the handle table is destroyed.
 */
int
globus_handle_table_init(
    globus_handle_table_t *             handle_table,
    globus_handle_destructor_t          destructor)
{
    globus_l_handle_table_t *		i_handle_table;

    if(!handle_table)
    {
        return GLOBUS_FAILURE;
    }

    i_handle_table = malloc(sizeof(globus_l_handle_table_t));
    if(handle_table == NULL)
    {
        return GLOBUS_FAILURE;
    }

    i_handle_table->table = malloc(GLOBUS_L_HANDLE_TABLE_BLOCK_SIZE * 
            sizeof(globus_l_handle_entry_t *));
    if(!i_handle_table->table)
    {
        free(handle_table);

        return GLOBUS_FAILURE;
    }

    *handle_table = i_handle_table;

    i_handle_table->next_slot = GLOBUS_NULL_HANDLE + 1;
    i_handle_table->table_size = GLOBUS_L_HANDLE_TABLE_BLOCK_SIZE;
    i_handle_table->inactive = NULL;
    i_handle_table->destructor = destructor;
    
    return GLOBUS_SUCCESS;
}
/* globus_handle_table_init() */

/**
 * @brief Destroy a handle table
 * @ingroup globus_handle_table
 * @details
 * Destroy a handle table and call the destructor for all objects associated
 * with it.
 * @param handle_table
 *     Pointer to the handle table to destroy
 */
int
globus_handle_table_destroy(
    globus_handle_table_t *             handle_table)
{
    int                                 i;
    globus_l_handle_entry_t **          table;
    globus_l_handle_entry_t *           inactive;
    globus_l_handle_entry_t *           save;
    globus_handle_destructor_t          destructor;
    globus_l_handle_table_t *		i_handle_table;

    if(!handle_table)
    {
        return GLOBUS_FAILURE;
    }

    i_handle_table = *handle_table;

    if(!i_handle_table)
    {
        return GLOBUS_FAILURE;
    }

    /* first free all active handles */
    table = i_handle_table->table;
    destructor = i_handle_table->destructor;
    i = i_handle_table->next_slot;
    while(--i > GLOBUS_NULL_HANDLE)
    {
        if(table[i])
        {
            if(destructor)
            {
                destructor(table[i]->value);
            }
            
            free(table[i]);
        }
    }

    /* then free inactive handles */
    inactive = i_handle_table->inactive;
    while(inactive)
    {
        save = inactive->pnext;
        free(inactive);
        inactive = save;
    }

    /* free the table */
    free(table);

    /* free the table handle */
    free(i_handle_table);

    /* finally, invalidate the handle */
    *handle_table = NULL;

    return GLOBUS_SUCCESS;
}
/* globus_l_callback_handle_destroy() */

/** Insert a datum into a handle table
 * @ingroup globus_handle_table
 * @details
 * Insert a value into the handle table, and return a unique handle to it.
 *
 * @param handle_table
 *     Handle table to add the value to
 * @param value
 *     The value to insert into the table
 * @param initial_refs
 *     The initial reference count of this value in the table
 *
 * @return The globus_handle_table_insert() function returns a unique handle
 * to value.
 */
globus_handle_t
globus_handle_table_insert(
    globus_handle_table_t *             handle_table,
    void *                              value,
    int                                 initial_refs)
{
    globus_l_handle_entry_t *           entry;
    globus_l_handle_table_t *		i_handle_table;

    if(!handle_table)
    {
        return GLOBUS_NULL_HANDLE;
    }

    i_handle_table = *handle_table;

    if(!i_handle_table)
    {
        return GLOBUS_NULL_HANDLE;
    }

    /* see if we have an inactive handle, if so, take it */
    if(i_handle_table->inactive)
    {
        entry = i_handle_table->inactive;
        i_handle_table->inactive = entry->pnext;
    }
    /* otherwise allocate a new entry */
    else
    {
        /* if table is full, make bigger */
        if(i_handle_table->next_slot == i_handle_table->table_size)
        {
            globus_l_handle_entry_t ** new_table;

            new_table = realloc(
                    i_handle_table->table,
                    (i_handle_table->table_size + 
                        GLOBUS_L_HANDLE_TABLE_BLOCK_SIZE) *
                        sizeof(globus_l_handle_entry_t *));

            if(!new_table)
            {
                return GLOBUS_NULL_HANDLE;
            }

            i_handle_table->table = new_table;
            i_handle_table->table_size += GLOBUS_L_HANDLE_TABLE_BLOCK_SIZE;
        }

        entry = malloc(sizeof(globus_l_handle_entry_t));
        if(!entry)
        {
            return GLOBUS_NULL_HANDLE;
        }

        entry->index = i_handle_table->next_slot++;
    }

    /* now bind this entry to table */
    i_handle_table->table[entry->index] = entry;

    entry->value = value;
    entry->ref = initial_refs;

    return entry->index;
}
/* globus_handle_table_insert() */

/**
 * @brief Increment the reference count for handle
 * @ingroup globus_handle_table
 * @param handle_table
 *     The table that the handle was created in.
 * @param handle       
 *     The handle to a datum to increment the reference count for.
 * @param inc
 *     The number of references to add the handle.
 * @return The globus_handle_table_increment_reference_by() function returns
 * a boolean value indicating whether the handle still references a valid
 * datum.
 */
globus_bool_t
globus_handle_table_increment_reference_by(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle,
    unsigned int                        inc)
{
    globus_l_handle_entry_t *           entry;
    globus_l_handle_table_t *		i_handle_table;

    if(!handle_table)
    {
        return GLOBUS_FALSE;
    }

    i_handle_table = *handle_table;

    if(!i_handle_table)
    {
        return GLOBUS_FALSE;
    }

    if(handle > GLOBUS_NULL_HANDLE && handle < i_handle_table->next_slot)
    {
        entry = i_handle_table->table[handle];
    }
    else
    {
        entry = NULL;
    }

    if(entry)
    {
        entry->ref += inc;
        return GLOBUS_TRUE;
    }
    else
    {
        return GLOBUS_FALSE;
    }
}

/**
 * @brief Remove a reference to a handle
 * @ingroup globus_handle_table
 * @details
 * Remove a reference to a handle table entry, calling its destructor if no
 * more references exist for the handle.
 *
 * @param handle_table
 *     The table that the handle was created in.
 * @param handle       
 *     The handle to a datum to decrement the reference count for.
 *
 * @return The globus_handle_table_decrement_reference() function returns
 * a boolean value indicating whether the handle still references a valid
 * datum.
 */
globus_bool_t
globus_handle_table_decrement_reference(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle)
{
    globus_l_handle_entry_t *           entry;
    globus_l_handle_table_t *		i_handle_table;

    if(!handle_table)
    {
        return GLOBUS_FALSE;
    }

    i_handle_table = *handle_table;

    if(!i_handle_table)
    {
        return GLOBUS_FALSE;
    }

    if(handle > GLOBUS_NULL_HANDLE && handle < i_handle_table->next_slot)
    {
        entry = i_handle_table->table[handle];
    }
    else
    {
        entry = NULL;
    }

    if(entry)
    {
        entry->ref--;
        if(entry->ref == 0)
        {
            if(i_handle_table->destructor)
            {
                i_handle_table->destructor(entry->value);
            }
            
            /* NULL out slot and push this on the inactive list */
            i_handle_table->table[handle] = NULL;
            entry->pnext = i_handle_table->inactive;
            i_handle_table->inactive = entry;
        }
        else
        {
            return GLOBUS_TRUE;
        }
    }

    return GLOBUS_FALSE;
}
/* globus_handle_table_decrement_reference() */

/**
 * @brief Add a reference to a handle table entry
 * @ingroup globus_handle_table
 * @details
 * @param handle_table
 *     The table that the handle was created in.
 * @param handle       
 *     The handle to a datum to increment the reference count for.
 * @return The globus_handle_table_increment_reference() function returns
 * a boolean value indicating whether the handle still references a valid
 * datum.
 */
globus_bool_t
globus_handle_table_increment_reference(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle)
{
    return globus_handle_table_increment_reference_by(
        handle_table,
        handle,
        1);
}
/* globus_handle_table_increment_reference() */

/**
 * @brief Resolve a handle its datum
 * @ingroup globus_handle_table
 * @param handle_table
 *     The table that the handle was created in.
 * @param handle       
 *     The handle to a datum to resolve
 * @return The globus_handle_table_lookup() function returns
 * the datum associated with the handle in the handle table, or NULL
 * if the handle does not reference valid data.
 */
void *
globus_handle_table_lookup(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle)
{
    globus_l_handle_entry_t *           entry;
    globus_l_handle_table_t *		i_handle_table;

    if(!handle_table)
    {
        return NULL;
    }

    i_handle_table = *handle_table;

    if(!i_handle_table)
    {
        return NULL;
    }

    if(handle > GLOBUS_NULL_HANDLE && handle < i_handle_table->next_slot)
    {
        entry = i_handle_table->table[handle];
    }
    else
    {
        entry = NULL;
    }

    if(entry)
    {
        return entry->value;
    }
    else
    {
        return NULL;
    }
}
/* globus_handle_table_lookup() */
