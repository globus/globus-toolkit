/******************************************************************************
globus_handle_table.c
 
Description:
    This module implements a reference-counting handle table structure.
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#include "config.h"
#include "globus_handle_table.h"

/******************************************************************************
		             Type definitions
******************************************************************************/
#define GLOBUS_L_HASH_TABLE_SIZE            42

/******************************************************************************
                           local data structures
******************************************************************************/
typedef struct
{
    int					ref;
    globus_handle_t			handle;
    void *				value;
} globus_l_handle_entry_t;

/*
 * Function: globus_handle_table_init()
 * 
 * Description: Initialize a handle table, setting it up to generate
 *              unique handle numbers
 * 
 * Parameters: 
 * 
 * Returns: 
 */
void
globus_handle_table_init(
    globus_handle_table_t *		handle_table)
{
    globus_mutex_init(&handle_table->lock,
		      (globus_mutexattr_t *) GLOBUS_NULL);

    globus_hashtable_init(&handle_table->table,
			  GLOBUS_L_HASH_TABLE_SIZE,
			  globus_hashtable_int_hash,
			  globus_hashtable_int_keyeq);

    handle_table->last_handle = GLOBUS_HANDLE_TABLE_NO_HANDLE;
}
/* globus_l_callback_handle_init() */

/*
 * Function: globus_handle_table_destroy()
 * 
 * Description: Delete a handle table
 * 
 * Parameters: 
 * 
 * Returns: 
 */
void
globus_handle_table_destroy(
    globus_handle_table_t *		handle_table)
{
    globus_mutex_destroy(&handle_table->lock);
    globus_hashtable_destroy(&handle_table->table);
}
/* globus_l_callback_handle_destroy() */

/*
 * Function: globus_handle_table_insert()
 * 
 * Description: Insert a value into the handle table, and
 *              return a unique handle.
 * 
 * Parameters:  handle_table - the table of unique handles
 *                  we want to use
 *              value - the value to insert into the table
 *              initial_refs - the initial reference count
 *                  of this value in the table.
 * 
 * Returns:  A unique handle. Note that if all possible
 *           integers are already used as handles, then
 *           this will deadlock.
 */
globus_handle_t
globus_handle_table_insert(
    globus_handle_table_t *		handle_table,
    void *				value,
    int					initial_refs)
{
    globus_bool_t			done = GLOBUS_FALSE;
    void *				tmp_found;
    globus_l_handle_entry_t *		entry;

    globus_mutex_lock(&handle_table->lock);

    /* Search for new handle number */
    while(!done)
    {
        handle_table->last_handle++;
	if(handle_table->last_handle == GLOBUS_HANDLE_TABLE_NO_HANDLE)
        {
	    handle_table->last_handle++;
	}
        
        tmp_found = globus_hashtable_lookup(&handle_table->table, 
				            (void *)handle_table->last_handle);
        if(tmp_found == GLOBUS_NULL)
	{
            done = GLOBUS_TRUE;
	}
    }

    /* Create a new handle table entry */
    entry = (globus_l_handle_entry_t *)
	       globus_malloc(sizeof(globus_l_handle_entry_t));
    entry->handle = handle_table->last_handle;
    entry->value = value;
    entry->ref = initial_refs;

    /* Insert it into the handle table */
    globus_hashtable_insert(&handle_table->table, 
			    (void *) entry->handle,
			    (void *) entry);
    globus_mutex_unlock(&handle_table->lock);

    /* Return our new, unique handle */
    return entry->handle;
}
/* globus_handle_table_insert() */

globus_bool_t
globus_handle_table_increment_reference_by(
    globus_handle_table_t *                     handle_table,
    globus_handle_t                             handle,
    unsigned int                                inc)
{
    globus_l_handle_entry_t *		entry;
    globus_bool_t			still_in_table;

    globus_mutex_lock(&handle_table->lock);

    entry = globus_hashtable_lookup(&handle_table->table,
				    (void *) handle);

    if(entry == GLOBUS_NULL)
    {
	still_in_table = GLOBUS_FALSE;
    }
    else
    {
	still_in_table = GLOBUS_TRUE;
	entry->ref += inc;
    }
    globus_mutex_unlock(&handle_table->lock);

    return still_in_table;
}
/*
 * Function: globus_handle_table_decrement_reference()
 * 
 * Description: Remove a reference to a handle table entry,
 *              deleting the entry if no more references
 *              exist.
 * 
 * Parameters:  handle_table - the table of unique handles
 *                  we want to use
 *              handle - the handle that we want to remove
 * 
 * Returns:  GLOBUS_TRUE if the handle is still referenced.
 *
 */
globus_bool_t
globus_handle_table_decrement_reference(
    globus_handle_table_t *		handle_table,
    globus_handle_t			handle)
{
    globus_l_handle_entry_t *		entry;
    globus_bool_t			still_in_table;
    void *				rc;

    globus_mutex_lock(&handle_table->lock);

    entry = globus_hashtable_lookup(&handle_table->table,
				    (void *) handle);

    if(entry == GLOBUS_NULL)
    {
	rc =  GLOBUS_NULL;
	still_in_table = GLOBUS_FALSE;
    }
    else
    {
	entry->ref--;
	rc = entry->value;
	if(entry->ref == 0)
	{
	    globus_hashtable_remove(&handle_table->table,
				    (void *)handle);
	    globus_free(entry);
	    still_in_table = GLOBUS_FALSE;
	}
	else
	{
	    still_in_table = GLOBUS_TRUE;
	}
    }
    globus_mutex_unlock(&handle_table->lock);

    return still_in_table;
}
/* globus_handle_table_remove() */

/*
 * Function: globus_handle_table_increment_reference()
 * 
 * Description: Add a reference to a handle table entry.
 * 
 * Parameters:  handle_table - the table of unique handles
 *                  we want to use
 *              handle - the handle that we want to remove
 * 
 * Returns:  GLOBUS_TRUE if the handle is still referenced.
 *
 */
globus_bool_t
globus_handle_table_increment_reference(
    globus_handle_table_t *		handle_table,
    globus_handle_t			handle)
{
    globus_l_handle_entry_t *		entry;
    globus_bool_t			still_in_table;

    globus_mutex_lock(&handle_table->lock);

    entry = globus_hashtable_lookup(&handle_table->table,
				    (void *) handle);

    if(entry == GLOBUS_NULL)
    {
	still_in_table = GLOBUS_FALSE;
    }
    else
    {
	still_in_table = GLOBUS_TRUE;
	entry->ref++;
    }
    globus_mutex_unlock(&handle_table->lock);

    return still_in_table;
}
/* globus_handle_table_remove() */

/*
 * Function: globus_handle_table_lookup()
 * 
 * Description: Find the void * corresponding to a unique
 *              handle. Does not update the reference count.
 * 
 * Parameters:  handle_table - the table of unique handles
 *                  we want to use
 *              handle - the handle that we want to look up
 * 
 * Returns:  the data value associated with the handle
 *
 */
void *
globus_handle_table_lookup(
    globus_handle_table_t *		handle_table,
    globus_handle_t			handle)
{
    globus_l_handle_entry_t *		entry;
    void *				rc;

    globus_mutex_lock(&handle_table->lock);

    entry = globus_hashtable_lookup(&handle_table->table,
				    (void *) handle);

    if(entry == GLOBUS_NULL)
    {
	rc =  GLOBUS_NULL;
    }
    else
    {
	rc = entry->value;
    }
    globus_mutex_unlock(&handle_table->lock);

    return rc;
}
/* globus_handle_table_lookup() */
