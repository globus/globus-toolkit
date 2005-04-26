/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

/******************************************************************************
globus_gass_transfer_keyvalue.c
 
Description:
    This module implements a simple list of key-value pairs
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

#include "globus_i_gass_transfer.h"
#include <string.h>

/******************************************************************************
			  Module Specific Constants
******************************************************************************/

globus_bool_t
globus_i_gass_transfer_keyvalue_search_pred(
    void *					datum,
    void *					args)
{
    globus_gass_transfer_keyvalue_t *	kv;

    kv = (globus_gass_transfer_keyvalue_t *) datum;
    if (datum == GLOBUS_NULL || args == GLOBUS_NULL)
    {
	return GLOBUS_FALSE;
    }
    else if(strcmp(kv->key, args) == 0)
    {
	return GLOBUS_TRUE;
    }
    else
    {
	return GLOBUS_FALSE;
    }
}
/* globus_i_gass_transfer_keyvalue_search_pred() */

char *
globus_i_gass_transfer_keyvalue_lookup(
    globus_list_t **				list,
    char *					key)
{
    globus_list_t *				tmp;
    globus_gass_transfer_keyvalue_t *	kv;

    tmp = globus_list_search_pred(
	    *list,
	    globus_i_gass_transfer_keyvalue_search_pred, 
	    (void *) key);

    if(tmp)
    {
	kv = (globus_gass_transfer_keyvalue_t *)
	    globus_list_first(tmp);
	return kv->value;
    }
    else
    {
	return GLOBUS_NULL;
    }
}
/* globus_i_gass_transfer_keyvalue_lookup() */

void
globus_i_gass_transfer_keyvalue_insert(
    globus_list_t **				list,
    char *					key,
    char *					value)
{
    globus_gass_transfer_keyvalue_t *	kv;

    kv = globus_malloc(sizeof(globus_gass_transfer_keyvalue_t));
    kv->key = key;
    kv->value = value;

    globus_list_insert(list,
		       kv);
}
/* globus_i_gass_transfer_keyvalue_insert() */

void
globus_i_gass_transfer_keyvalue_replace(
    globus_list_t **				list,
    char *					key,
    char *					value)
{
    globus_list_t *				tmp;
    globus_gass_transfer_keyvalue_t *	kv;

    tmp = globus_list_search_pred(
	    *list,
	    globus_i_gass_transfer_keyvalue_search_pred, 
	    (void *) key);

    globus_assert(tmp != GLOBUS_NULL);
    kv = (globus_gass_transfer_keyvalue_t *)
	globus_list_first(tmp);
    kv->value = value;
}
/* globus_i_gass_transfer_keyvalue_replace() */

void
globus_i_gass_transfer_keyvalue_destroy(
    globus_list_t **				list)
{
    globus_list_t *				tmp;
    globus_gass_transfer_keyvalue_t *		kv;

    tmp = *list;

    while(!globus_list_empty(tmp))
    {
	kv = globus_list_remove(list,
				tmp);
	tmp = *list;
	globus_free(kv->key);
	globus_free(kv->value);
	globus_free(kv);
    }
}
/* globus_i_gass_transfer_keyvalue_destroy() */
