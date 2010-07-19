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
