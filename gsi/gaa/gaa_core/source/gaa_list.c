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

#include "gaa.h"
#include "gaa_private.h"

/** @defgroup gaa_list_static "static routines from gaa_core/gaa_list.c"
 */
static gaaint_list *
gaa_l_list_new(gaaint_listaddfunc addfunc, gaa_listcompfunc compare,
	       gaa_freefunc freefunc);

static gaa_status
gaa_l_list_prepend(gaaint_list *list, void *data, gaa_listcompfunc checkdups);

static gaa_status
gaa_l_list_append(gaaint_list *list, void *data, gaa_listcompfunc checkdups);

static gaa_status
gaa_l_list_add_sorted(gaaint_list *list, void *data,
		      gaa_listcompfunc checkdups);

static
gaa_l_list_has_dup(gaaint_list *list, gaa_listcompfunc checkdups, void *data);

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_list_prepend()
 *
 * @ingroup gaa_list_static
 *
 *  Create a new list entry and prepend it to a list.  This function
 *  is used by gaa_i_new_stack() as a listadd function.
 *
 *  @param list
 *         input/output list to add to.
 *  @param data
 *         input data to add to list
 *  @param checkdups
 *         optional input function to check for duplicates -- if this
 *         function is nonzero, then it will be called to see if an
 *         "equal" data item is already in the list, in which case
 *         the data item will not be added.
 * 
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_list_prepend(gaaint_list *	list,
		   void *		data,
		   gaa_listcompfunc	checkdups)
{
    gaaint_list_entry *			l;
    int					skipped = 0;

    if (list == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    if ((l = (gaaint_list_entry *)malloc(sizeof(gaaint_list_entry))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    l->data = data;
    l->next = list->entries;
    l->prev = 0;
    gaacore_mutex_lock(list->mutex);
    if (! (skipped = gaa_l_list_has_dup(list, checkdups, data)))
    {
	if (list->entries)
	    list->entries->prev = l;
	else
	    list->last = l;
	list->entries = l;
    }
    gaacore_mutex_unlock(list->mutex);
    if (skipped)
	free(l);
    return(GAA_S_SUCCESS);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_list_append()
 *
 * @ingroup gaa_list_static
 *
 *  Create a new list entry and append it to a list.  This function
 *  is used by gaa_i_new_silo() as a listadd function.
 *
 *  @param list
 *         input/output list to add to.
 *  @param data
 *         input data to add to list
 *  @param checkdups
 *         optional input function to check for duplicates -- if this
 *         function is nonzero, then it will be called to see if an
 *         "equal" data item is already in the list, in which case
 *         the data item will not be added.
 * 
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_list_append(gaaint_list *		list,
		  void *		data,
		  gaa_listcompfunc	checkdups)
{
    gaaint_list_entry *			l;
    int					skipped = 0;

    if (list == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((l = (gaaint_list_entry *)malloc(sizeof(gaaint_list_entry))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    l->data = data;
    l->next = 0;
    l->prev = list->last;
    gaacore_mutex_lock(list->mutex);
    if (! (skipped = gaa_l_list_has_dup(list, checkdups, data)))
    {
	if (list->last)
	    list->last->next = l;
	else
	    list->entries = l;
	list->last = l;
    }
    gaacore_mutex_unlock(list->mutex);
    if (skipped)
	free(l);
    return(GAA_S_SUCCESS);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_list_new()
 *
 * @ingroup gaa_list_static
 *
 *  Create a new list
 *
 *  @param addfunc
 *         function to be used to add entries to the list (e.g.
 *         gaa_l_list_prepend(), gaa_l_list_append(), gaa_l_list_add_sorted()).
 *  @param compare
 *         optional input function to compare list entries (this function
 *         is available for an addfunc -- such as gaa_l_list_add_sorted() --
 *         to use to add entries in order.
 *  @param freefunc
 *         optional input function.  If this function is nonzero, then
 *         it will be used to free the data associated with each list
 *         entry when the list is freed.
 *
 *  @retval <list pointer>
 *          the newly-created list
 *  @retval 0
 *          An error has occurred.
 * 
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaaint_list *
gaa_l_list_new(gaaint_listaddfunc	addfunc,
	       gaa_listcompfunc		compare,
	       gaa_freefunc		freefunc)
{
    gaaint_list *list;
    gaa_status status;

    if ((list = (gaaint_list *)malloc(sizeof(gaaint_list))) == 0)
	return(0);
    list->mutex = 0;
    if (((status = gaacore_mutex_create(&(list->mutex))) != GAA_S_SUCCESS) &&
	(GAA_MAJSTAT(status) != GAA_S_UNIMPLEMENTED_FUNCTION))
    {
	free(list);
	return(0);
    }
    list->addfunc = addfunc;
    list->compare = compare;
    list->freefunc = freefunc;
    list->entries = 0;
    list->last = 0;
    return(list);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_list_add_sorted()
 *
 * @ingroup gaa_list_static
 *
 *  Create a new list entry and add it, in order to a sorted list.
 *  This function is used by gaa_i_new_sorted_list() as a listadd function.
 *
 *  @param list
 *         input/output list to add to.
 *  @param data
 *         input data to add to list
 *  @param checkdups
 *         optional input function to check for duplicates -- if this
 *         function is nonzero, then it will be called to see if an
 *         "equal" data item is already in the list, in which case
 *         the data item will not be added.
 * 
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_list_add_sorted(gaaint_list *	list,
		      void *		data,
		      gaa_listcompfunc	checkdups)
{
    gaaint_list_entry *			l;
    gaaint_list_entry *			le;
    int					skipped = 0;

    if (list == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if ((l = (gaaint_list_entry *)malloc(sizeof(gaaint_list_entry))) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    l->data = data;
    gaacore_mutex_lock(list->mutex);
    if (! (skipped = gaa_l_list_has_dup(list, checkdups, data)))
    {
	if (list->entries == 0)
	{
	    l->prev = l->next = 0;
	    list->entries = list->last = l;
	}
	else
	{
	    for (le = list->entries;
		 le && (list->compare(le->data, l->data) < 0); le = le->next)
		;
	    if (le)
	    {
		l->next = le;
		l->prev = le->prev;
		if (le->prev)
		    le->prev->next = l;
		else
		    list->entries = l;
		le->prev = l;
	    }
	    else
	    {
		list->last->next = l;
		l->prev = list->last;
		l->next = 0;
		list->last = l;
	    }
	}
    }
    gaacore_mutex_unlock(list->mutex);
    if (skipped)
	free(l);
    return(GAA_S_SUCCESS);
}

/** gaa_i_new_stack()
 *
 *  @ingroup gaa_internal
 *
 *  Create a new stack.
 *
 *  @param freefunc
 *         optional input function to be used to free list entries when
 *         the list is freed.
 */
gaaint_list *
gaa_i_new_stack(gaa_freefunc freefunc)
{
    return(gaa_l_list_new(gaa_l_list_prepend, 0, freefunc));
}

/** gaa_i_new_stack()
 *
 *  @ingroup gaa_internal
 *
 *  Create a new silo.
 *
 *  @param freefunc
 *         optional input function to be used to free list entries when
 *         the list is freed.
 */
gaaint_list *
gaa_i_new_silo(gaa_freefunc freefunc)
{
    return(gaa_l_list_new(gaa_l_list_append, 0, freefunc));
}

/** gaa_i_new_sorted_list()
 *
 *  @ingroup gaa_internal
 *
 *  Create a new sorted list
 *
 *  @param compare
 *         input function to compare list entries (to determine the
 *         sort order
 *  @param freefunc
 *         optional input function to be used to free list entries when
 *         the list is freed.
 */
gaaint_list *
gaa_i_new_sorted_list(gaa_listcompfunc compare, gaa_freefunc freefunc)
{
    return(gaa_l_list_new(gaa_l_list_add_sorted, compare, freefunc));
}

/** gaa_i_list_add_entry()
 *
 *  @ingroup gaa_internal
 *
 *  Add an entry to a list.  The position of the new entry will be
 *  determined by the list's addfunc.
 *
 *  @param list
 *         input/output list
 *  @param data
 *         input data to add
 */
gaa_status
gaa_i_list_add_entry(gaa_list_ptr list, void *data)
{
    if (list == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    return(list->addfunc(list, data, 0));
}

/** gaa_i_list_add_unique_entry()
 *
 *  @ingroup gaa_internal
 *
 *  Add an entry to a list, unless an equivalent entry already exists.
 *
 *  @param list
 *         input/output list
 *  @param data
 *         input data to add
 *  @param checkdups
 *         input comparison function to determine whether there's an
 *         equivalent entry
 */
gaa_status
gaa_i_list_add_unique_entry(gaa_list_ptr list, void *data, gaa_listcompfunc checkdups)
{
    if (list == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    return(list->addfunc(list, data, checkdups));
}

/** gaa_list_first()
 *
 *  @ingroup gaa
 * 
 *  Find the first entry in a list
 *
 *  @param list
 *         input list
 *
 *  @retval <list_entry>
 *          first list entry
 *  @retval 0
 *          list was null
 */
gaa_list_entry_ptr
gaa_list_first(gaa_list_ptr list)
{
    if (list == 0)
	return(0);
    return(list->entries);
}

/** gaa_list_next()
 *
 *  @ingroup gaa
 * 
 *  Find the next entry in a list
 *
 *  @param entry
 *         input list entry
 *
 *  @retval <list_entry>
 *          next list entry
 *  @retval 0
 *          entry was null
 */
gaa_list_entry_ptr
gaa_list_next(gaa_list_entry_ptr entry)
{
    if (entry == 0)
	return(0);
    return(entry->next);
}


/** gaa_list_entry_value()
 *
 *  @ingroup gaa
 * 
 *  Find the data in a list entry.
 *
 *  @param entry
 *         input list entry
 *
 *  @retval <data>
 *          data from list entry
 *  @retval 0
 *          entry was null
 */
void *
gaa_list_entry_value(gaa_list_entry_ptr entry)
{
    if (entry == 0)
	return(0);
    return(entry->data);
}


/** gaa_i_list_clear()
 *
 *  @ingroup gaa_internal
 * 
 *  Clear a list, freeing all its entries
 *
 *  @param list
 *         input/output list to clear
 */
void
gaa_i_list_clear(gaaint_list *list)
{
    gaaint_list_entry *ent;
    gaaint_list_entry *nxt;
    gaacore_mutex_lock(list->mutex);
    for (ent = list->entries; ent; ) {
	nxt = ent->next;
	if (list->freefunc)
	    list->freefunc(ent->data);
	free(ent);
	ent = nxt;
    }
    list->entries = 0;
    list->last = 0;
    gaacore_mutex_unlock(list->mutex);
}

/** gaa_list_free()
 *
 *  @ingroup gaa
 *
 *  Free a list and all its entries.
 *
 *  @param list
 *         list to free
 *
 *  @note
 *  If the list's freefunc is nonzero, it will be called to free the
 *  data associated with each list entry.
 */
void
gaa_list_free (gaa_list_ptr list)
{
    if (list == 0)
	return;
    gaa_i_list_clear(list);
    gaacore_mutex_destroy(list->mutex);
    free(list);
}

/** gaa_i_policy_order()
 *
 *  @ingroup gaa_internal
 *
 *  Compare two policy entries.  Used in the list of policy entries
 *  created by gaa_l_init_policy().
 *
 *  @param e1
 *         input policy entry to compare
 *  @param e2
 *         input policy entry to compare
 * 
 *  @retval -1
 *          e1 < e2 (e1's priority is less than e2's, or the priorities
 *                   are equal and e1's num is less than e2's)
 *  @retval 0
 *          e1 == e2 (the priorities and nums are equal)
 *  @retval 1
 *          e2 < e1
 */
gaa_i_policy_order(gaa_policy_entry *e1,
		   gaa_policy_entry *e2)
{
    if (! e1 && e2)
	return(-1);
    if (!e1 && !e2)
	return(0);
    if (e1 && !e2)
	return(1);
    
    /* Neither e1 nor e2 is null */
    if (e1->priority < e2->priority)
	return(-1);
    if (e1->priority > e2->priority)
	return(1);

    /* Priorities are the same */
    if (e1->num < e2->num)
	return(-1);
    if (e1->num > e2->num)
	return(1);
    return(0);
}

/** gaa_i_list_empty()
 *
 *  @ingroup gaa_internal
 *
 *  Check to see whether a list is empty.
 *
 *  @param list
 *         input list to check.
 *
 *  @retval 0
 *          list is not empty
 *  @retval 1
 *          list is empty
 */
gaa_i_list_empty(gaaint_list *list)
{
    return(list->entries == 0);
}

/** gaa_i_list_merge()
 *
 *  @ingroup gaa_internal
 *
 *  Merge two lists into one.
 *
 *  @param dest
 *         input/output list (will be merged list on output)
 *  @param src
 *         input list
 */
gaa_status
gaa_i_list_merge(gaaint_list *dest, gaaint_list *src)
{
    int status = GAA_S_SUCCESS;
    gaaint_list_entry *ent;

    for (ent = gaa_list_first(src); ent; ent = gaa_list_next(ent))
	if ((status = gaa_i_list_add_entry(dest, gaa_list_entry_value(ent))) != GAA_S_SUCCESS)
	    return(status);
    return(status);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_list_has_dup()
 *
 *  @ingroup gaa_list_static
 *
 *  Call the checkdups function to see whether the list has an element
 *  equivalent to the specified data.
 *
 *  @param list
 *         input list to check
 *  @param checkdups
 *         input function to compare data to list entry
 *  @param data
 *         input data to compare
 *
 *  @retval 1
 *          list has an entry equivalent to the specified data
 *  @retval 0
 *          list does not have an entry equivalent to the specified data
 * 
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
   
static
gaa_l_list_has_dup(gaaint_list *list, gaa_listcompfunc checkdups, void *data)
{
    gaa_list_entry_ptr ent;
    if (checkdups == 0)
	return(0);
    for (ent = gaa_list_first(list); ent; ent = gaa_list_next(ent))
	if (checkdups(gaa_list_entry_value(ent), data) == 0)
	    return(1);
    return(0);
}
