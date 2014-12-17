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
 * @file globus_list.c
 * @brief Linked List Implementation
 */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#include "globus_common_include.h"
#include "globus_list.h"
#include "globus_memory.h"
#include "globus_libc.h"

#define GLOBUS_L_LIST_INIT_MEM_COUNT            512

#define _MEMORY_USE_INTERNAL_MEM 1

#ifdef  _MEMORY_USE_INTERNAL_MEM
    static globus_memory_t                globus_l_memory_list_info;

#   define MALLOC_LIST_T()                                                  \
        ((globus_list_t *)                                                  \
             globus_memory_pop_node(&globus_l_memory_list_info))
#   define FREE_LIST_T(ptr)                                                 \
        (globus_memory_push_node(                                           \
                                  &globus_l_memory_list_info,               \
                                  (globus_byte_t *)ptr))
#else
#   define MALLOC_LIST_T()                                                  \
        ((globus_list_t *)                                                  \
            globus_malloc(sizeof(globus_list_t)))
#   define FREE_LIST_T(ptr)                                                 \
        (globus_free(ptr))
#endif

static globus_bool_t                            globus_l_list_active = GLOBUS_FALSE;
/*
 * needs to be called by thread
 */
int
globus_i_list_pre_activate(void)
{
    if(!globus_l_list_active)
    {
        globus_l_list_active = GLOBUS_TRUE;
#       if defined(_MEMORY_USE_INTERNAL_MEM)
        {
            globus_memory_init(
                &globus_l_memory_list_info,
                sizeof(globus_list_t),
                GLOBUS_L_LIST_INIT_MEM_COUNT);
        }
#       endif
    }
    return GLOBUS_SUCCESS;
}

int
globus_list_int_less (
    void * low_datum, 
    void * high_datum,
    void *ignored)
{
    return (low_datum) < (high_datum);
}

/**
 * @brief Retrieve head datum
 * @ingroup globus_list
 * @details
 * The accessor globus_list_first() returns the datum at the head of the list;
 * this datum is the one provided to the globus_list_cons() call that
 * constructed the head of the list.
 *
 * It is an error to call this routine on the empty list.
 * @param head
 *     List to retrieve from
 * @return The list datum.
 */
void *
globus_list_first(
    globus_list_t * head)
{
    assert (head != GLOBUS_NULL);
    return (void *) head->datum;
}

/**
 * @brief Get the remainder of the list
 * @ingroup globus_list
 * @details
 * The accessor globus_list_rest() returns the remainder of the list elements,
 * containing all data except the datum returned by globus_list_first().
 *
 * It is an error to call this routine on the empty list.
 * @param head
 *     Head of the list
 * @return Remainder of the list
 */
globus_list_t *
globus_list_rest(
    globus_list_t * head)
{
    assert (head != GLOBUS_NULL);
    return (globus_list_t *) head->next;
}

globus_list_t **
globus_list_rest_ref(
    globus_list_t * head)
{
    assert (head != GLOBUS_NULL);
    return (globus_list_t **) &(head->next);
}

/**
 * @brief List empty predicate
 * @ingroup globus_list
 * @details
 * The predicate globus_list_empty returns non-zero if list==NULL, otherwise
 * returns 0.
 */
int 
globus_list_empty(
    globus_list_t * head)
{
    return head == GLOBUS_NULL;
}

/**
 * @brief Get the number of elements in a list
 * @ingroup globus_list
 * @details
 * The routine globus_list_size() computes and returns the total number of data
 * contained in the list. An empty list has zero elements.
 * @param head
 *     Head of the list
 * @return Number of data items in the list
 */
int 
globus_list_size(
    globus_list_t *head)
{
    globus_list_t *                         list;
    int                                     size = 0;

    for(list = head;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        size++;
    }

    return size;
}

globus_list_t *
globus_list_concat(
    globus_list_t *                     front_list,
    globus_list_t *                     back_list)
{
    globus_list_t *                     front_copy = NULL;
    globus_list_t *                     back_copy = NULL;
    globus_list_t *                     list;

    back_copy = globus_list_copy(back_list);

    if(front_list == NULL)
    {
        return back_copy;
    }
    front_copy = globus_list_copy(front_list);
    for(list = front_copy; list->next != NULL; list = list->next);
    list->next = back_copy;

    return front_copy;
}

/* return the old datum value */
/**
 * @brief Replace first datum
 * @ingroup globus_list
 * @details
 * The mutator globus_list_replace_first() returns the datum at the head of the
 * list and modifies the list to contain the provided datum instead.
 *
 * It is an error to call this routine on the empty list (NULL).
 * @param head
 *     List to modify
 * @param datum
 *     New datum
 * @return The old value of the first datum in the list.
 */
void *
globus_list_replace_first(
    globus_list_t * head, 
    void *datum)
{
    void *old_datum;
    assert (head != GLOBUS_NULL);
    old_datum = head->datum;
    head->datum = datum;
    return old_datum;
}

/**
 * @brief Search a list for a datum
 * @ingroup globus_list
 * @details
 * The routine globus_list_search() traverses the elements in list until a
 * sub-list is found with datum as the first element. If such a sub-list is
 * found, it is returned, otherwise the empty list  is returned.
 * @param head
 *     Head of the list to search
 * @param datum
 *     Datum to search for in the list
 * @return The first list node found which contains the datum, or NULL if not
 * found.
 */
globus_list_t *
globus_list_search (
    globus_list_t *head, 
    void *datum)
{
    globus_list_t *                         list;
    void *                                  td;

    if(globus_list_empty(head))
    {
        return GLOBUS_NULL;
    }

    for(list = head; 
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        td = globus_list_first(list);
        if(td == datum)
        {
            return list;
        }
    }

    return GLOBUS_NULL;
}

/**
 * @brief Search a list with a predicate
 * @ingroup globus_list
 * @details
 * The routine globus_list_search_pred() traverses the elements in list until a
 * sub-list is found with datum as the first element such that predicate
 * (datum, pred_args) evaluates TRUE. If such a sub-list is found, it is
 * returned, otherwise the empty list is returned.
 *
 * It is an error to provide a predicate value of NULL.
 * @param head
 *     List to search
 * @param predicate
 *     Predicate function
 * @param pred_args
 *     Parameter to pass to the predicate function
 */
globus_list_t *
globus_list_search_pred(
    globus_list_t *head, 
    globus_list_pred_t predicate,
    void *pred_args)
{
  if (globus_list_empty (head)) {
    /* end of list chain */
    return GLOBUS_NULL;
  }
  else if ((*predicate) (globus_list_first (head), pred_args)) {
    /* found list binding */
    return head;
  }
  else {
    /* check rest of chain */
    return globus_list_search_pred (globus_list_rest (head), predicate, pred_args);
  }
}

static globus_list_t *
s_globus_list_min_with_register(
    globus_list_t *current_min,
	globus_list_t *rest_head,
	globus_list_relation_t relation,
	void *relation_args)
{
    if (globus_list_empty (rest_head)) 
    {
        return current_min;
    }
    else if((*relation) (globus_list_first(current_min), 
			 globus_list_first(rest_head),
			 relation_args) ) 
    {
        return s_globus_list_min_with_register (current_min,
				     globus_list_rest (rest_head),
				     relation,
				     relation_args);
    }
    else 
    {
        return s_globus_list_min_with_register (rest_head,
				     globus_list_rest (rest_head),
				     relation,
				     relation_args);
    }
}

/**
 * @brief Find the minimum value of a list
 * @ingroup globus_list
 * @details
 * The globus_list_min() routine traverses the list and returns the first
 * minimum valued datum, as determined by the order defined by the given
 * relation.
 * @param head
 *     List to search
 * @param relation
 *     Relation predicate
 * @param relation_args
 *     Argument passed to the relation
 * @return This routine returns a list node whose first node is the minimum
 * of the values in the original list to search, or NULL of the list was empty.
 */
globus_list_t *
globus_list_min(
    globus_list_t *head,
    globus_list_relation_t relation,
    void *relation_args)
{
    if (globus_list_empty (head)) 
    {
        return GLOBUS_NULL;
    }
    else 
    {
        return s_globus_list_min_with_register (head,
				     globus_list_rest(head),
				     relation,
				     relation_args);
    }
}

void
globus_list_halves_destructive (
    globus_list_t  * head,
	globus_list_t * volatile * leftp,
	globus_list_t * volatile * rightp)
{
    int len;
    int i;

    assert (leftp!=GLOBUS_NULL);
    assert (rightp!=GLOBUS_NULL);
  
    len = globus_list_size (head);
  
    *leftp = head;

    for (i=0; i<(len/2 - 1); i++) 
    {
        head = globus_list_rest (head);
    }

    *rightp = globus_list_rest (head);

    *(globus_list_rest_ref (head)) = GLOBUS_NULL;
}

globus_list_t *
globus_list_sort_merge_destructive(
    globus_list_t * left,
	globus_list_t * right,
	globus_list_relation_t relation,
	void *relation_args)
{
    globus_list_t  * result = GLOBUS_NULL;
    globus_list_t ** result_tail = GLOBUS_NULL;

    while ( (! globus_list_empty (left))
	      && (! globus_list_empty (right)) ) 
    {
        if ( relation (globus_list_first (left),
		   globus_list_first (right),
		   relation_args) ) 
        {
            if ( result_tail ) *result_tail = left;
            else result = left;
      
            result_tail = globus_list_rest_ref (left);
            left = globus_list_rest (left);
            *result_tail = GLOBUS_NULL;
        }
        else 
        {
            if ( result_tail ) *result_tail = right;
            else result = right;
            result_tail = globus_list_rest_ref (right);
            right = globus_list_rest (right);
            *result_tail = GLOBUS_NULL;
        }
    }

    if ( globus_list_empty (left) ) 
    {
        if ( result_tail ) *result_tail = right;
        else result = right;
    }
    else 
    {
        assert ( globus_list_empty (right) );
        if ( result_tail ) *result_tail = left;
        else result = left;
    }

    return result;
}

globus_list_t *
globus_list_sort_destructive (
    globus_list_t *                         head,
	globus_list_relation_t                  relation,
	void *                                  relation_args)
{
    globus_list_t *                         left;
    globus_list_t *                         right;

    if ( globus_list_empty (head) 
       || globus_list_empty (globus_list_rest (head))) 
    {
        return head;
    }

    globus_list_halves_destructive (head, &left, &right);

    return globus_list_sort_merge_destructive (
			     globus_list_sort_destructive (left,
							   relation,
							   relation_args),
			     globus_list_sort_destructive (right,
							   relation,
							   relation_args),
			     relation,
			     relation_args);
}

/**
 * @brief Sort a list
 * @ingroup globus_list
 * @details
 * The globus_list_sort() routine returns a new copy of the list where the
 * elements have been reordered to satisfy the provided relation, or returns
 * NULL if the list cannot be created. This sort is currently implemented as a
 * fast merge sort.
 * @param head
 *     List to sort
 * @param relation
 *     Predicate relation to use for the sort
 * @param relation_args
 *     Parameter to relation
 * @return This routine returns a new list whose data items are the same as the
 * old list. The list must be freed with globus_list_free().
 */
globus_list_t *
globus_list_sort (globus_list_t *head,
		  globus_list_relation_t relation,
		  void *relation_args)
{
    return globus_list_sort_destructive (globus_list_copy (head),
				       relation,
				       relation_args);
}

/**
 * @brief Insert an item in a list
 * @ingroup globus_list
 * @details
 * The constructor globus_list_insert() mutates the list reference headp in
 * place to contain a newly allocated list node holding datum and using the
 * original value named by the list reference as the remainder of the list.
 * 
 * All list nodes constructed by globus_list_cons should eventually be
 * destroyed using globus_list_remove or globus_list_free.
 * @param headp
 *     List reference to insert into.
 * @param datum
 *     Datum to add to the list.
 * @return This routine returns zero on success, or non-zero on failure.
 */
int 
globus_list_insert (
    globus_list_t * volatile *              headp, 
    void *                                  datum)
{
    globus_bool_t                        mal;
    globus_list_t *                      entry;

    mal = !globus_l_list_active;

    if(mal)
    {
        entry = globus_malloc(sizeof(globus_list_t));
        entry->malloced = mal;
    }
    else
    {
        entry = MALLOC_LIST_T();
        entry->malloced = mal;
    }
    entry->datum = datum;
    entry->next = *headp;

    *headp = entry;

    return 0;
}

/**
 * @brief List constructor
 * @ingroup globus_list
 * @details
 * The constructor globus_list_cons() returns a freshly allocated list node
 * initialized to contain datum and to refer to rest as the remainder of the
 * new list, or returns NULL if a new node could not be allocated.
 *
 * All list nodes constructed by globus_list_cons() should eventually be
 * destroyed using globus_list_remove() or globus_list_free().
 * @param datum
 *     Item to add to the list
 * @param rest
 *     List to set as the remainder of the new list.
 * @return List node.
 */
globus_list_t *
globus_list_cons (void * datum, globus_list_t * rest)
{
    int err;

    err = globus_list_insert (&rest, datum);
    if(err) 
    {
        return NULL;
    }

    return rest;
}

/**
 * @brief Copy constructor
 * @ingroup globus_list
 * @details
 * The globus_list_copy() constructor creates a newly allocated list containing
 * the same data as the source list.
 *
 * All list nodes constructed by globus_list_copy should eventually be
 * destroyed using globus_list_remove() or globus_list_free().
 *
 * @param head
 *     List to copy
 * 
 * @return Copy of the list
 */
globus_list_t *
globus_list_copy (globus_list_t *head)
{
    globus_list_t *                     entry;
    globus_bool_t                       mal;

    mal = !globus_l_list_active;
    if (head!=GLOBUS_NULL) 
    {
        if(mal)
        {
            entry = globus_malloc(sizeof(globus_list_t));
            entry->malloced = mal;
        }
        else
        {
            entry = MALLOC_LIST_T();
            entry->malloced = mal;
        }
        entry->datum = head->datum;
        entry->next = globus_list_copy (head->next);

        return entry;
    }
    else 
    {
        return GLOBUS_NULL;
    }
}

/**
 * @brief Remove a datum from a list
 * @ingroup globus_list
 * @details
 * The globus_list_remove() routine searches a list provided by reference,
 * mutating the list in place to remove the specified entry and deallocate its
 * resources. If the entry is found, it is removed and its datum is returned;
 * if the entry is not found no effects are done and NULL is returned.
 * @param headp
 *     Reference to the head of the list
 * @param entry
 *     List entry to remove from the list
 * @return Either the datum which is removed from the list, or NULL if it
 * isn't present.
 */
void *
globus_list_remove(
    globus_list_t * volatile *              headp, 
    globus_list_t *                         entry)
{
    globus_list_t *                         i;
    globus_list_t *                         j;
    void *                                  datum;

    assert (headp);
    assert (entry);
    
    datum = globus_list_first (entry);
    if(*headp == entry)
    {
        *headp = globus_list_rest(*headp);
        if(entry->malloced)
        {
            globus_free(entry);
        }
        else
        {
            FREE_LIST_T(entry);
        }
        return datum;
    }

    i = *headp;
    j = globus_list_rest(i);
    while(!globus_list_empty(j))
    {
        if(entry == j)
        {
            j = globus_list_rest(j);
            i->next = j;
            if(entry->malloced)
            {
                globus_free(entry);
            }
            else
            {
                FREE_LIST_T(entry);
            }
            return datum;
        }
        i = globus_list_rest(i);
        j = globus_list_rest(j);
    }

    return GLOBUS_NULL;
}

/**
 * @brief Free a list
 * @ingroup globus_list
 * @details
 * The globus_list_free() routine deallocates an entire list, abandoning its
 * data.
 * @param head
 *     Head of the list to free
 */
void
globus_list_free (globus_list_t *head)
{
    while (! globus_list_empty (head)) 
    {
        globus_list_remove (&head, head);
    }
}


void globus_list_destroy_all(
    globus_list_t *                     head,
    void                                (*data_free)(void *))
{
    void *                              data;
    
    while (! globus_list_empty (head)) 
    {
        if((data = globus_list_remove (&head, head)) != NULL)
        {
            data_free(data);
        }
    }

    return;
}

globus_list_t * 
globus_list_from_string(
    const char *                        in_string,
    int                                 delim,
    const char *                        ignored)
{
    globus_list_t *                     list = NULL;
    char *                              string;
    char *                              entry;
    char *                              ptr;

    if(in_string == NULL)
    {
        goto error_params;
    }

    string = globus_libc_strdup(in_string);
    if(string != NULL)
    {
        entry = string;
        while((ptr = strchr(entry, delim)) != NULL)
        {
            *ptr = '\0';
            if(ignored != NULL)
            {
                while(*entry && strchr(ignored, *entry) != NULL)
                {
                    entry++;
                }
            }
            globus_list_insert(&list, globus_libc_strdup(entry)); 
            entry = ptr + 1;
        }
        if(ptr == NULL && *entry != '\0')
        {
            globus_list_insert(&list, globus_libc_strdup(entry)); 
        }               
        globus_free(string);     
    }
    
    return list;
    
error_params:
    return NULL;
}


