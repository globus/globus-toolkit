#include "globus_common_include.h"
#include "globus_priority_q.h"
#include "globus_list.h"
#include "globus_libc.h"

typedef struct globus_l_priority_q_entry_s
{
    void *                        priority;
    void *                        datum;
} globus_l_priority_q_entry_t;

#if defined(__PRIORITY_Q_USE_I_MEM)

#   define PRIORITY_Q_MEM_INIT(TimeQ)                                 \
    {                                                                 \
           TimeQ->mem_initialized = GLOBUS_TRUE;                      \
           globus_memory_init(                                      \
               &TimeQ->mem,                                           \
               sizeof(globus_l_priority_q_entry_t),                   \
               10);                                                   \
    }

#   define PRIORITY_Q_MEM_DESTROY(TimeQ)                              \
    {                                                                 \
           TimeQ->mem_initialized = GLOBUS_FALSE;                     \
           globus_memory_destroy(                                   \
               &TimeQ->mem);                                          \
    }

#   define MALLOC_PRIORITY_Q_ENTRY(TimeQ)                             \
        ((globus_l_priority_q_entry_t *) globus_memory_pop_node(    \
                                        &TimeQ->mem))

#   define FREE_PRIORITY_Q_ENTRY(TimeQ, ptr)                          \
        (globus_memory_push_node(                                   \
             &TimeQ->mem,                                             \
             (globus_byte_t *)ptr))

#else

#   define PRIORITY_Q_MEM_INIT(TimeQ)                                 \
    {}

#   define PRIORITY_Q_MEM_DESTROY(TimeQ)                              \
    {}

#   define MALLOC_PRIORITY_Q_ENTRY(TimeQ)                             \
       ((globus_l_priority_q_entry_t *)globus_malloc(                 \
                                      sizeof(globus_l_priority_q_entry_t)))

#   define  FREE_PRIORITY_Q_ENTRY(TimeQ, ptr)                         \
       (globus_free(ptr))

#endif

int
globus_priority_q_init(
    globus_priority_q_t *                       priority_q,
    globus_priority_q_cmp_func_t                cmp_func)
{
    PRIORITY_Q_MEM_INIT(priority_q);

    if(priority_q == GLOBUS_NULL)
    {
	return GLOBUS_FAILURE;
    }

    priority_q->head = GLOBUS_NULL;
    priority_q->tail = GLOBUS_NULL;
    priority_q->cmp_func = cmp_func;

    return GLOBUS_SUCCESS;
}

void
globus_priority_q_destroy(
    globus_priority_q_t *                           priority_q)
{
    globus_list_t *            head;
    void *                     priority_q_entry;

    if(priority_q != GLOBUS_NULL)
    {
	head = priority_q->head;
	while (!globus_list_empty (head)) 
	{
	    priority_q_entry = globus_list_remove(&head, head);
            FREE_PRIORITY_Q_ENTRY(priority_q, priority_q_entry);
        }
	priority_q->head = GLOBUS_NULL;
	priority_q->tail = GLOBUS_NULL;
    }
    
    PRIORITY_Q_MEM_DESTROY(priority_q);
}

globus_bool_t 
globus_priority_q_empty(
    globus_priority_q_t *                           priority_q)
{
    if(priority_q == GLOBUS_NULL)
    {
        return GLOBUS_FALSE;
    }

    return (priority_q->head == GLOBUS_NULL);
}

int 
globus_priority_q_size(
    globus_priority_q_t *                           priority_q)
{
    assert(priority_q != GLOBUS_NULL);

    return globus_list_size(priority_q->head);
}

int
globus_priority_q_enqueue(
    globus_priority_q_t *                           priority_q,
    void *                                          datum,
    void *                                          priority)
{
    globus_list_t *                      i;
    globus_list_t *                      j;
    globus_l_priority_q_entry_t *        entry;
    globus_l_priority_q_entry_t *        tmp_entry;
    globus_bool_t                        found = GLOBUS_FALSE;

    if(priority_q == GLOBUS_NULL)
    {
	return GLOBUS_FAILURE;
    }

   
    /* create new entry */ 
    entry = MALLOC_PRIORITY_Q_ENTRY(priority_q);

    entry->priority = priority;
    entry->datum = datum;

    /* if queue empty insert in front */
    if(priority_q->head == GLOBUS_NULL)
    {
	globus_list_insert(&priority_q->head, (void *) entry);
	priority_q->tail = priority_q->head;
    }
    else
    {
       i = GLOBUS_NULL;
       j = priority_q->head;
       while(!globus_list_empty(j) && !found)
       {
           tmp_entry = (globus_l_priority_q_entry_t *)
			  globus_list_first(j);
           if(priority_q->cmp_func(
                  &tmp_entry->priority,
                  &entry->priority) > 0)
	   {
               globus_list_insert((globus_list_t **) &j, (void *)entry);
	       /* if inserting at begining, repoint head */
	       if(i == GLOBUS_NULL)
	       {
                   priority_q->head = j;
	       }
	       /* otherwise insert new list after old beginning */
	       else
	       {
                   i->next = j;
	       }
	       found = GLOBUS_TRUE;
	   }

	   /* advance pointers */
	   i = j;
	   j = globus_list_rest(j);
       }

       /*if not found place at end */
       if(!found)
       {
	   i = GLOBUS_NULL;
           globus_list_insert((globus_list_t **) &i,
			      (void *)           entry);
           priority_q->tail->next = i;
	   priority_q->tail = i;
       }
    }

    return GLOBUS_TRUE;
}

void *
globus_priority_q_remove(
    globus_priority_q_t *                           priority_q, 
    void *                                          datum)
{
    globus_list_t *                    i;
    globus_list_t *                    j;
    globus_bool_t                      found = GLOBUS_FALSE;
    globus_l_priority_q_entry_t *      entry;
    void *                        rc;

    assert(priority_q != GLOBUS_NULL);

    if(globus_list_empty(priority_q->head))
    {
	return GLOBUS_NULL;
    }

    i = GLOBUS_NULL;
    j = priority_q->head;
    while(!globus_list_empty(j) && !found)
    {
        entry = (globus_l_priority_q_entry_t *)
		   globus_list_first(j);
        if(entry->datum == datum)
	{
            found = GLOBUS_TRUE;
	}
	else
	{
            i = j;
	    j = globus_list_rest(j);
	}
    }

    if(found)
    {
        rc = entry->datum;
	if(j == priority_q->tail)
	{
	    priority_q->tail = i;
        }
	globus_list_remove(&priority_q->head, j);
        FREE_PRIORITY_Q_ENTRY(priority_q, entry);
    }
    else
    {
	rc = GLOBUS_NULL;
    }

    return rc;
}

void *
globus_priority_q_dequeue(
    globus_priority_q_t *                           priority_q)
{
    void *                        rc;
    globus_l_priority_q_entry_t *      entry;

    assert(priority_q != GLOBUS_NULL);

    if(globus_list_empty(priority_q->head))
    {
        return GLOBUS_NULL;
    }

    entry = (globus_l_priority_q_entry_t *)
	       globus_list_remove (&(priority_q->head),
				   priority_q->head);

    if(globus_list_empty(priority_q->head))
    {
        priority_q->tail = priority_q->head;
    }

    rc = entry->datum;
    FREE_PRIORITY_Q_ENTRY(priority_q, entry);
    return rc;
}


void *
globus_priority_q_first (
    globus_priority_q_t *                     priority_q)
{
    void *                                    rc;
    globus_l_priority_q_entry_t *             entry;

    assert(priority_q != GLOBUS_NULL);

    if(globus_list_empty(priority_q->head))
    {
        return GLOBUS_NULL;
    }

    entry = (globus_l_priority_q_entry_t *)
	       globus_list_first(priority_q->head);

    rc = entry->datum;
    return rc;
}

void *
globus_priority_q_first_priority(
    globus_priority_q_t *                         priority_q)
{
    globus_l_priority_q_entry_t *                 entry;

    assert(priority_q != GLOBUS_NULL);

    if(globus_list_empty(priority_q->head))
    {
        return GLOBUS_NULL;
    }

    entry = (globus_l_priority_q_entry_t *)
	       globus_list_first(priority_q->head);

    return &entry->priority;
}

void *
globus_priority_q_priority_at(
    globus_priority_q_t *                        priority_q,
    int                                          element_index)
{
    int                                          ctr;
    globus_l_priority_q_entry_t *                entry;
    globus_list_t *               list;

    list = priority_q->head;
    for(ctr = 0; ctr < element_index; ctr++)
    {
        if(list == GLOBUS_NULL)
	{
            return GLOBUS_NULL;
	}
	list = globus_list_rest(list);
    }
    
    entry = (globus_l_priority_q_entry_t *)
	       globus_list_first(list);

    return &entry->priority;
}


int 
globus_priority_q_fifo_cmp_func(
    void *                                    priority_1,
    void *                                    priority_2)
{
    return -1;
}


