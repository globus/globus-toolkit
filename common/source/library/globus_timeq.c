#include "config.h"
#include "globus_common.h"

#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>

#include "globus_timeq.h"
#include "globus_list.h"

typedef struct globus_l_timeq_entry_s
{
    globus_abstime_t              time;
    void *                        datum;
} globus_l_timeq_entry_t;

#if defined(__TIMEQ_USE_I_MEM)

#   define TIMEQ_MEM_INIT(TimeQ)                                      \
    {                                                                 \
           TimeQ->mem_initialized = GLOBUS_TRUE;                      \
           globus_memory_init(                                      \
               &TimeQ->mem,                                           \
               sizeof(globus_l_timeq_entry_t),                        \
               10);                                                   \
    }

#   define TIMEQ_MEM_DESTROY(TimeQ)                                   \
    {                                                                 \
           TimeQ->mem_initialized = GLOBUS_FALSE;                     \
           globus_memory_destroy(                                   \
               &TimeQ->mem);                                          \
    }

#   define MALLOC_TIMEQ_ENTRY(TimeQ)                                  \
        ((globus_l_timeq_entry_t *) globus_memory_pop_node(         \
                                        &TimeQ->mem))

#   define FREE_TIMEQ_ENTRY(TimeQ, ptr)                               \
        (globus_memory_push_node(                                   \
             &TimeQ->mem,                                             \
             (globus_byte_t *)ptr))

#else

#   define TIMEQ_MEM_INIT(TimeQ)                                      \
    {}

#   define TIMEQ_MEM_DESTROY(TimeQ)                                   \
    {}

#   define MALLOC_TIMEQ_ENTRY(TimeQ)                                  \
       ((globus_l_timeq_entry_t *)globus_malloc(                      \
                                      sizeof(globus_l_timeq_entry_t)))

#   define  FREE_TIMEQ_ENTRY(TimeQ, ptr)                              \
       (globus_free(ptr))

#endif

int
globus_timeq_init(
    globus_timeq_t *                       timeq)
{
    TIMEQ_MEM_INIT(timeq);

    if(timeq == GLOBUS_NULL)
    {
	return GLOBUS_FAILURE;
    }

    timeq->head = GLOBUS_NULL;
    timeq->tail = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}

void
globus_timeq_destroy(
    globus_timeq_t *                           timeq)
{
    globus_list_t *            head;
    void *                     timeq_entry;

    if(timeq != GLOBUS_NULL)
    {
	head = timeq->head;
	while (!globus_list_empty (head)) 
	{
	    timeq_entry = globus_list_remove(&head, head);
            FREE_TIMEQ_ENTRY(timeq, timeq_entry);
        }
	timeq->head = GLOBUS_NULL;
	timeq->tail = GLOBUS_NULL;
    }
    
    TIMEQ_MEM_DESTROY(timeq);
}

globus_bool_t 
globus_timeq_empty(
    globus_timeq_t *                           timeq)
{
    if(timeq == GLOBUS_NULL)
    {
        return GLOBUS_FALSE;
    }

    return (timeq->head == GLOBUS_NULL);
}

int 
globus_timeq_size(
    globus_timeq_t *                           timeq)
{
    assert(timeq != GLOBUS_NULL);

    return globus_list_size(timeq->head);
}

int
globus_timeq_enqueue(
    globus_timeq_t *                           timeq,
    void *                                     datum,
    globus_abstime_t *                         insert_time)
{
    globus_list_t *                 i;
    globus_list_t *                 j;
    globus_l_timeq_entry_t *        entry;
    globus_l_timeq_entry_t *        tmp_entry;
    globus_bool_t                   found = GLOBUS_FALSE;

    if(timeq == GLOBUS_NULL)
    {
	return GLOBUS_FAILURE;
    }

   
    /* create new entry */ 
    entry = MALLOC_TIMEQ_ENTRY(timeq);
    GlobusTimeAbstimeCopy(entry->time, *insert_time);
    entry->datum = datum;

    /* if queue empty insert in front */
    if(timeq->head == GLOBUS_NULL)
    {
	globus_list_insert(&timeq->head, (void *) entry);
	timeq->tail = timeq->head;
    }
    else
    {
       i = GLOBUS_NULL;
       j = timeq->head;
       while(!globus_list_empty(j) && !found)
       {
           tmp_entry = (globus_l_timeq_entry_t *)
			  globus_list_first(j);
           if(globus_abstime_cmp(&tmp_entry->time, &entry->time) > 0)
	   {
               globus_list_insert((globus_list_t **) &j, (void *)entry);
	       /* if inserting at begining, repoint head */
	       if(i == GLOBUS_NULL)
	       {
                   timeq->head = j;
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
           timeq->tail->next = i;
	   timeq->tail = i;
       }
    }

    return GLOBUS_TRUE;
}

void *
globus_timeq_remove(
    globus_timeq_t *                           timeq, 
    void *                                     datum)
{
    globus_list_t *               i;
    globus_list_t *               j;
    globus_bool_t                 found = GLOBUS_FALSE;
    globus_l_timeq_entry_t *      entry;
    void *                        rc;

    assert(timeq != GLOBUS_NULL);

    if(globus_list_empty(timeq->head))
    {
	return GLOBUS_NULL;
    }

    i = GLOBUS_NULL;
    j = timeq->head;
    while(!globus_list_empty(j) && !found)
    {
        entry = (globus_l_timeq_entry_t *)
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
	if(j == timeq->tail)
	{
	    timeq->tail = i;
        }
	globus_list_remove(&timeq->head, j);
        FREE_TIMEQ_ENTRY(timeq, entry);
    }
    else
    {
	rc = GLOBUS_NULL;
    }

    return rc;
}

void *
globus_timeq_dequeue(
    globus_timeq_t *                           timeq)
{
    void *                        rc;
    globus_l_timeq_entry_t *      entry;

    assert(timeq != GLOBUS_NULL);

    if(globus_list_empty(timeq->head))
    {
        return GLOBUS_NULL;
    }

    entry = (globus_l_timeq_entry_t *)
	       globus_list_remove (&(timeq->head),
				   timeq->head);

    if(globus_list_empty(timeq->head))
    {
        timeq->tail = timeq->head;
    }

    rc = entry->datum;
    FREE_TIMEQ_ENTRY(timeq, entry);
    return rc;
}


void *
globus_timeq_first (globus_timeq_t *timeq)
{
    void *                        rc;
    globus_l_timeq_entry_t *      entry;

    assert(timeq != GLOBUS_NULL);

    if(globus_list_empty(timeq->head))
    {
        return GLOBUS_NULL;
    }

    entry = (globus_l_timeq_entry_t *)
	       globus_list_first(timeq->head);

    rc = entry->datum;
    return rc;
}

globus_abstime_t *
globus_timeq_first_time(globus_timeq_t *timeq)
{
    globus_l_timeq_entry_t *      entry;

    assert(timeq != GLOBUS_NULL);

    if(globus_list_empty(timeq->head))
    {
        return GLOBUS_NULL;
    }

    entry = (globus_l_timeq_entry_t *)
	       globus_list_first(timeq->head);

    return &entry->time;
}

globus_abstime_t *
globus_timeq_time_at(globus_timeq_t *  timeq,
		     int               element_index)
{
    int                           ctr;
    globus_l_timeq_entry_t *      entry;
    globus_list_t *               list;

    list = timeq->head;
    for(ctr = 0; ctr < element_index; ctr++)
    {
        if(list == GLOBUS_NULL)
	{
            return GLOBUS_NULL;
	}
	list = globus_list_rest(list);
    }
    
    entry = (globus_l_timeq_entry_t *)
	       globus_list_first(list);

    return &entry->time;
}

void
globus_i_timeq_dump(globus_timeq_t *timeq)
{
    globus_list_t  *                      i;
    void *                                v;

    i = timeq->head;

    while(!globus_list_empty(i))
    {
        v = globus_list_first(i);	
	globus_libc_printf("globus_i_timeq_dump() : 0x%p\n", v);
        i = globus_list_rest(i);
    }
}



