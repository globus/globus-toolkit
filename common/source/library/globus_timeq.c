#include "globus_common_include.h"
#include "globus_timeq.h"
#include "globus_list.h"
#include "globus_libc.h"
#include "globus_error.h"

/******************************************************************
 *  macros to turn on and off memory management
 *****************************************************************/
#define __TIMEQ_USE_I_MEM 1

#if defined(__TIMEQ_USE_I_MEM)
#   define TIMEQ_MEM_INIT(TimeQ)                                        \
    {                                                                   \
           TimeQ->mem_initialized = GLOBUS_TRUE;                        \
           globus_memory_init(                                          \
               &TimeQ->mem,                                             \
               sizeof(globus_l_timeq_entry_t),                          \
               10);                                                     \
    }
#   define TIMEQ_MEM_DESTROY(TimeQ)                                     \
    {                                                                   \
           TimeQ->mem_initialized = GLOBUS_FALSE;                       \
           globus_memory_destroy(                                       \
               &TimeQ->mem);                                            \
    }
#   define MALLOC_TIMEQ_ENTRY(TimeQ)                                    \
        ((globus_l_timeq_entry_t *) globus_memory_pop_node(             \
                                        &TimeQ->mem))

#   define FREE_TIMEQ_ENTRY(TimeQ, ptr)                                 \
        (globus_memory_push_node(                                       \
             &TimeQ->mem,                                               \
             (globus_byte_t *)ptr))
#else
#   define TIMEQ_MEM_INIT(TimeQ)                                        \
    {}
#   define TIMEQ_MEM_DESTROY(TimeQ)                                     \
    {}
#   define MALLOC_TIMEQ_ENTRY(TimeQ)                                    \
       ((globus_l_timeq_entry_t *)globus_malloc(                        \
                                      sizeof(globus_l_timeq_entry_t)))
#   define  FREE_TIMEQ_ENTRY(TimeQ, ptr)                                \
       (globus_free(ptr))
#endif

/************************************************************************
 *  internal structure
 ***********************************************************************/
typedef struct globus_l_timeq_entry_s
{
    globus_abstime_t                            time;
    void *                                      datum;
} globus_l_timeq_entry_t;

typedef struct globus_timeq_s 
{
    globus_list_t * volatile                    head;
    globus_list_t * volatile                    tail;
#if defined(__TIMEQ_USE_I_MEM)
    globus_memory_t                             mem;
    globus_bool_t                               mem_initialized;
#endif
};

/************************************************************************
 *  functions
 ***********************************************************************/
globus_result_t
globus_timeq_init(
    globus_timeq_t *                            timeq)
{
    struct globus_timeq_s *                     s_timeq;
    
    if(timeq == GLOBUS_NULL)
    {
	    return globus_error_put(GLOBUS_ERROR_NO_INFO);
    }
    
    s_timeq = globus_malloc(sizeof(struct globus_timeq_s));
    *timeq = s_timeq;
    
    TIMEQ_MEM_INIT(s_timeq);

    s_timeq->head = GLOBUS_NULL;
    s_timeq->tail = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_timeq_destroy(
    globus_timeq_t *                            timeq)
{
    globus_list_t *                             head;
    void *                                      timeq_entry;
    struct globus_timeq_s *                     s_timeq;

    if(timeq == GLOBUS_NULL)
    {
	    return globus_error_put(GLOBUS_ERROR_NO_INFO);
    }
    
    s_timeq = *timeq;
    head = s_timeq->head;
	while (!globus_list_empty (head)) 
	{
	    timeq_entry = globus_list_remove(&head, head);
        FREE_TIMEQ_ENTRY(s_timeq, timeq_entry);
    }
	s_timeq->head = GLOBUS_NULL;
	s_timeq->tail = GLOBUS_NULL;
    
    TIMEQ_MEM_DESTROY(s_timeq);
    globus_free(s_timeq);
    
    return GLOBUS_SUCCESS;
}

globus_bool_t 
globus_timeq_empty(
    globus_timeq_t *                            timeq)
{
    struct globus_timeq_s *                     s_timeq;
    
    if(timeq == GLOBUS_NULL)
    {
        return GLOBUS_FALSE;
    }
    s_timeq = *timeq;
    if(s_timeq == GLOBUS_NULL)
    {
        return GLOBUS_FALSE;
    }

    return (s_timeq->head == GLOBUS_NULL);
}

int 
globus_timeq_size(
    globus_timeq_t *                            timeq)
{
    struct globus_timeq_s *                     s_timeq;
    
    assert(timeq != GLOBUS_NULL);
    
    s_timeq = *timeq;
    assert(s_timeq != GLOBUS_NULL);
    
    return globus_list_size(s_timeq->head);
}

/*
 *  the signature of this changed
 */
globus_result_t
globus_timeq_enqueue(
    globus_timeq_t *                            timeq,
    void *                                      datum,
    globus_abstime_t *                          insert_time)
{
    globus_list_t *                             i;
    globus_list_t *                             j;
    globus_l_timeq_entry_t *                    entry;
    globus_l_timeq_entry_t *                    tmp_entry;
    globus_bool_t                               found = GLOBUS_FALSE;
    struct globus_timeq_s *                     s_timeq;

    if(timeq == GLOBUS_NULL)
    {
	    return globus_error_put(GLOBUS_ERROR_NO_INFO);
    }
    s_timeq = *timeq;
    if(s_timeq == GLOBUS_NULL)
    {
	    return globus_error_put(GLOBUS_ERROR_NO_INFO);
    }
    
    /* create new entry */ 
    entry = MALLOC_TIMEQ_ENTRY(s_timeq);
    GlobusTimeAbstimeCopy(entry->time, *insert_time);
    entry->datum = datum;

    /* if queue empty insert in front */
    if(s_timeq->head == GLOBUS_NULL)
    {
	    globus_list_insert(&s_timeq->head, (void *) entry);
	    s_timeq->tail = s_timeq->head;
    }
    else
    {
        i = GLOBUS_NULL;
        j = s_timeq->head;
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
                    s_timeq->head = j;
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
                globus_list_insert(
                    (globus_list_t **) &i,
			        (void *)           entry);
            s_timeq->tail->next = i;
	        s_timeq->tail = i;
        }
    }
    return GLOBUS_SUCCESS;
}


void *
globus_timeq_remove(
    globus_timeq_t *                            timeq, 
    void *                                      datum)
{
    globus_list_t *                             i;
    globus_list_t *                             j;
    globus_bool_t                               found = GLOBUS_FALSE;
    globus_l_timeq_entry_t *                    entry;
    void *                                      rc;
    struct globus_timeq_s *                     s_timeq;

    assert(timeq != GLOBUS_NULL);
    s_timeq = *timeq;
    assert(s_timeq != GLOBUS_NULL);

    if(globus_list_empty(s_timeq->head))
    {
	    return GLOBUS_NULL;
    }
    
    i = GLOBUS_NULL;
    j = s_timeq->head;
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
	    if(j == s_timeq->tail)
	    {
	        s_timeq->tail = i;
        }
	    globus_list_remove(&s_timeq->head, j);
        FREE_TIMEQ_ENTRY(s_timeq, entry);
    }
    else
    {
	    rc = GLOBUS_NULL;
    }

    return rc;
}

void *
globus_timeq_dequeue(
    globus_timeq_t *                            timeq)
{
    void *                                      rc;
    globus_l_timeq_entry_t *                    entry;
    struct globus_timeq_s *                     s_timeq;

    assert(timeq != GLOBUS_NULL);
    s_timeq = *timeq;
    assert(s_timeq != GLOBUS_NULL);
    
    if(globus_list_empty(s_timeq->head))
    {
        return GLOBUS_NULL;
    }

    entry = (globus_l_timeq_entry_t *)
	       globus_list_remove (
	            &(s_timeq->head),
			    s_timeq->head);

    if(globus_list_empty(s_timeq->head))
    {
        s_timeq->tail = s_timeq->head;
    }

    rc = entry->datum;
    FREE_TIMEQ_ENTRY(s_timeq, entry);
    
    return rc;
}

void *
globus_timeq_first(
    globus_timeq_t *                            timeq)
{
    void *                                      rc;
    globus_l_timeq_entry_t *                    entry;
    struct globus_timeq_s *                     s_timeq;

    assert(timeq != GLOBUS_NULL);
    s_timeq = *timeq;
    assert(s_timeq != GLOBUS_NULL);
    
    if(globus_list_empty(s_timeq->head))
    {
        return GLOBUS_NULL;
    }

    entry = (globus_l_timeq_entry_t *)
	       globus_list_first(s_timeq->head);

    rc = entry->datum;
    return rc;
}

globus_abstime_t *
globus_timeq_first_time(
    globus_timeq_t *                            timeq)
{
    globus_l_timeq_entry_t *                    entry;
    struct globus_timeq_s *                     s_timeq;
    
    assert(timeq != GLOBUS_NULL);
    s_timeq = *timeq;
    assert(s_timeq != GLOBUS_NULL);
    
    if(globus_list_empty(s_timeq->head))
    {
        return GLOBUS_NULL;
    }

    entry = (globus_l_timeq_entry_t *)
	       globus_list_first(s_timeq->head);

    return &entry->time;
}

globus_abstime_t *
globus_timeq_time_at(
    globus_timeq_t *                            timeq,
    int                                         element_index)
{
    int                                         ctr;
    globus_l_timeq_entry_t *                    entry;
    globus_list_t *                             list;
    struct globus_timeq_s *                     s_timeq;
    
    assert(timeq != GLOBUS_NULL);
    s_timeq = *timeq;
    assert(s_timeq != GLOBUS_NULL);
    
    list = s_timeq->head;
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

