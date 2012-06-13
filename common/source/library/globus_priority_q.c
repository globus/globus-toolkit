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

#include "globus_priority_q.h"
#include "globus_libc.h"

#define GLOBUS_L_PRIORITY_Q_CHUNK_SIZE 100

/* you can't change this, it is just more descriptive than '1' */
#define GLOBUS_L_PRIORITY_Q_TOP_SLOT 1

typedef struct globus_l_priority_q_entry_s
{
    void *                              priority;
    void *                              datum;
} globus_l_priority_q_entry_t;

static
int
globus_l_priority_q_percolate_up(
    globus_priority_q_t *               priority_q,
    int                                 hole,
    void *                              priority)
{
    globus_l_priority_q_entry_t **      heap;
    globus_priority_q_cmp_func_t        cmp_func;

    heap = priority_q->heap;
    cmp_func = priority_q->cmp_func;

    while(hole > GLOBUS_L_PRIORITY_Q_TOP_SLOT && 
        cmp_func(heap[hole / 2]->priority, priority) > 0)
    {
        heap[hole] = heap[hole / 2];
        hole /= 2;
    }
    
    return hole;
}

static
int
globus_l_priority_q_percolate_down(
    globus_priority_q_t *               priority_q,
    int                                 hole,
    void *                              priority)
{
    globus_l_priority_q_entry_t **      heap;
    globus_priority_q_cmp_func_t        cmp_func;
    int                                 last_slot;
    int                                 child;

    heap = priority_q->heap;
    cmp_func = priority_q->cmp_func;
    last_slot = priority_q->next_slot - 1;

    child = hole * 2;
    while(child <= last_slot)
    {
        if(child != last_slot && 
            cmp_func(heap[child]->priority, heap[child + 1]->priority) > 0)
        {
            child++;
        }

        if(cmp_func(priority, heap[child]->priority) > 0)
        {
            heap[hole] = heap[child];
            hole = child;
            child = hole * 2;
        }
        else
        {
            break;
        }
    }

    return hole;
}

/**
 * @brief Initialize a priority queue
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_init() function initializes a globus_priority_q_t structure
 * for use with the other functions in the
 * @link globus_priority_q Priority Queue @endlink module. If this function returns
 * GLOBUS_SUCCESS, the caller is responsible for deallocating the members of this
 * structure when it is no longer needed by passing it to
 * globus_priority_q_destroy().
 *
 * @param priority_q
 *     Pointer to the priority queue structure to initialize.
 * @param cmp_func
 *     Pointer to a function which computes the relative relationship between two
 *     priorities. See the documentation of #globus_priority_q_cmp_func_t for 
 *     details on how to implement that function.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_FAILURE
 *     Failure
 */
int
globus_priority_q_init(
    globus_priority_q_t *               priority_q,
    globus_priority_q_cmp_func_t        cmp_func)
{
    globus_bool_t                       result;
    
    if(!priority_q)
    {
        return GLOBUS_FAILURE;
    }
    
    priority_q->heap = (globus_l_priority_q_entry_t **)
        globus_libc_malloc(
            GLOBUS_L_PRIORITY_Q_CHUNK_SIZE * 
                sizeof(globus_l_priority_q_entry_t *));
    if(!priority_q->heap)
    {
        return GLOBUS_FAILURE;
    }
    
    result = globus_memory_init(
        &priority_q->memory,
        sizeof(globus_l_priority_q_entry_t),
        GLOBUS_L_PRIORITY_Q_CHUNK_SIZE);                                    

    if(result != GLOBUS_TRUE)
    {
        globus_libc_free(priority_q->heap);
        return GLOBUS_FAILURE;
    }
    
    priority_q->next_slot = GLOBUS_L_PRIORITY_Q_TOP_SLOT;
    priority_q->max_len = GLOBUS_L_PRIORITY_Q_CHUNK_SIZE;
    priority_q->cmp_func = cmp_func;

    return GLOBUS_SUCCESS;
}
/* globus_priority_q_init() */

/**
 * @brief Destroy a Priority Queue
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_destroy() function destroys the contents of a priority
 * queue. After this function returns, the structure pointed to by priority_q is
 * invalid and must not be passed to any functions in the
 * @link globus_priority_q Priority Queue @endlink module other
 * globus_priority_q_init().
 *
 * Note that this function does not call any destructors for the data inserted
 * into the priority queue, so the caller must be sure to either have other
 * references to those data or free them before calling this function.
 *
 * @param priority_q
 *     Pointer to the priority_q to destroy.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_FAILURE
 *     Failure
 */
int
globus_priority_q_destroy(
    globus_priority_q_t *               priority_q)
{
    int                                 i;
    globus_l_priority_q_entry_t **      heap;
    
    if(!priority_q)
    {
        return GLOBUS_FAILURE;
    }
    
    i = priority_q->next_slot - GLOBUS_L_PRIORITY_Q_TOP_SLOT;
    heap = priority_q->heap + GLOBUS_L_PRIORITY_Q_TOP_SLOT;
    while(i--)
    {
        globus_memory_push_node(&priority_q->memory, (globus_byte_t *) heap[i]);
    }
    
    globus_libc_free(priority_q->heap);
    globus_memory_destroy(&priority_q->memory);
    
    return GLOBUS_SUCCESS;
}
/* globus_priority_q_destroy() */

/**
 * @brief Priority Queue Empty Predicate
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_empty() function checks the given priority queue to determine
 * if it is empty. It is considered empty if it has been initialized via
 * globus_priority_q_init() and there are no items which have been inserted via
 * globus_priority_q_enqueue() which have not been removed by calling
 * globus_priority_q_remove() or globus_priority_q_dequeue(). If it is empty, this function
 * returns GLOBUS_TRUE; otherwise it returns GLOBUS_FALSE.
 * 
 * @param priority_q
 *     Pointer to the priority queue to check
 *
 * @retval GLOBUS_TRUE
 *     The priority queue is empty
 * @retval GLOBUS_FALSE
 *     The priority queue is not empty, or the priority queue is invalid
 */
globus_bool_t
globus_priority_q_empty(
    globus_priority_q_t *               priority_q)
{
    if(!priority_q)
    {
        return GLOBUS_FALSE;
    }

    return (priority_q->next_slot == GLOBUS_L_PRIORITY_Q_TOP_SLOT);
}
/* globus_priority_q_empty() */

/**
 * @brief Priority Queue Size
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_size() function returns the size of the priority queue,
 * that is, the number of elements that are currently enqueued in it. The special
 * value GLOBUS_FAILURE is returned if a null pointer is passed to this function.
 *
 * @param priority_q
 *     Pointer to the priority queue to check
 *
 * @return This function returns the number of elements in the queue, or GLOBUS_FAILURE
 * if the priority_q pointer is invalid.
 */
int
globus_priority_q_size(
    globus_priority_q_t *               priority_q)
{
    if(!priority_q)
    {
        return GLOBUS_FAILURE;
    }
    
    return priority_q->next_slot - GLOBUS_L_PRIORITY_Q_TOP_SLOT;
}
/* globus_priority_q_size() */

/**
 * @brief Add a Datum to a Priority Queue
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_enqueue() function inserts a datum into the priority queue
 * based on its priority. When an item is inserted, the pointers to both the datum and
 * the priority are copied into the priority_q data structure, so neither may be
 * freed until the datum is removed from the priority queue, or undefined behavior may
 * occur.
 *
 * Note that there is no fifo fallback for priorities, so the order of two
 * items with equivalent priorities is not specified relative to each other. To enable
 * fifo fallback, use a compound priority that includes a priority level and a sequence
 * number as the value pointed to by the priority parameter and pass a suitable comparison
 * function to initialize the priority queue.
 *
 * @param priority_q
 *     Pointer to the priority queue to insert datum into
 * @param datum
 *     The datum to insert into the queue
 * @param priority
 *     The priority of the datum
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_FAILURE
 *     Failure
 */
int
globus_priority_q_enqueue(
    globus_priority_q_t *               priority_q,
    void *                              datum,
    void *                              priority)
{
    globus_l_priority_q_entry_t **      heap;
    globus_l_priority_q_entry_t *       new_entry;
    int                                 hole;
    
    if(!priority_q)
    {
        return GLOBUS_FAILURE;
    }
    
    /* make sure we have room */
    if(priority_q->next_slot == priority_q->max_len)
    {
        heap = (globus_l_priority_q_entry_t **)
            globus_libc_realloc(
                priority_q->heap,
                (priority_q->max_len + GLOBUS_L_PRIORITY_Q_CHUNK_SIZE) * 
                    sizeof(globus_l_priority_q_entry_t *));
        if(!heap)
        {
            return GLOBUS_FAILURE;
        }

        priority_q->heap = heap;
        priority_q->max_len += GLOBUS_L_PRIORITY_Q_CHUNK_SIZE;
    }

    /* allocate a new entry */
    new_entry = (globus_l_priority_q_entry_t *) 
        globus_memory_pop_node(&priority_q->memory);
    if(!new_entry)
    {
        return GLOBUS_FAILURE;
    }
    new_entry->datum = datum;
    new_entry->priority = priority;
    
    /* set new entry at next_slot and percolate up */
    hole = globus_l_priority_q_percolate_up(
        priority_q, priority_q->next_slot++, priority);
    
    priority_q->heap[hole] = new_entry;

    return GLOBUS_SUCCESS;
}
/* globus_priority_q_enqueue() */

/**
 * @brief Remove a Datum From A Priority Queue
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_dequeue() function removes the highest-priority datum from the
 * given priority queue and returns it. If the priority_q pointer is NULL or the priority
 * queue is empty, this function returns NULL.
 *
 * @param priority_q
 *     Pointer to the priority queue to remove from.
 *
 * @return
 *     This function returns the highest-priority datum from the priority queue.
 */
void *
globus_priority_q_dequeue(
    globus_priority_q_t *               priority_q)
{
    globus_l_priority_q_entry_t *       entry;
    void *                              datum;
    int                                 hole;
    
    if(!priority_q || priority_q->next_slot == GLOBUS_L_PRIORITY_Q_TOP_SLOT)
    {
        return GLOBUS_NULL;
    }

    /* remove first element and save user's data */
    entry = priority_q->heap[GLOBUS_L_PRIORITY_Q_TOP_SLOT];
    datum = entry->datum;
    globus_memory_push_node(&priority_q->memory, (globus_byte_t *) entry);

    /* take last element and percolate down */
    if(--priority_q->next_slot > GLOBUS_L_PRIORITY_Q_TOP_SLOT)
    {
        entry = priority_q->heap[priority_q->next_slot];
        
        hole = globus_l_priority_q_percolate_down(
            priority_q, GLOBUS_L_PRIORITY_Q_TOP_SLOT, entry->priority);
        
        priority_q->heap[hole] = entry;
    }
    
    return datum;
}
/* globus_priority_q_dequeue() */

/**
 * @brief Get the Highest-Priority Datum From a Priority Queue
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_first() function returns the highest-priority datum from the
 * priority queue pointed to by priority_q. The datum is not removed from the queue; to
 * do that, use globus_priority_q_dequeue() instead. If the priority_q pointer is NULL
 * or the queue is empty, this function returns NULL. The priority queue retains a reference
 * to the returned datum, so the pointer value returned must not freed until the datum
 * is removed from the queue.
 *
 * @param priority_q
 *     Pointer to the priority queue to inspect
 * @return
 *     This function returns the highest-priority datum from the priority queue.
 */
void *
globus_priority_q_first (
    globus_priority_q_t *               priority_q)
{
    globus_l_priority_q_entry_t *       entry;

    if(!priority_q || priority_q->next_slot == GLOBUS_L_PRIORITY_Q_TOP_SLOT)
    {
        return GLOBUS_NULL;
    }
    
    entry = priority_q->heap[GLOBUS_L_PRIORITY_Q_TOP_SLOT];

    return entry->datum;
}
/* globus_priority_q_first () */

/**
 * @brief Get the Highest Priority in Priority Queue
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_first_priority() function returns the value of highest priority
 * in the priority queue (not the datum associated with that priority). If the priority_q
 * pointer is NULL or empty, this function returns NULL. The priority queue
 * retains a reference to the returned priority, so the pointer value returned must not
 * be freed until the datum associated with it is removed from the queue.
 *
 * @param priority_q
 *     Pointer to the priority queue to inspect
 * @return
 *     This function returns the highest priority value in the priority queue.
 */
void *
globus_priority_q_first_priority(
    globus_priority_q_t *               priority_q)
{
    globus_l_priority_q_entry_t *       entry;

    if(!priority_q || priority_q->next_slot == GLOBUS_L_PRIORITY_Q_TOP_SLOT)
    {
        return GLOBUS_NULL;
    }
    
    entry = priority_q->heap[GLOBUS_L_PRIORITY_Q_TOP_SLOT];

    return entry->priority;
}
/* globus_priority_q_first_priority() */

/**
 * @brief Remove an Arbitrary Datum from a Priority Queue
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_remove() function removes the highest-priority instance of the
 * specified datum from the priority queue and returns the datum if it is found. If the
 * priority_q is NULL or the datum is not found, this function returns NULL.
 *
 * @param priority_q
 *     Pointer to the priority queue to modify
 * @param datum
 *     Pointer to the datum to search for.
 * @return This function returns datum if it was present in the priority queue
 */
void *
globus_priority_q_remove(
    globus_priority_q_t *               priority_q,
    void *                              datum)
{
    globus_l_priority_q_entry_t **      heap;
    globus_l_priority_q_entry_t *       entry;
    int                                 hole;
    int                                 size;
    void *                              old_priority;
    void *                              new_priority;
    
    if(!priority_q)
    {
        return GLOBUS_NULL;
    }
    
    /* first find entry and position */
    heap = priority_q->heap;
    hole = GLOBUS_L_PRIORITY_Q_TOP_SLOT;
    size = priority_q->next_slot;
    entry = GLOBUS_NULL;
    
    while(hole < size)
    {
        if(heap[hole]->datum == datum)
        {
            entry = heap[hole];
            break;
        }
        hole++;
    }
    
    /* if we found it, remove it
     * then we need to percolate the new hole up, then down
     */
    if(entry)
    {
        old_priority = entry->priority;
        globus_memory_push_node(&priority_q->memory, (globus_byte_t *) entry);
        
        /* take entry from end of heap if removed entry
         * was not at the end of the heap (also catches empty heap) 
         */
        if(--priority_q->next_slot != hole)
        {
            entry = heap[priority_q->next_slot];
            new_priority = entry->priority;
            
            if(priority_q->cmp_func(new_priority, old_priority) > 0)
            {
                hole = globus_l_priority_q_percolate_down(
                    priority_q, hole, new_priority);
            }
            else
            {
                hole = globus_l_priority_q_percolate_up(
                    priority_q, hole, new_priority);
            }
            
            heap[hole] = entry;
        }
        
        return datum;
    }
    else
    {
        return GLOBUS_NULL;
    }
}
/* globus_priority_q_remove() */

/**
 * @brief Modify the Priority of Datum
 * @ingroup globus_priority_q
 * @details
 * The globus_priority_q_modify() function modifies the priority of the highest-priority
 * instance of datum in the priority queue so that it new_priority. The old priority of
 * the datum is returned. If the priority_q is NULL or the datum is not present, this
 * function returns NULL.
 *
 * @param priority_q
 *     Pointer to the priority queue to modify
 * @param datum
 *     Pointer to the datum whose priority is being modified
 * @param new_priority
 *     Pointer to the new priority
 *
 * @return This function returns the old priority of datum.
 */
void *
globus_priority_q_modify(
    globus_priority_q_t *               priority_q,
    void *                              datum,
    void *                              new_priority)
{
    globus_l_priority_q_entry_t **      heap;
    globus_l_priority_q_entry_t *       entry;
    int                                 hole;
    int                                 size;
    void *                              old_priority;
    
    if(!priority_q)
    {
        return GLOBUS_NULL;
    }
    
    /* first find entry and position */
    heap = priority_q->heap;
    hole = GLOBUS_L_PRIORITY_Q_TOP_SLOT;
    size = priority_q->next_slot;
    entry = GLOBUS_NULL;
    
    while(hole < size)
    {
        if(heap[hole]->datum == datum)
        {
            entry = heap[hole];
            break;
        }
        hole++;
    }
    
    /* if we found it, modify it and
     * then we need to percolate up, then down
     */
    if(entry)
    {
        old_priority = entry->priority;
        entry->priority = new_priority;
        
        hole = globus_l_priority_q_percolate_down(
            priority_q, hole, new_priority);
        hole = globus_l_priority_q_percolate_up(
            priority_q, hole, new_priority);
        
        heap[hole] = entry;
        
        return old_priority;
    }
    else
    {
        return GLOBUS_NULL;
    }
}
/* globus_priority_q_modify() */
