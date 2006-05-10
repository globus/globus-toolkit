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

#ifndef GLOBUS_COMMON_PRIORITY_Q_H
#define GLOBUS_COMMON_PRIORITY_Q_H

/********************************************************************
 *
 *  This file defines the a priority queue for globus
 *  It is implemented using a binary heap (minheap) and does NOT have
 *  a fifo fallback for like priorities.  If you need fifo fallback,
 *  you should use a compound priority with the primary priority being
 *  the 'real' priority and the secondary being a serial number.
 *
 ********************************************************************/

#include "globus_common_include.h"
#include "globus_memory.h"


EXTERN_C_BEGIN

/*
 * if priority_1 comes after priority_2, return > 0
 * else if priority_1 comes before priority_2, return < 0
 * else return 0
 */
 
typedef int (*globus_priority_q_cmp_func_t)(
    void *                                  priority_1,
    void *                                  priority_2);

typedef struct globus_priority_q_s
{
    struct globus_l_priority_q_entry_s **   heap;
    int                                     next_slot;
    size_t                                  max_len;
    globus_memory_t                         memory;
    globus_priority_q_cmp_func_t            cmp_func;
} globus_priority_q_t;

int
globus_priority_q_init(
    globus_priority_q_t *               priority_q,
    globus_priority_q_cmp_func_t        cmp_func);

int
globus_priority_q_destroy(
    globus_priority_q_t *               priority_q);

globus_bool_t
globus_priority_q_empty(
    globus_priority_q_t *               priority_q);

int
globus_priority_q_size(
    globus_priority_q_t *               priority_q);

int
globus_priority_q_enqueue(
    globus_priority_q_t *               priority_q,
    void *                              datum,
    void *                              priority);

void *
globus_priority_q_remove(
    globus_priority_q_t *               priority_q,
    void *                              datum);

/*
 * it is acceptable to modify the priority already stored within the queue
 * before making this call.  The old priority is not looked at
 */
void *
globus_priority_q_modify(
    globus_priority_q_t *               priority_q,
    void *                              datum,
    void *                              new_priority);

void *
globus_priority_q_dequeue(
    globus_priority_q_t *               priority_q);

void *
globus_priority_q_first(
    globus_priority_q_t *               priority_q);

void *
globus_priority_q_first_priority(
    globus_priority_q_t *               priority_q);

EXTERN_C_END

#endif /* GLOBUS_COMMON_PRIORITY_Q_H */
