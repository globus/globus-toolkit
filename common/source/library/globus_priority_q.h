#ifndef GLOBUS_COMMON_PRIORITY_Q_H
#define GLOBUS_COMMON_PRIORITY_Q_H

/********************************************************************
 *
 *  THis file defines the a time stamped queue for globus
 *
 ********************************************************************/

#include "globus_common_include.h"
#include "globus_memory.h"
#include "globus_list.h"

EXTERN_C_BEGIN

#define __PRIORITY_Q_USE_I_MEM 1

typedef int (*globus_priority_q_cmp_func_t)(
    void *                                    priority_1,
    void *                                    priority_2);

typedef struct globus_priority_q_s 
{
    globus_list_t * volatile       head;
    globus_list_t * volatile       tail;

    globus_priority_q_cmp_func_t   cmp_func;

#if defined(__PRIORITY_Q_USE_I_MEM)
    globus_memory_t                mem;
    globus_bool_t                  mem_initialized;
#endif

} globus_priority_q_t;

int 
globus_priority_q_fifo_cmp_func(
    void *                                    priority_1,
    void *                                    priority_2);

extern int
globus_priority_q_init(
    globus_priority_q_t *                     priority_q,
    globus_priority_q_cmp_func_t              cmp_func);

extern void
globus_priority_q_destroy(
    globus_priority_q_t *                     priority_q);

extern globus_bool_t 
globus_priority_q_empty(
    globus_priority_q_t *                     priority_q);

extern int 
globus_priority_q_size(
    globus_priority_q_t *                     priority_q);

extern int
globus_priority_q_enqueue(
    globus_priority_q_t *                     priority_q,
    void *                                    datum,
    void *                                    priority);

extern void *
globus_priority_q_remove(
    globus_priority_q_t *                     headp, 
    void *                                    datum);

extern void *
globus_priority_q_dequeue(
    globus_priority_q_t *                     priority_q);

extern void *
globus_priority_q_first(
    globus_priority_q_t *                     priority_q);

void *
globus_timeq_first_priority(
    globus_priority_q_t *                     priority_q);

void *
globus_priority_q_priority_at(
    globus_priority_q_t *                     priority_q,
    int                                       element_index);

EXTERN_C_END

#endif /* GLOBUS_COMMON_PRIORITY_Q_H */


