#ifndef GLOBUS_COMMON_PRIORITY_Q_H
#define GLOBUS_COMMON_PRIORITY_Q_H

/********************************************************************
 *
 *  This file defines the a priority queue for globus
 *
 ********************************************************************/

#include "globus_common.h"

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif


EXTERN_C_BEGIN

#define __PRIORITY_Q_USE_I_MEM 1

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
