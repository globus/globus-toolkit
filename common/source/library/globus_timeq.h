#ifndef GLOBUS_COMMON_TIMEQ_H
#define GLOBUS_COMMON_TIMEQ_H

/**
 *
 *  This file defines the a time stamped queue for globus
 *
 *  The queue is ordered ascending by the time associated with each element 
 *  when it is added.
 */
#include "globus_common_include.h"
#include "globus_time.h"
#include "globus_memory.h"

EXTERN_C_BEGIN

/*
 * forward declare internal type
 */
struct globus_timeq_s;

/*
 *  define type as a pointer to internal type.
 */
typedef struct globus_timeq_s *                             globus_timeq_t;

/**
 *  initialize the timeq data type.  This must be done before
 *  a timeq structure can be used.
 */
extern globus_result_t
globus_timeq_init(
    globus_timeq_t *                                        timeq);

/**
 *  destroy a timq datatype.  A destroy must be associate with
 *  every init or memory will leak.
 */
extern globus_result_t
globus_timeq_destroy(
    globus_timeq_t *                                        timeq);

/**
 *  determine if the timq is empty or not.  GLOBUS_TRUE is returned when
 *  empty, GLOBUS_FALSE when not empty.
 */
extern globus_bool_t 
globus_timeq_empty(
    globus_timeq_t *                                        timeq);

/**
 *  determine the number if elements in the queue.
 *
 *  The total number of elements in the queue is returned.
 */
extern int 
globus_timeq_size(
    globus_timeq_t *                                        timeq);

/**
 *  add an element to the queue.
 *
 *  @param timeq
 *          the time queue datum is being added to.
 *
 *  @param datum
 *          the data to be added to the queue.
 *  @param time_offset
 *          the time associate with the datum.
 *          
 */
extern globus_result_t
globus_timeq_enqueue(
    globus_timeq_t *                                        timeq,
    void *                                                  datum,
    globus_abstime_t *                                      time_offset);

/**
 *  pop an element off the queue.
 *
 *  The element pointed to by datum is removed from the queue.
 */
extern void *
globus_timeq_remove(
    globus_timeq_t *                                        headp, 
    void *                                                  datum);

/**
 *  The element at the front of the queue is popped off.
 */
extern void *
globus_timeq_dequeue(
    globus_timeq_t *                                        timeq);

/**
 *  peek at the first element in the queue
 */
extern void *
globus_timeq_first(
    globus_timeq_t *                                        timeq);

/**
 *  peek at the time associated with the first elemnent in the queue.
 */
globus_abstime_t *
globus_timeq_first_time(
    globus_timeq_t *                                        timeq);

/**
 *  peek at the time associated with the element that is element_index
 *  deep in the queue.
 */
globus_abstime_t *
globus_timeq_time_at(
    globus_timeq_t *                                        timeq,
    int                                                     element_index);

EXTERN_C_END

#endif /* GLOBUS_COMMON_TIMEQ_H */


