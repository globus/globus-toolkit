#ifndef GLOBUS_COMMON_TIMEQ_H
#define GLOBUS_COMMON_TIMEQ_H

/********************************************************************
 *
 *  THis file defines the a time stamped queue for globus
 *
 ********************************************************************/

#include "globus_common.h"
#include "globus_list.h"
#include "globus_time.h"
#include "globus_memory.h"

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

#define __TIMEQ_USE_I_MEM 1

typedef struct globus_timeq_s 
{
    globus_list_t * volatile head;
    globus_list_t * volatile tail;
#if defined(__TIMEQ_USE_I_MEM)
    globus_memory_t               mem;
    globus_bool_t                 mem_initialized;
#endif
} globus_timeq_t;


#define GlobusTimeToTimeT(GTime, TimeT) \
{ \
    (TimeT).tv_sec = (time_t) (GTime / 1000000); \
    (TimeT).tv_usec = (long)(GTime % 1000000); \
}

#define TimeTToGlobusTime(GTime, TimeT) \
{ \
    GTime =(globus_time_t) (TimeT).tv_sec * (globus_time_t)1000000; \
    GTime = GTime + (TimeT).tv_usec; \
}

#define GlobusTimeToGlobusAbstimeT(GTime, AbstimeT)        \
{                                                          \
    (AbstimeT).tv_sec = (time_t) (GTime / 1000000);        \
    (AbstimeT).tv_nsec = (long)((GTime % 1000000) * 1000); \
    if((AbstimeT).tv_nsec > 1000000000)                    \
    {                                                      \
        (AbstimeT).tv_sec++;                               \
	(AbstimeT).tv_nsec = 0;                            \
    }                                                      \
}

#define GlobusCommonGetAbstime(AbstimeT)          \
{                                                 \
    struct timeval __time_t;                      \
                                                  \
    gettimeofday(&__time_t, GLOBUS_NULL);         \
                                                  \
    (AbstimeT).tv_sec = __time_t.tv_sec;          \
    (AbstimeT).tv_nsec = __time_t.tv_usec * 1000; \
}

extern int
globus_timeq_init(
    globus_timeq_t *                     timeq);

extern void
globus_timeq_destroy(
    globus_timeq_t *                     timeq);

extern globus_bool_t 
globus_timeq_empty(
    globus_timeq_t *                     timeq);

extern int 
globus_timeq_size(
    globus_timeq_t *                     timeq);

extern int
globus_timeq_enqueue(
    globus_timeq_t *                     timeq,
    void *                               datum,
    globus_abstime_t *                   time_offset);

extern void *
globus_timeq_remove(
    globus_timeq_t *                     headp, 
    void *                               datum);

extern void *
globus_timeq_dequeue(
    globus_timeq_t *                     timeq);

extern void *
globus_timeq_first(
    globus_timeq_t *                     timeq);

globus_abstime_t *
globus_timeq_first_time(
    globus_timeq_t *                     timeq);

globus_abstime_t *
globus_timeq_time_at(
    globus_timeq_t *                     timeq,
    int                                  element_index);

EXTERN_C_END

#endif /* GLOBUS_COMMON_TIMEQ_H */
