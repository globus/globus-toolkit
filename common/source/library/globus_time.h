#if !defined(GLOBUS_TIME_H)
#define      GLOBUS_TIME_H


#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif


#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>

#include "globus_common.h"

EXTERN_C_BEGIN

#define GLOBUS_I_TIME_INFINITY_SEC   INT_MAX
#define GLOBUS_I_TIME_INFINITY_NSEC  INT_MAX
#define GLOBUS_I_TIME_INFINITY_USEC  INT_MAX

typedef struct timeval  globus_reltime_t;

/*
 * passed in relative time and set to absolute
 */
#define  GlobusTimeAbstimeSet(Abstime, Sec, USec)         \
{                                                         \
    GlobusTimeAbstimeGetCurrent(Abstime);                 \
    (Abstime).tv_nsec += (USec * 1000);                   \
    if((Abstime).tv_nsec > 1000000000)                    \
    {                                                     \
        (Abstime).tv_sec += ((Abstime).tv_nsec / 1000000000);\
        (Abstime).tv_nsec = (Abstime).tv_nsec  % 1000000000; \
    }                                                     \
    (Abstime).tv_sec += Sec;                              \
}
/*
 * gets the remaining time
 */
#define  GlobusTimeAbstimeGet(Abstime, Sec, USec)         \
{                                                         \
    Sec = (Abstime).tv_sec;                               \
    USec = ((Abstime).tv_nsec / 1000);                    \
}

#define  GlobusTimeReltimeSet(Reltime, Sec, USec)         \
{                                                         \
    (Reltime).tv_usec = (USec);                           \
    (Reltime).tv_sec = Sec;                               \
    if((Reltime).tv_usec >= 1000000)                      \
    {                                                     \
        (Reltime).tv_sec += ((Reltime).tv_usec / 1000000);\
        (Reltime).tv_usec = (Reltime).tv_usec  % 1000000; \
    }                                                     \
}

#define  GlobusTimeReltimeGet(Reltime, Sec, USec)         \
{                                                         \
    (USec) = (Reltime).tv_usec;                           \
    (Sec) = (Reltime).tv_sec;                             \
}

#define  GlobusTimeAbstimePrintf(Abstime)                 \
{                                                         \
    printf("sec  -->%lu\n", (Abstime).tv_sec);            \
    printf("nsec -->%lu\n", (Abstime).tv_nsec);           \
}

#define  GlobusTimeReltimePrintf(Reltime)                 \
{                                                         \
    printf("sec  -->%lu\n", (Reltime).tv_sec);            \
    printf("usec -->%lu\n", (Reltime).tv_usec);           \
}

/* 
 * return absolute value in Relative time result
 */
#define  GlobusTimeAbstimeDiff(Reltime, T1, T2)           \
{                                                         \
    int __res = globus_abstime_cmp(&(T1), &(T2));         \
    if(__res < 0)                                         \
    {                                                     \
        (Reltime).tv_sec = (T2).tv_sec - (T1).tv_sec;     \
        (Reltime).tv_usec =                               \
                (((T2).tv_nsec - (T1).tv_nsec) / 1000);   \
        if((Reltime).tv_usec < 0)                         \
        {                                                 \
            (Reltime).tv_sec--;                           \
            (Reltime).tv_usec += 1000000;                 \
        }                                                 \
    }                                                     \
    else if(__res > 0)                                    \
    {                                                     \
        (Reltime).tv_sec = (T1).tv_sec - (T2).tv_sec;     \
        (Reltime).tv_usec =                               \
                (((T1).tv_nsec - (T2).tv_nsec) / 1000);   \
        if((Reltime).tv_usec < 0)                         \
        {                                                 \
            (Reltime).tv_sec--;                           \
            (Reltime).tv_usec += 1000000;                 \
        }                                                 \
    }                                                     \
    else                                                  \
    {                                                     \
        (Reltime).tv_sec = 0;                             \
        (Reltime).tv_usec = 0;                            \
    }                                                     \
}

#define  GlobusTimeReltimeDiff(Reltime, T1, T2)           \
{                                                         \
    int __res = globus_reltime_cmp(&(T1), &(T2));         \
    if(__res < 0)                                         \
    {                                                     \
        (Reltime).tv_sec = (T2).tv_sec - (T1).tv_sec;     \
        (Reltime).tv_usec =                               \
                ((T2).tv_usec - (T1).tv_usec);            \
        if((Reltime).tv_usec < 0)                         \
        {                                                 \
            (Reltime).tv_sec--;                           \
            (Reltime).tv_usec += 1000000;                 \
        }                                                 \
    }                                                     \
    else if(__res > 0)                                    \
    {                                                     \
        (Reltime).tv_sec = (T1).tv_sec - (T2).tv_sec;     \
        (Reltime).tv_usec =                               \
                ((T1).tv_usec - (T2).tv_usec);            \
        if((Reltime).tv_usec < 0)                         \
        {                                                 \
            (Reltime).tv_sec--;                           \
            (Reltime).tv_usec += 1000000;                 \
        }                                                 \
    }                                                     \
    else                                                  \
    {                                                     \
        (Reltime).tv_sec = 0;                             \
        (Reltime).tv_usec = 0;                            \
    }                                                     \
}

#define  GlobusTimeReltimeToUSec(SlpInt, Reltime)         \
{                                                         \
    SlpInt = ((Reltime).tv_sec * 1000000) +               \
                                     ((Reltime).tv_usec); \
}

#define  GlobusTimeAbstimeInc(Abstime, Reltime)           \
{                                                         \
    (Abstime).tv_nsec += ((Reltime).tv_usec * 1000);      \
    if((Abstime).tv_nsec > 1000000000)                    \
    {                                                     \
        (Abstime).tv_sec++;                               \
        (Abstime).tv_nsec -= 1000000000;                  \
    }                                                     \
    (Abstime).tv_sec += (Reltime).tv_sec;                 \
}

#define  GlobusTimeAbstimeDec(Abstime, Reltime)           \
{                                                         \
    (Abstime).tv_nsec -= ((Reltime).tv_usec * 1000);      \
    if((Abstime).tv_nsec < 0)                             \
    {                                                     \
        (Abstime).tv_sec--;                               \
        (Abstime).tv_nsec += 1000000000;                  \
    }                                                     \
    (Abstime).tv_sec -= (Reltime).tv_sec;                 \
}

#define  GlobusTimeAbstimeGetCurrent(Abstime)             \
{                                                         \
    struct timeval __time;                                \
                                                          \
    gettimeofday(&__time, GLOBUS_NULL);                   \
    (Abstime).tv_sec = __time.tv_sec;                     \
    (Abstime).tv_nsec = (__time.tv_usec * 1000);           \
}

#define  GlobusTimeAbstimeCopy(Dest, Src)                 \
{                                                         \
   (Dest).tv_sec = (Src).tv_sec;                          \
   (Dest).tv_nsec = (Src).tv_nsec;                        \
}

#define  GlobusTimeReltimeCopy(Dest, Src)                 \
{                                                         \
   (Dest).tv_sec = (Src).tv_sec;                          \
   (Dest).tv_usec = (Src).tv_usec;                        \
}

#define  GlobusTimeReltimeMultiply(Reltime, Factor)       \
{                                                         \
   (Reltime).tv_usec *= Factor;                           \
   (Reltime).tv_sec *= Factor;                            \
                                                          \
    if((Reltime).tv_usec >= 1000000)                      \
    {                                                     \
        (Reltime).tv_sec += ((Reltime).tv_usec / 1000000);\
        (Reltime).tv_usec = (Reltime).tv_usec  % 1000000; \
    }                                                     \
}

#define  GlobusTimeReltimeDivide(Reltime, Factor)         \
{                                                         \
   (Reltime).tv_usec /= 2;                                \
   (Reltime).tv_sec /= 2;                                 \
}

extern const globus_abstime_t         globus_i_abstime_infinity;
extern const globus_abstime_t         globus_i_abstime_zero;
extern const globus_reltime_t         globus_i_reltime_infinity;
extern const globus_reltime_t         globus_i_reltime_zero;

globus_bool_t
globus_time_has_expired(
    const globus_abstime_t *                     abstime);

globus_bool_t
globus_time_abstime_is_infinity(
    const globus_abstime_t *                     abstime);

globus_bool_t
globus_time_reltime_is_infinity(
    const globus_reltime_t *                     reltime);

int
globus_abstime_cmp(
    const globus_abstime_t *                     abstime_1,
    const globus_abstime_t *                     abstime_2);

int
globus_reltime_cmp(
    const globus_reltime_t *                     reltime_1,
    const globus_reltime_t *                     reltime_2);


EXTERN_C_END

#endif /* GLOBUS_TIME_H */
