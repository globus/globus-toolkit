/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#if !defined(GLOBUS_TIME_H)
#define      GLOBUS_TIME_H

#include "globus_common_include.h"

EXTERN_C_BEGIN

#define GLOBUS_I_TIME_INFINITY_SEC   INT_MAX
#define GLOBUS_I_TIME_INFINITY_NSEC  INT_MAX
#define GLOBUS_I_TIME_INFINITY_USEC  INT_MAX

#if defined (GLOBUS_TIMESPEC_EXISTS)
    typedef struct timespec      globus_abstime_t;
#else
    typedef struct globus_abstime_s
    {
       long    tv_sec;
       long    tv_nsec;
    } globus_abstime_t;
#endif

typedef struct timeval  globus_reltime_t;

/**
 *  Set the abstime structure to the sec and usec parameter values.
 */
#define  GlobusTimeAbstimeSet(Abstime, Sec, USec)         \
{                                                         \
    GlobusTimeAbstimeGetCurrent(Abstime);                 \
    (Abstime).tv_nsec += (USec * 1000);                   \
    if((Abstime).tv_nsec >= 1000000000)                    \
    {                                                     \
        (Abstime).tv_sec += ((Abstime).tv_nsec / 1000000000);\
        (Abstime).tv_nsec = (Abstime).tv_nsec  % 1000000000; \
    }                                                     \
    (Abstime).tv_sec += Sec;                              \
}
/**
 *  Seperates abstime structure into its components,sec and usec.
 */
#define  GlobusTimeAbstimeGet(Abstime, Sec, USec)         \
{                                                         \
    Sec = (Abstime).tv_sec;                               \
    USec = ((Abstime).tv_nsec / 1000);                    \
}

/**
 *  Set the reltime structure to the sec and usec parameter values.
 */
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

/**
 *  Find the difference between the 2 absolute times.
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

/**
 *  Convert a relitive time into a long in usec units
 */
#define  GlobusTimeReltimeToUSec(SlpInt, Reltime)         \
{                                                         \
    SlpInt = ((Reltime).tv_sec * 1000000) +               \
                                     ((Reltime).tv_usec); \
}

/**
 *  Convert a relative time into a long in millisec units
 */
#define  GlobusTimeReltimeToMilliSec( Milliseconds, Reltime)  \
{                                                         \
    Milliseconds = ((Reltime).tv_sec * 1000) +            \
                              ((Reltime).tv_usec)/ 1000;   \
}

/**
 *  Add reltime to abstime
 */
#define  GlobusTimeAbstimeInc(Abstime, Reltime)           \
{                                                         \
    (Abstime).tv_nsec += ((Reltime).tv_usec * 1000);      \
    if((Abstime).tv_nsec >= 1000000000)                    \
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


/**
 *  Get the current time
 */
#if defined(TARGET_ARCH_WIN32)
#   define GlobusTimeAbstimeGetCurrent(Abstime)           \
    {                                                     \
        struct _timeb timebuffer;                      \
                                                          \
        _ftime(&timebuffer);                            \
        (Abstime).tv_sec = timebuffer.time;               \
        (Abstime).tv_nsec = (timebuffer.millitm * 1000);  \
    }
/*
 * On Net+OS on ARM, this is needed if the device is not running NTP or
 * does not have a RTC. In this case, times will overflow after about a 
 * year and a half.
#elif defined(TARGET_ARCH_NETOS)
#   define  GlobusTimeAbstimeGetCurrent(Abstime)          \
    {                                                     \
        ULONG ticks = tx_time_get();                      \
        (Abstime).tv_sec = ticks / NABspTicksPerSecond;  \
        (Abstime).tv_nsec = (ticks % NABspTicksPerSecond) * 1000000000;  \
    }
*/
#else
#   define  GlobusTimeAbstimeGetCurrent(Abstime)          \
    {                                                     \
        struct timeval __time;                            \
                                                          \
        gettimeofday(&__time, GLOBUS_NULL);               \
        (Abstime).tv_sec = __time.tv_sec;                 \
        (Abstime).tv_nsec = (__time.tv_usec * 1000);      \
    }
#endif

/**
 *  Copy the absolute time
 */
#define  GlobusTimeAbstimeCopy(Dest, Src)                 \
{                                                         \
   (Dest).tv_sec = (Src).tv_sec;                          \
   (Dest).tv_nsec = (Src).tv_nsec;                        \
}

/**
 *  Copy the relative time
 */
#define  GlobusTimeReltimeCopy(Dest, Src)                 \
{                                                         \
   (Dest).tv_sec = (Src).tv_sec;                          \
   (Dest).tv_usec = (Src).tv_usec;                        \
}

/**
 *  Multiple the reltime by factor
 */
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

/**
 *  divide the reltime by factor
 */
#define  GlobusTimeReltimeDivide(Reltime, Factor)         \
{                                                         \
   (Reltime).tv_usec /= Factor;                           \
   (Reltime).tv_sec /= Factor;                            \
}

extern const globus_abstime_t         globus_i_abstime_infinity;
extern const globus_abstime_t         globus_i_abstime_zero;
extern const globus_reltime_t         globus_i_reltime_infinity;
extern const globus_reltime_t         globus_i_reltime_zero;

/**
 *  Has abstime expired
 *
 *  Returns a boolean that reflects whether or not abstime is less than the
 *  current time.
 */
globus_bool_t
globus_time_has_expired(
    const globus_abstime_t *                     abstime);

/**
 *  Returns a boolean that reflects whether or not abstime is infinity.
 */
globus_bool_t
globus_time_abstime_is_infinity(
    const globus_abstime_t *                     abstime);

/**
 *  Returns a boolean that reflects whether or not reltime is infinity.
 */
globus_bool_t
globus_time_reltime_is_infinity(
    const globus_reltime_t *                     reltime);

/**
 *  Compare two absolute times.
 *
 *  This function returns an integer that reflects the comparison of two 
 *  abstimes in the following way.
 *
 *  0  :  values are the same.
 *  -1 :  the first value is less than the second.
 *  1  :  the first value is greater than the second.
 */
int
globus_abstime_cmp(
    const globus_abstime_t *                     abstime_1,
    const globus_abstime_t *                     abstime_2);

/**
 *  Compare two absolute times.
 *
 *  This function returns an integer that reflects the comparison of two 
 *  reltimes in the following way.
 *
 *  0  :  values are the same.
 *  -1 :  the first value is less than the second.
 *  1  :  the first value is greater than the second.
 */
int
globus_reltime_cmp(
    const globus_reltime_t *                     reltime_1,
    const globus_reltime_t *                     reltime_2);


EXTERN_C_END

#endif /* GLOBUS_TIME_H */


