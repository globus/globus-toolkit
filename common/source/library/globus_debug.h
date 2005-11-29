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


#ifndef GLOBUS_DEBUG_H
#define GLOBUS_DEBUG_H

#include "globus_common_include.h"
#include "globus_time.h"

EXTERN_C_BEGIN

#ifdef BUILD_DEBUG

typedef struct
{
    unsigned                            levels;
    unsigned                            timestamp_levels;
    FILE *                              file;
    globus_bool_t                       thread_ids;
    globus_bool_t                       using_file;
} globus_debug_handle_t;

void
globus_debug_init(
    const char *                        env_name,
    const char *                        level_names,
    globus_debug_handle_t *             handle);

#ifdef BUILD_LITE
#define GlobusDebugThreadId() getpid()
#else
#define GlobusDebugThreadId() globus_thread_self()
#endif

/* call in same file as module_activate func (before (de)activate funcs) */
#define GlobusDebugDefine(module_name)                                      \
    extern globus_debug_handle_t globus_i_##module_name##_debug_handle;     \
    void globus_i_##module_name##_debug_printf(const char * fmt, ...)       \
    {                                                                       \
        va_list ap;                                                         \
	                                                                    \
        if(!globus_i_##module_name##_debug_handle.file)                     \
            return;                                                         \
                                                                            \
        va_start(ap, fmt);                                                  \
        if(globus_i_##module_name##_debug_handle.thread_ids)                \
        {                                                                   \
            char buf[4096]; /* XXX better not use a fmt bigger than this */ \
            sprintf(                                                        \
                buf, "%lu::%s", (unsigned long) GlobusDebugThreadId(), fmt);\
            vfprintf(globus_i_##module_name##_debug_handle.file, buf, ap);  \
        }                                                                   \
        else                                                                \
        {                                                                   \
            vfprintf(globus_i_##module_name##_debug_handle.file, fmt, ap);  \
        }                                                                   \
        va_end(ap);                                                         \
    }                                                                       \
    void globus_i_##module_name##_debug_time_printf(const char * fmt, ...)  \
    {                                                                       \
        va_list ap;                                                         \
        char buf[4096]; /* XXX better not use a fmt bigger than this */     \
        globus_abstime_t current_time;                                      \
	                                                                    \
        if(!globus_i_##module_name##_debug_handle.file)                     \
            return;                                                         \
                                                                            \
        GlobusTimeAbstimeGetCurrent(current_time);                          \
        va_start(ap, fmt);                                                  \
        if(globus_i_##module_name##_debug_handle.thread_ids)                \
        {                                                                   \
            sprintf(buf, "%lu:%lu.%.9lu::%s",                               \
                (unsigned long) GlobusDebugThreadId(),                      \
                (unsigned long) current_time.tv_sec,                        \
                (unsigned long) current_time.tv_nsec,                       \
                fmt);                                                       \
            vfprintf(globus_i_##module_name##_debug_handle.file, buf, ap);  \
        }                                                                   \
        else                                                                \
        {                                                                   \
            sprintf(buf, "%lu.%.9lu::%s",                                   \
                (unsigned long) current_time.tv_sec,                        \
                (unsigned long) current_time.tv_nsec,                       \
                fmt);                                                       \
            vfprintf(globus_i_##module_name##_debug_handle.file, buf, ap);  \
        }                                                                   \
        va_end(ap);                                                         \
    }                                                                       \
    void globus_i_##module_name##_debug_fwrite(                             \
        const void *ptr, size_t size, size_t  nmemb)                        \
    {                                                                       \
        if(globus_i_##module_name##_debug_handle.file)                      \
            fwrite(ptr, size, nmemb,                                        \
                globus_i_##module_name##_debug_handle.file);                \
    }                                                                       \
    globus_debug_handle_t globus_i_##module_name##_debug_handle

/* call this in a header file (if needed externally) */
#define GlobusDebugDeclare(module_name)                                     \
    extern void globus_i_##module_name##_debug_printf(const char *, ...);   \
    extern void globus_i_##module_name##_debug_time_printf(const char *, ...);\
    extern void globus_i_##module_name##_debug_fwrite(                      \
        const void *ptr, size_t size, size_t nmemb);                        \
    extern globus_debug_handle_t globus_i_##module_name##_debug_handle

/* call this in module activate func
 *
 * 'levels' is a space separated list of level names that can be used in env
 *    they will map to a 2^i value (so, list them in same order as value)
 *
 * will look in env for {module_name}_DEBUG whose value is:
 * <levels> [, [ [ # ] <file name>] [, <flags> [, <timestamp_levels>] ] ]
 * where <levels> can be a single numeric or '|' separated level names
 * <file name> is a debug output file... can be empty.  stderr by default
 *    if a '#' precedes the filename, the file will be overwritten on each run
 *    otherwise, the default is to append to the existing (if one exists)
 * <flags> 0 default (or any of the following to enable:
 *         1 show thread ids
 *         2 append pid to debug filename
 * <timestamp_levels> similar to <levels>. specifies which levels to print
 *   timestamps with.  default is none.
 * Also, users can use the ALL level in their env setting to turn on 
 * all levels or precede the list of levels with '^' to enable all levels
 * except those.
 */
#define GlobusDebugInit(module_name, levels)                                \
    globus_debug_init(                                                      \
        #module_name "_DEBUG",                                              \
        #levels,                                                            \
        &globus_i_##module_name##_debug_handle)

/* call this in module deactivate func */
#define GlobusDebugDestroy(module_name)                                     \
    do                                                                      \
    {                                                                       \
        if(globus_i_##module_name##_debug_handle.using_file)                \
        {                                                                   \
            fclose(globus_i_##module_name##_debug_handle.file);             \
        }                                                                   \
        globus_i_##module_name##_debug_handle.file = GLOBUS_NULL;           \
    } while(0)

/* use this to print a message unconditionally (message must be enclosed in
 * parenthesis and contains a format and possibly var args
 */
#define GlobusDebugMyPrintf(module_name, message)                           \
    globus_i_##module_name##_debug_printf message
#define GlobusDebugMyTimePrintf(module_name, message)                       \
    globus_i_##module_name##_debug_time_printf message

#define GlobusDebugMyFwrite(module_name, buffer, size, count)               \
    globus_i_##module_name##_debug_fwrite((buffer), (size), (count))

#define GlobusDebugMyFile(module_name)                                      \
    (globus_i_##module_name##_debug_handle.file)
    
/* use this in an if() to debug enable blocks of code 
 * for example
 * 
 * if(GlobusDebugTrue(MY_MODULE, VERIFICATION))
 * {
 *    compute stats
 *    GlobusDebugMyPrintf(MY_MODULE, "Stats = %d\n", stats);
 * }
 */
#define GlobusDebugTrue(module_name, level)                                 \
    (globus_i_##module_name##_debug_handle.levels & (level))

#define GlobusDebugTimeTrue(module_name, level)                             \
    (globus_i_##module_name##_debug_handle.timestamp_levels & (level))

/* most likely wrap this with your own macro,
 * so you dont need to pass module_name all the time
 * 'message' needs to be wrapped with parens and contains a format and
 * possibly var args
 */
#define GlobusDebugPrintf(module_name, level, message)                      \
    do                                                                      \
    {                                                                       \
        if(GlobusDebugTrue(module_name, level))                             \
        {                                                                   \
            if(!GlobusDebugTimeTrue(module_name, level))                    \
            {                                                               \
                GlobusDebugMyPrintf(module_name, message);                  \
            }                                                               \
            else                                                            \
            {                                                               \
                GlobusDebugMyTimePrintf(module_name, message);              \
            }                                                               \
        }                                                                   \
    } while(0)

#define GlobusDebugFwrite(module_name, level, buffer, size, count)          \
    do                                                                      \
    {                                                                       \
        if(GlobusDebugTrue(module_name, level))                             \
        {                                                                   \
            GlobusDebugMyFwrite(module_name, buffer, size, count);          \
        }                                                                   \
    } while(0)

#else

#define GlobusDebugThreadId()                                   0
#define GlobusDebugDeclare(module_name)
#define GlobusDebugDefine(module_name)
#define GlobusDebugInit(module_name, levels)                    do {} while(0)
#define GlobusDebugDestroy(module_name)                         do {} while(0)
#define GlobusDebugPrintf(module_name, level, message)          do {} while(0)
#define GlobusDebugFwrite(module_name, level, buffer, size, count)          \
                                                                do {} while(0)
#define GlobusDebugMyPrintf(module_name, message)               do {} while(0)
#define GlobusDebugMyTimePrintf(module_name, message)           do {} while(0)
#define GlobusDebugMyFwrite(module_name, buffer, size, count)   do {} while(0)
#define GlobusDebugMyFile(module_name)                          (stderr)
#define GlobusDebugTrue(module_name, level)                     0
#define GlobusDebugTimeTrue(module_name, level)                 0

#endif

EXTERN_C_END

#endif /* GLOBUS_DEBUG_H */
