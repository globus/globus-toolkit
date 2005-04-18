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

#ifndef GLOBUS_RMUTEX_INCLUDE
#define GLOBUS_RMUTEX_INCLUDE

#include "globus_common_include.h"
#include GLOBUS_THREAD_INCLUDE

#ifndef BUILD_LITE

EXTERN_C_BEGIN

typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_thread_t			thread_id;
    int					level;
    int                                 waiting;
} globus_rmutex_t;

typedef int                             globus_rmutexattr_t;

int
globus_rmutex_init(
    globus_rmutex_t *                   rmutex,
    globus_rmutexattr_t *               attr);

int
globus_rmutex_lock(
    globus_rmutex_t *                   rmutex);

int
globus_rmutex_unlock(
    globus_rmutex_t *                   rmutex);

int
globus_rmutex_destroy(
    globus_rmutex_t *                   rmutex);

EXTERN_C_END

#else

typedef globus_mutex_t                  globus_rmutex_t;
typedef int                             globus_rmutexattr_t;

#define globus_rmutex_init(x, y) (*(x) = 0)
#define globus_rmutex_lock(x) (*(x) = 1)
#define globus_rmutex_unlock(x) (*(x) = 0)
#define globus_rmutex_destroy(x) (*(x) = 0)

#endif
#endif
