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

#ifndef _GLOBUS_USAGE_H_
#define _GLOBUS_USAGE_H_

#include "globus_common.h"

EXTERN_C_BEGIN

#define GLOBUS_USAGE_MODULE             &globus_i_usage_stats_module
extern globus_module_descriptor_t       globus_i_usage_stats_module;

typedef struct globus_usage_stats_handle_s * globus_usage_stats_handle_t;

enum
{
    GLOBUS_USAGE_STATS_ERROR_TYPE_OOM,
    GLOBUS_USAGE_STATS_ERROR_TYPE_TOO_BIG,
    GLOBUS_USAGE_STATS_ERROR_TYPE_UNKNOWN_HOSTNAME
};

globus_result_t
globus_usage_stats_handle_init(
    globus_usage_stats_handle_t *       handle,
    uint16_t                            code,
    uint16_t                            version,
    const char *                        targets);

void
globus_usage_stats_handle_destroy(
    globus_usage_stats_handle_t         handle);

globus_result_t
globus_usage_stats_send(
    globus_usage_stats_handle_t         handle,
    int                                 count,
    ...);

globus_result_t
globus_usage_stats_vsend(
    globus_usage_stats_handle_t         handle,
    int                                 count,
    va_list                             ap);

EXTERN_C_END

#endif

