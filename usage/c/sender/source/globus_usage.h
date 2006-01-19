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

