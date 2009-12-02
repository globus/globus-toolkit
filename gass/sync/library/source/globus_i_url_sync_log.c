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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_url_sync_debug.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_url_sync.h"
#include "globus_i_url_sync.h"
#include "globus_common.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

#define GLOBUS_L_URL_SYNC_LOG_MASK      255

typedef struct globus_l_url_sync_log_s
{
    globus_logging_handle_t             log_handle;
    globus_url_sync_log_level_t         log_level;
} globus_l_url_sync_log_t;

static globus_l_url_sync_log_t          globus_l_url_sync_log;
static globus_logging_handle_t          globus_l_url_sync_debug_default_log_handle;

void
globus_url_sync_log_set_level(
    globus_url_sync_log_level_t             level)
{
    globus_l_url_sync_log.log_level = level;
}

void
globus_url_sync_log_set_handle(
    globus_logging_handle_t                 log_handle)
{
    globus_l_url_sync_log.log_handle = log_handle;
}

/**
 * Activates the debug group.
 */
globus_result_t
globus_i_url_sync_log_activate()
{
    globus_result_t                         res;

    res = globus_logging_init(
                &globus_l_url_sync_debug_default_log_handle,
                NULL,
                1024,
                GLOBUS_L_URL_SYNC_LOG_MASK,
                &globus_logging_stdio_module,
                stderr);

    if (res == GLOBUS_SUCCESS)
    {
        globus_l_url_sync_log.log_handle =
                globus_l_url_sync_debug_default_log_handle;
    }
    globus_l_url_sync_log.log_level = GLOBUS_URL_SYNC_LOG_LEVEL_NONE;

    return res;
}

/**
 * Deactivates the debug group.
 */
globus_result_t
globus_i_url_sync_log_deactivate()
{
    globus_l_url_sync_log.log_level     = GLOBUS_URL_SYNC_LOG_LEVEL_NONE;
    globus_l_url_sync_log.log_handle    = GLOBUS_NULL;

    return globus_logging_destroy(globus_l_url_sync_debug_default_log_handle);
}

/**
 * Writes a formatted string to the log.
 */
void
globus_i_url_sync_log_write(
    globus_url_sync_log_level_t             log_level,
    char *                                  fmt,
                                            ...)
{
    va_list                                 ap;

    if (log_level > globus_l_url_sync_log.log_level)
        return;

    va_start(ap, fmt);
    globus_logging_vwrite(
            globus_l_url_sync_log.log_handle,
            globus_l_url_sync_log.log_level,
            fmt,
            ap);
    va_end(ap);
}


#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
