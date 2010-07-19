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

#ifndef GLOBUS_LOGGING_H
#define GLOBUS_LOGGING_H 1

#include "globus_common_include.h"
#include "globus_time.h"

#define GLOBUS_LOGGING_INLINE           0x08000000

typedef struct globus_l_logging_handle_s * globus_logging_handle_t;

typedef enum
{
    GLOBUS_LOGGING_ERROR_PARAMETER,
    GLOBUS_LOGGING_ERROR_ALLOC
} globus_logging_error_type_t;

typedef void
(*globus_logging_open_func_t)(
    void *                              user_arg);

typedef void
(*globus_logging_write_func_t)(
    globus_byte_t *                     buf,
    globus_size_t                       length,
    void *                              user_arg);

typedef void
(*globus_logging_close_func_t)(
    void *                              user_arg);

typedef void
(*globus_logging_header_func_t)(
    char *                              buffer,
    globus_size_t *                     buf_len);

typedef struct globus_logging_module_s
{
    globus_logging_open_func_t          open_func;
    globus_logging_write_func_t         write_func;
    globus_logging_close_func_t         close_func;
    globus_logging_header_func_t        header_func;
} globus_logging_module_t;


globus_result_t
globus_logging_init(
    globus_logging_handle_t *           out_handle,
    globus_reltime_t *                  flush_period,
    int                                 buffer_length,
    int                                 log_type,
    globus_logging_module_t *           module,
    void *                              user_arg);

globus_result_t
globus_logging_write(
    globus_logging_handle_t             handle,
    int                                 type,
    const char *                        fmt,
    ...);

globus_result_t
globus_logging_vwrite(
    globus_logging_handle_t             handle,
    int                                 type,
    const char *                        fmt,
    va_list                             ap);

globus_result_t
globus_logging_flush(
    globus_logging_handle_t             handle);

globus_result_t
globus_logging_destroy(
    globus_logging_handle_t             handle);

extern globus_logging_module_t          globus_logging_stdio_module;
extern globus_logging_module_t          globus_logging_syslog_module;
extern globus_logging_module_t          globus_logging_stdio_ng_module;
extern globus_logging_module_t          globus_logging_syslog_ng_module;

#endif
