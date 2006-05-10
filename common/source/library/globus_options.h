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

#ifndef GLOBUS_OPTIONS_H
#define GLOBUS_OPTIONS_H 1

#include "globus_common_include.h"


enum 
{
    GLOBUS_OPTIONS_HELP = 1,
    GLOBUS_OPTIONS_NOT_ENOUGH_ARGS,
    GLOBUS_OPTIONS_INVALID_PARAMETER,
    GLOBUS_OPTIONS_UNKNOWN
};

typedef
globus_result_t
(*globus_options_callback_t)(
    char *                              cmd,
    char *                              parm,
    void *                              arg,
    int *                               out_parms_used);

typedef
globus_result_t
(*globus_options_unknown_callback_t)(
    const char *                        parm,
    void *                              arg);

typedef struct globus_options_entry_s
{
    char *                              opt_name; /* long and filename */
    char *                              short_opt;
    char *                              env;
    char *                              parms_desc;
    char *                              description;
    int                                 arg_count;
    globus_options_callback_t           func;
} globus_options_entry_t;

typedef struct globus_l_options_handle_s * globus_options_handle_t;

globus_result_t
globus_options_init(
    globus_options_handle_t *           out_handle,
    globus_options_unknown_callback_t   unknown_func,
    void *                              user_arg,
    globus_options_entry_t *            table);

globus_result_t
globus_options_destroy(
    globus_options_handle_t             handle);

globus_result_t
globus_options_command_line_process(
    globus_options_handle_t             handle,
    int                                 argc,
    char **                             argv);

globus_result_t
globus_options_env_process(
    globus_options_handle_t             handle);

globus_result_t
globus_options_file_process(
    globus_options_handle_t             handle,
    char *                              filename);

#endif
