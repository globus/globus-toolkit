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

#include "globus_i_prews_gram_throughput_test.h"
#include "version.h"

static const char * usage =
"prews-gram-throughput-test [-help] \n"
"    [-resource-manager <resource manager>]\n"
"    [-job-duration <job duration in seconds>]\n"
"    [-load <load per thread in seconds>]\n"
"    [-num-threads <number of job submittion threads>]\n"
"    [-test-duration <total test duration in seconds>]\n"
"\n";


#define globus_l_args_error_fmt(fmt__, arg__)                               \
{                                                                           \
    fprintf(stderr,                                                         \
        "ERROR: " fmt__ "\n\nSyntax: %s\nUse -help to display full usage\n",\
        (arg__), usage);                                                    \
    globus_module_deactivate_all();                                         \
    exit(1);                                                                \
}

#define globus_l_args_error_fmt2(fmt__, arg1__, arg2__)                     \
{                                                                           \
    fprintf(stderr,                                                         \
        "ERROR: " fmt__ "\n\nSyntax: %s\nUse -help to display full usage\n",\
        (arg1__), (arg2__), usage);                                         \
    globus_module_deactivate_all();                                         \
    exit(1);                                                                \
}

#define globus_l_args_error_fmt3(fmt__, arg1__, arg2__, arg3__)             \
{                                                                           \
    fprintf(stderr,                                                         \
        "ERROR: " fmt__ "\n\nSyntax: %s\nUse -help to display full usage\n",\
        (arg1__), (arg2__), (arg3__), usage);                               \
    globus_module_deactivate_all();                                         \
    exit(1);                                                                \
}


/* argument processing stuff */
enum
{
    arg_resource_manager = 1,
    arg_job_duration,
    arg_load,
    arg_num_threads,
    arg_test_duration,
    arg_num = arg_test_duration
};


#define listname(x)                     x##_aliases
#define defname(x)                      x##_definition
#define funcname(x)                     x##_predicate_test
#define paramsname(x)                   x##_predicate_params

#define namedef(id, alias1, alias2)                                         \
    static char * listname(id)[] = {alias1, alias2, NULL}

#define flagdef(id, alias1, alias2)                                         \
    namedef(id, alias1, alias2);                                            \
    static globus_args_option_descriptor_t defname(id) = {                  \
         id, listname(id), 0, NULL, NULL}

#define oneargdef(id, alias1, alias2)                                       \
    namedef(id, alias1, alias2);                                            \
    static globus_args_valid_predicate_t funcname(id)[] = {NULL};           \
    static void * paramsname(id)[] = {NULL};                                \
    globus_args_option_descriptor_t defname(id) = {(int) id,                \
        (char **) listname(id), 1, funcname(id), (void **) paramsname(id)}


oneargdef(arg_resource_manager, "-r", "-resource-manager");
oneargdef(arg_job_duration, "-d", "-job-duration");
oneargdef(arg_load, "-l", "-load");
oneargdef(arg_num_threads, "-n", "-num-threads");
oneargdef(arg_test_duration, "-t", "-test-duration");


#define setupopt(id) args_options[id-1] = defname(id)
#define globus_l_args_init()                                                \
    setupopt(arg_resource_manager);                                         \
    setupopt(arg_job_duration);                                             \
    setupopt(arg_load);                                                     \
    setupopt(arg_num_threads);                                              \
    setupopt(arg_test_duration);

static globus_args_option_descriptor_t  args_options[arg_num];


void
globus_i_parse_arguments(
    int                                 argc,
    char **                             argv,
    globus_i_info_t *                   info)
{
    int                                 rc;
    char *                              program;
    globus_list_t *                     options_found = NULL;
    globus_args_option_instance_t *     instance;
    globus_list_t *                     list;

    globus_l_args_init();

    program = strrchr(argv[0], '/');
    program = program ? program + 1 : argv[0];

    if((rc = globus_args_scan(
        &argc,
        &argv,
        arg_num,
        args_options,
        program,
        &local_version,
        usage,
        usage,
        &options_found,
        NULL)) < 0)  /* error on argument line */
    {
        globus_module_deactivate_all();
        exit(rc == GLOBUS_FAILURE ? -4 : 0);
    }

    for(list = options_found;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        instance = globus_list_first(list);

        switch(instance->id_number)
        {
          case arg_resource_manager:
            info->resource_manager = globus_libc_strdup(instance->values[0]);
            break;
          case arg_job_duration:
            info->job_duration = atoi(instance->values[0]);
            break;
          case arg_load:
            info->load = atoi(instance->values[0]);
            break;
          case arg_num_threads:
            info->num_threads = atoi(instance->values[0]);
            break;
          case arg_test_duration:
            info->test_duration = atoi(instance->values[0]);
            break;
          default:
            globus_l_args_error_fmt(
                "parse panic, arg id = %d", instance->id_number);
            break;
        }
    }

    globus_args_option_instance_list_free(&options_found);

}



