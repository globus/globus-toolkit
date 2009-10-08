/*
 * Copyright 1999-2009 University of Chicago
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

#include "globus_common.h"
#include "globus_gram_job_manager.h"
#include "globus_gsi_system_config.h"
#include "globus_callout.h"
#include "globus_callout_constants.h"
#include "globus_gram_jobmanager_callout_error.h"

#include <string.h>

globus_logging_handle_t                 globus_i_gram_job_manager_log_stdio;
globus_logging_handle_t                 globus_i_gram_job_manager_log_sys;
globus_logging_module_t                 globus_l_gram_logging_module;

int
globus_gram_job_manager_logging_init(
    globus_gram_job_manager_config_t *  config)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    time_t                              now;
    struct tm *                         nowtm;
    char *                              path;
    FILE *                              fp;


    if (config->syslog_enabled)
    {
        result = globus_logging_init(
                &globus_i_gram_job_manager_log_sys,
                NULL,
                0,
                config->log_levels|GLOBUS_LOGGING_INLINE,
                &globus_logging_syslog_ng_module,
                NULL);

        if (result != GLOBUS_SUCCESS)
        {
            char * errstr = globus_error_print_friendly(
                    globus_error_peek(result));

            fprintf(stderr, "Error initializing logging: %s\n", errstr);
            exit(1);
        }
    }
    else
    {
        globus_i_gram_job_manager_log_sys = NULL;
    }

    if (config->stdiolog_enabled)
    {
        now = time(NULL);
        nowtm = gmtime(&now);

        path = globus_common_create_string(
                "%s/gram_%04d%02d%02d.log",
                config->stdiolog_directory,
                nowtm->tm_year + 1900,
                nowtm->tm_mon + 1,
                nowtm->tm_mday);

        if (path == NULL)
        {
            fprintf(stderr, "Error constructing logging path\n");
        }

        fp = fopen(path, "a");
        setvbuf(fp, NULL, _IONBF, 0);
        result = globus_logging_init(
                &globus_i_gram_job_manager_log_stdio,
                NULL,
                0,
                config->log_levels|GLOBUS_LOGGING_INLINE,
                &globus_logging_stdio_ng_module,
                fp);

        if (result != GLOBUS_SUCCESS)
        {
            char * errstr = globus_error_print_friendly(
                    globus_error_peek(result));

            fprintf(stderr, "Error initializing logging: %s\n", errstr);
            exit(1);
        }
    }
    return result;
}
/* globus_gram_job_manager_logging_init() */

char *
globus_gram_prepare_log_string(
    const char *                        instr)
{
    char *                              outstr;
    int                                 i = 0;
    if (instr == NULL)
    {
        return NULL;
    }
    outstr = malloc(2*strlen(instr) + 1);
    if (outstr == NULL)
    {
        return NULL;
    }

    while (*instr != 0)
    {
        if (*instr == '\n')
        {
            outstr[i++] = '\\';
            outstr[i++] = 'n';
            instr++;
        }
        else if (*instr == '\\')
        {
            outstr[i++] = '\\';
            outstr[i++] = '\\';
            instr++;
        }
        else if (*instr == '"')
        {
            outstr[i++] = '\\';
            outstr[i++] = '"';
            instr++;
        }
        else
        {
            outstr[i++] = *(instr++);
        }
    }
    outstr[i++] = '\0';

    return outstr;
}
/* globus_gram_prepare_log_string() */
