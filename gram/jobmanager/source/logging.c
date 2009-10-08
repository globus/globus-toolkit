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
static FILE *                           globus_l_gram_log_fp = NULL;

static
void
globus_l_gram_logging_close(
    void *                              user_arg);

static
void
globus_l_gram_logging_write(
    globus_byte_t *                     buf,
    globus_size_t                       length,
    void *                              user_arg);

globus_logging_module_t                 globus_l_gram_logging_module =
{
    NULL,
    globus_l_gram_logging_write,
    globus_l_gram_logging_close,
    NULL
};

int
globus_gram_job_manager_logging_init(
    globus_gram_job_manager_config_t *  config)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    time_t                              now;
    struct tm *                         nowtm;

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
        globus_l_gram_logging_module.header_func =
                globus_logging_stdio_ng_module.header_func;
        now = time(NULL);
        nowtm = gmtime(&now);

        result = globus_logging_init(
                &globus_i_gram_job_manager_log_stdio,
                NULL,
                0,
                config->log_levels|GLOBUS_LOGGING_INLINE,
                &globus_l_gram_logging_module,
                (void *) config->stdiolog_directory);

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

static
void
globus_l_gram_logging_write(
    globus_byte_t *                     buf,
    globus_size_t                       length,
    void *                              user_arg)
{
    const char *                        dir = user_arg;
    time_t                              now;
    struct tm *                         now_tm;
    static char                         path[MAXPATHLEN] = "";
    static char                         last_path[MAXPATHLEN] = "";
    int                                 fd;
    int                                 flags;
    int                                 rc;

    now = time(NULL);
    now_tm = gmtime(&now);

    snprintf(
            path,
            sizeof(path),
            "%s/gram_%04d%02d%02d.log",
            dir,
            now_tm->tm_year + 1900,
            now_tm->tm_mon + 1,
            now_tm->tm_mday);

    if (strcmp(path, last_path) != 0)
    {
        strcpy(last_path, path);
        if (globus_l_gram_log_fp != NULL)
        {
            freopen(path, "a", globus_l_gram_log_fp);
        }
        else
        {
            globus_l_gram_log_fp = fopen(path, "a");
            globus_assert(globus_l_gram_log_fp != NULL);
            setvbuf(globus_l_gram_log_fp, NULL, _IONBF, 0);
        }

        fd = fileno(globus_l_gram_log_fp);
        flags = fcntl(fd, F_GETFL);
        globus_assert(flags >= 0);
        flags |= FD_CLOEXEC;
        rc = fcntl(fd, F_SETFL, flags);
        globus_assert(rc >= 0);
    }

    fwrite(buf, length, 1, globus_l_gram_log_fp);
}
/* globus_l_gram_logging_write() */

static
void
globus_l_gram_logging_close(
    void *                              user_arg)
{
    if (globus_l_gram_log_fp != NULL)
    {
        fclose(globus_l_gram_log_fp);
        globus_l_gram_log_fp = NULL;
    }
}
/* globus_l_gram_logging_close() */
