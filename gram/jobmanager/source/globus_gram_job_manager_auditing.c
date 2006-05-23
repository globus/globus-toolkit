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

#include "globus_gram_job_manager.h"

static
int
globus_l_gram_audit_get_username(
    char **                             username);

static
int
globus_l_gram_audit_write_timestamp(
    FILE *                              f,
    time_t                              when,
    const char *                        delim);

static
int
globus_l_gram_audit_write_string(
    FILE *                              f,
    const char *                        s,
    const char *                        delim);

int
globus_gram_job_manager_auditing_file_write(
    globus_gram_jobmanager_request_t *  request)
{
    char *                              filename;
    FILE *                              auditing_file;
    time_t                              now;
    struct tm                           tmv;
    struct tm *                         tmp;
    char *                              name;
    int                                 rc;

    if (request->auditing_dir == NULL)
    {
        rc = GLOBUS_SUCCESS;

        goto out;
    }

    rc = globus_l_gram_audit_get_username(&name);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto out;
    }

    now = time(NULL);
    if (now <= 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto free_name_out;
    }

    tmp = globus_libc_gmtime_r(&now, &tmv);

    filename = globus_common_create_string(
            "%s/%04d%02d%02dT%02d:%02d:%02d-%s-%s.gramaudit",
            request->auditing_dir,
            tmp->tm_year + 1900,
            tmp->tm_mon + 1,
            tmp->tm_mday,
            tmp->tm_hour,
            tmp->tm_min,
            tmp->tm_sec,
            name,
            request->uniq_id);

    if (filename == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto free_name_out;
    }

    auditing_file = fopen(filename, "w");

    if (auditing_file == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto free_filename_out;
    }

    /* job_grid_id */
    rc = globus_l_gram_audit_write_string(auditing_file, request->job_contact, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* local_job_id */
    rc = globus_l_gram_audit_write_string(auditing_file, request->job_id, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* submission_job_id (WS-GRAM only) */
    rc = globus_l_gram_audit_write_string(auditing_file, NULL, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* subject name */
    rc = globus_l_gram_audit_write_string(auditing_file, request->subject, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* username */
    rc = globus_l_gram_audit_write_string(auditing_file, name, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* creation_time */
    rc = globus_l_gram_audit_write_timestamp(auditing_file, request->creation_time, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* queued_time */
    rc = globus_l_gram_audit_write_timestamp(auditing_file, request->queued_time, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* stage_in_gid (WS-GRAM only) */
    rc = globus_l_gram_audit_write_string(auditing_file, NULL, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* stage_out_grid_id (WS-GRAM only) */
    rc = globus_l_gram_audit_write_string(auditing_file, NULL, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* clean_up_grid_id (WS-GRAM only) */
    rc = globus_l_gram_audit_write_string(auditing_file, NULL, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }
    /* globus_toolkit_version */
    rc = globus_l_gram_audit_write_string(auditing_file, request->globus_version, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* resource_manager_type */
    rc = globus_l_gram_audit_write_string(auditing_file, request->jobmanager_type, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* job_description */
    rc = globus_l_gram_audit_write_string(auditing_file, request->rsl_spec, ",");
    if (rc != 0)
    {
        goto close_filename_out;
    }

    /* success_flag */
    rc = globus_l_gram_audit_write_string(auditing_file,
            request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE ? "true" : "false",
            "\n");

    if (rc != 0)
    {
        goto close_filename_out;
    }

close_filename_out:
    fclose(auditing_file);
    if (rc != 0)
    {
        remove(filename);
    }
free_filename_out:
    free(filename);
free_name_out:
    free(name);
out:
    return rc;
}
/* globus_gram_job_manager_auditing_file_write() */

static
int
globus_l_gram_audit_get_username(
    char **                             username)
{
    struct passwd                       pwd;
    struct passwd *                     res;
    int                                 rc;
    char                                buffer[128];

    rc = globus_libc_getpwuid_r(
            getuid(),
            &pwd,
            buffer,
            sizeof(buffer),
            &res);

    if (rc != 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;

        goto out;
    }

    *username = globus_libc_strdup(pwd.pw_name);

    if (*username == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto out;
    }

out:
    return rc;
}
/* globus_l_gram_audit_get_username() */

static
int
globus_l_gram_audit_write_string(
    FILE *                              f,
    const char *                        s,
    const char *                        delim)
{
    int                                 rc;

    if (s == NULL)
    {
        rc = fprintf(f, "\"NULL\"%s", delim);

        return rc >= 0 ? GLOBUS_SUCCESS : GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
    }

    rc = fputc('"', f);
    if (rc == EOF)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
    }
    while (*s != '\0')
    {
        if (*s == '"')
        {
            rc = fprintf(f, "&quot;");
        }
        else
        {
            rc = fputc(*s, f);
        }

        if (rc < 0)
        {
            return GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
        }
        s++;
    }
    rc = fputc('"', f);
    if (rc == EOF)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
    }
    rc = fprintf(f, delim);
    return rc >= 0 ? GLOBUS_SUCCESS : GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
}
/* globus_l_gram_audit_write_string() */

static
int
globus_l_gram_audit_write_timestamp(
    FILE *                              f,
    time_t                              when,
    const char *                        delim)
{
    int                                 rc;
    char *                              t;
    char *                              tmp;
    struct tm                           tmv;
    struct tm *                         tm_p;
    char tbuf[26];

    if (when == 0)
    {
        rc = fprintf(f, "\"NULL\"%s", delim);
        return rc >= 0 ? GLOBUS_SUCCESS : GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
    }
    tm_p = globus_libc_gmtime_r(&when, &tmv);
    if (tm_p == NULL)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
    }
    t = asctime_r(tm_p, tbuf);
    if (t == NULL)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
    }
    tmp = strchr(t, '\n');
    if (tmp)
    {
       *tmp = '\0';
    }
    tmp = strrchr(t, ' ');
    *tmp = '\0';

    rc = fprintf(f, "\"%s UTC %s\"%s", t, tmp+1, delim);

    return rc >= 0 ? GLOBUS_SUCCESS : GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES;
}
/* globus_l_gram_audit_write_timestamp() */
