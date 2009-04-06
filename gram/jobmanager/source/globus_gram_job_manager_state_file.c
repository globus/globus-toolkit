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

#include "globus_gram_job_manager.h"

#include <string.h>


/**
 * Compute the name of the state file to use for this job request.
 *
 * Sets the value of the @a job_state_file member of the request structure.
 *
 * @param request
 *     The request to create the state file for.
 * @param state_file
 *     Pointer to set to the state file string. The caller is responsible for
 *     freeing this.
 * @param state_lock_file
 *     Pointer to set to the state file lockfile string. The caller is
 *     responsible for freeing this.
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed.
 */
int
globus_gram_job_manager_state_file_set(
    globus_gram_jobmanager_request_t *  request,
    char **                             state_file,
    char **                             state_lock_file)
{
    int                                 rc = GLOBUS_SUCCESS;

    if(request->config->job_state_file_dir == GLOBUS_NULL)
    {
        *state_file = globus_common_create_string(
                "%s/tmp/gram_job_state/%s.%s.%s",
                request->config->globus_location,
                request->config->logname ? request->config->logname : "globus",
                request->config->hostname,
                request->uniq_id);
    }
    else
    {
        *state_file = globus_common_create_string(
                "%s/job.%s.%s",
                request->config->job_state_file_dir,
                request->config->hostname,
                request->uniq_id);
    }

    if (*state_file == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto create_state_file_failed;
    }

    *state_lock_file = globus_common_create_string(
            "%s.lock",
            *state_file);

    if (*state_lock_file == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto create_state_lock_file_failed;
    }

    if (rc != GLOBUS_SUCCESS)
    {
create_state_lock_file_failed:
        free(*state_file);
        *state_file = NULL;
    }
create_state_file_failed:
    return rc;
}
/* globus_gram_job_manager_state_file_set() */

int
globus_l_gram_state_file_create_lock(
    globus_gram_jobmanager_request_t *  request)
{
    int                                 rc = GLOBUS_SUCCESS;

    globus_gram_job_manager_request_log(request,
                            "JM: Creating and locking state lock file\n");

    if (request->manager->lock_fd == -1)
    {
        /* We are not in single job manager mode */
        request->job_state_lock_fd = open( request->job_state_lock_file,
                                           O_RDWR | O_CREAT,
                                           S_IRUSR | S_IWUSR );
        if ( request->job_state_lock_fd < 0 )
        {
            globus_gram_job_manager_request_log(request,
                        "JM: Failed to open state lock file '%s', errno=%d\n",
                        request->job_state_lock_file, errno);

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;
            goto open_lock_file_failed;
        }

        rc = globus_gram_job_manager_file_lock(request->job_state_lock_fd);
        if ( rc != GLOBUS_SUCCESS )
        {
            globus_gram_job_manager_request_log(request,
                        "JM: Failed to lock state lock file '%s', errno=%d\n",
                        request->job_state_lock_file, errno);
            close( request->job_state_lock_fd );
            remove(request->job_state_lock_file);
            goto lock_file_failed;
        }
    }
    else
    {
        (void) unlink(request->job_state_lock_file);
        rc = symlink(request->manager->lock_path, request->job_state_lock_file);
        if (rc != GLOBUS_SUCCESS)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM: Error linking manager lock file to state lock file\n");
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;
            goto link_failed;
        }
    }

open_lock_file_failed:
lock_file_failed:
link_failed:
    return rc;
}
/* globus_gram_job_manager_state_file_create_lock() */

int
globus_gram_job_manager_state_file_write(
    globus_gram_jobmanager_request_t *  request)
{
    int                                 rc = GLOBUS_SUCCESS;
    FILE *                              fp;
    char                                tmp_file[1024];

    rc = globus_l_gram_state_file_create_lock(request);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    /*
     * We want the file update to be "atomic", so create a new temp file,
     * write the new information, close the new file, then rename the new
     * file on top of the old one. The rename is the atomic update action.
     */

    strcpy( tmp_file, request->job_state_file );
    strcat( tmp_file, ".tmp" );

    globus_gram_job_manager_request_log(request, "JM: Writing state file\n");

    fp = fopen( tmp_file, "w" );
    if ( fp == NULL )
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: Failed to open state file %s, errno=%d\n",
                tmp_file,
                errno);

        return GLOBUS_FAILURE;
    }

    rc = fprintf(fp, "%s\n", request->job_contact ? request->job_contact : " ");
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%4d\n", (int) request->jobmanager_state);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%4d\n", (int) request->status);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%4d\n", request->failure_code);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->job_id_string ? request->job_id_string : " ");
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->rsl_spec);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->cache_tag);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->config->jobmanager_type);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%d\n", request->two_phase_commit);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%s\n", request->scratchdir ? request->scratchdir : " ");
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%lu\n",
                 (unsigned long) request->manager->seg_last_timestamp);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%lu\n", (unsigned long) request->creation_time);
    if (rc < 0)
    {
        goto error_exit;
    }
    rc = fprintf(fp, "%lu\n", (unsigned long) request->queued_time);
    if (rc < 0)
    {
        goto error_exit;
    }

    fclose( fp );

    rc = rename( tmp_file, request->job_state_file );
    if (rc != 0)
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: Failed to rename state file\n");
        rc = GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;

error_exit:
    fclose(fp);
    remove(tmp_file);
    return GLOBUS_FAILURE;
}
/* globus_gram_job_manager_state_file_write() */

int
globus_gram_job_manager_state_file_read(
    globus_gram_jobmanager_request_t *  request)
{
    FILE *                              fp;
    char *                              buffer = NULL;
    size_t                              file_len;
    struct stat                         statbuf;
    int                                 rc;
    int                                 i;
    unsigned long                       tmp_timestamp;

    request->old_job_contact = NULL;

    globus_gram_job_manager_request_log(
            request,
            "JM: Attempting to read state file %s\n",
            request->job_state_file);

    if (stat(request->job_state_file, &statbuf) != 0)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NO_STATE_FILE;
    }
    file_len = (size_t) statbuf.st_size;
    buffer = malloc(file_len+1);
    if (buffer == NULL)
    {
        goto exit;
    }

    /* Try to obtain a lock on the state lock file */
    if ( request->job_state_lock_file != NULL &&
         request->job_state_lock_fd < 0 )
    {
        globus_gram_job_manager_request_log(request,
                                "JM: Locking state lock file\n");

        request->job_state_lock_fd = open( request->job_state_lock_file,
                                           O_RDWR );
        if ( request->job_state_lock_fd < 0 )
        {
            globus_gram_job_manager_request_log(request,
                        "JM: Failed to open state lock file '%s', errno=%d\n",
                        request->job_state_lock_file, errno);

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;

            goto free_buffer_exit;
        }

        rc = globus_gram_job_manager_file_lock(request->job_state_lock_fd);
        if ( rc != GLOBUS_SUCCESS )
        {
            if ( rc == GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE )
            {
                globus_gram_job_manager_request_log(request,
                        "JM: State lock file is locked, old jm is still alive\n");
                fp = fopen( request->job_state_file, "r" );
                if(fp)
                {
                    fgets( buffer, file_len, fp );
                    buffer[strlen(buffer)-1] = '\0';
                    request->old_job_contact = strdup(buffer);
                    fclose(fp);
                }
            }
            else
            {
                globus_gram_job_manager_request_log(request,
                        "JM: Failed to lock state lock file '%s', errno=%d\n",
                        request->job_state_lock_file, errno);
            }

            /* unlink here? */
            close( request->job_state_lock_fd );

            free(buffer);

            return rc;
        }
    }

    fp = fopen( request->job_state_file, "r" );
    if(!fp)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_NO_STATE_FILE;
    }

    if(fgets( buffer, file_len, fp )  == NULL)
    {
        goto error_exit;
    }
    /* job contact string */
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    request->restart_state = atoi( buffer );
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    globus_gram_job_manager_request_set_status_time(request,
                atoi( buffer ), statbuf.st_mtime);
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    request->failure_code = atoi( buffer );

    if(fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    if(strcmp(buffer, " ") != 0)
    {
        char * tmp;
        char * last = NULL;
        request->job_id_string = strdup( buffer );

        for (tmp = strtok_r(buffer, ",", &last);
             tmp != NULL;
             tmp = strtok_r(NULL, ",", &last))
        {
            char * id = strdup(tmp);

            globus_list_insert(&request->job_id_list, id);
        }

    }
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    request->rsl_spec = strdup( buffer );
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    request->cache_tag = strdup( buffer );
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    if((sscanf(buffer,"%d",&i)) < 1)
    {
        /* The last line we grabbed was the jobmanager_type. Now we
         * need to grab the two_phase_commit number. Older jobmanagers
         * don't print the jobmanager_type to the state file, hence
         * the check above.
         */
        if(fgets( buffer, file_len, fp ) == NULL)
        {
            goto error_exit;
        }
        buffer[strlen(buffer)-1] = '\0';
    }
    request->two_phase_commit = atoi(buffer);
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    if(strcmp(buffer, " ") != 0)
    {
        /*
         * Need to set the RSL substitution before reading the staging
         * state---otherwise we may get an RSL evaluation error
         */
        request->scratchdir = strdup(buffer);
        globus_symboltable_insert(
                &request->symbol_table,
                "SCRATCH_DIRECTORY",
                request->scratchdir);
    }
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    sscanf(buffer, "%lu", &tmp_timestamp);
    request->manager->seg_last_timestamp = (time_t) tmp_timestamp;

    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    sscanf(buffer, "%lu", &tmp_timestamp);
    request->creation_time = (time_t) tmp_timestamp;
    if (fgets( buffer, file_len, fp ) == NULL)
    {
        goto error_exit;
    }
    buffer[strlen(buffer)-1] = '\0';
    sscanf(buffer, "%lu", &tmp_timestamp);
    request->queued_time = (time_t) tmp_timestamp;

    rc = globus_gram_job_manager_staging_read_state(request,fp);
    if(rc != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    fclose(fp);

    free(buffer);

    return GLOBUS_SUCCESS;
error_exit:
    fclose(fp);
free_buffer_exit:
    if (buffer != NULL)
    {
        free(buffer);
    }
exit:
    return GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE;
}

int
globus_gram_job_manager_file_lock(
    int                                 fd)
{
    int rc;
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    while( (rc = fcntl( fd, F_SETLK, &fl )) < 0 )
    {
        if ( errno == EACCES || errno == EAGAIN )
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE;
            break;
        }
        else if ( errno != EINTR )
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE;
            break;
        }
    }
    return rc;
}
/* globus_gram_job_manager_file_lock() */
