/*
 * Copyright 1999-2008 University of Chicago
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
 * @file globus_gram_job_manager.c LRM-Specific state
 *
 * CVS Information:
 * 
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */

#include "globus_common.h"
#include "globus_gram_job_manager.h"

static
void
globus_l_gram_job_manager_open_logfile(
    globus_gram_job_manager_t *         manager);
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * Initialize runtime state associated with a LRM instance
 *
 * @param manager
 *     Job manager structure to initialize
 * @param config
 *     Configuration parameters defining this service instance
 *
 * @retval GLOBUS_SUCCESS
 *     Success.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *     Malloc failed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_REQUEST
 *     Invalid request.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES
 *     No resources.
 */
int
globus_gram_job_manager_init(
    globus_gram_job_manager_t *         manager,
    globus_gram_job_manager_config_t *  config)
{
    int                                 rc;

    if (manager == NULL || config == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto out;
    }

    manager->config = config;

    rc = globus_fifo_init(&manager->seg_event_queue);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto failed_seg_event_queue_init;
    }

    manager->seg_last_timestamp = (time_t) 0;

    globus_l_gram_job_manager_open_logfile(manager);

    rc = globus_gram_job_manager_validation_init(manager);
    if (rc != GLOBUS_SUCCESS)
    {
        goto validation_init_failed;
    }

    rc = globus_hashtable_init(
            &manager->request_hash,
            13,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto request_hashtable_init_failed;
    }

    rc = globus_gram_protocol_allow_attach(
            &manager->url_base,
            globus_gram_job_manager_query_callback,
            manager);

    if (rc != GLOBUS_SUCCESS)
    {
        goto allow_attach_failed;
    }

    if (rc != GLOBUS_SUCCESS)
    {
allow_attach_failed:
        globus_hashtable_destroy(&manager->request_hash);
request_hashtable_init_failed:
        globus_gram_job_manager_validation_destroy(
                manager->validation_records);
        manager->validation_records = NULL;
        
validation_init_failed:
        if (manager->jobmanager_logfile)
        {
            free(manager->jobmanager_logfile);
            manager->jobmanager_logfile = NULL;
        }
        if (manager->jobmanager_log_fp)
        {
            fclose(manager->jobmanager_log_fp);
            manager->jobmanager_log_fp = NULL;
        }
        globus_fifo_destroy(&manager->seg_event_queue);
failed_seg_event_queue_init:
        ;
    }
out:
    return rc;
}
/* globus_gram_job_manager_init() */

/**
 * Destroy job manager state
 * 
 * Memory used for runtime processing is freed, the GRAM listener and the SEG
 * are shut down.
 * 
 * @param manager
 *     Manager to destroy
 */
void
globus_gram_job_manager_destroy(
    globus_gram_job_manager_t *         manager)
{
    if (!manager)
    {
        return;
    }
    globus_gram_job_manager_shutdown_seg(manager->config->seg_module);

    globus_gram_protocol_callback_disallow(manager->url_base);
    free(manager->url_base);
    manager->url_base = NULL;


    globus_gram_job_manager_validation_destroy(
            manager->validation_records);
    manager->validation_records = NULL;
    
    if (manager->jobmanager_logfile)
    {
        free(manager->jobmanager_logfile);
        manager->jobmanager_logfile = NULL;
    }
    if (manager->jobmanager_log_fp)
    {
        fclose(manager->jobmanager_log_fp);
        manager->jobmanager_log_fp = NULL;
    }
    globus_fifo_destroy(&manager->seg_event_queue);

    return;
}
/* globus_gram_job_manager_destroy() */
static
void
globus_l_gram_job_manager_open_logfile(
    globus_gram_job_manager_t *         manager)
{
    if (manager->config->logfile_flag == GLOBUS_GRAM_JOB_MANAGER_DONT_SAVE)
    {
        /* don't write a log file */
        manager->jobmanager_logfile = globus_libc_strdup("/dev/null");
    }
    else
    {
        /*
         * Open the gram logfile just for testing!
         */
        manager->jobmanager_logfile = globus_common_create_string(
                "%s/gram_job_mgr_%lu.log",
                manager->config->home,
                (unsigned long) getpid());

        manager->jobmanager_log_fp =
                fopen(manager->jobmanager_logfile, "a");
	
	if (manager->jobmanager_log_fp == NULL)
        {
            free(manager->jobmanager_logfile);
            manager->jobmanager_logfile = globus_libc_strdup("/dev/null");
        }
    }

    if (manager->jobmanager_log_fp == NULL)
    {
	manager->jobmanager_log_fp =
                fopen(manager->jobmanager_logfile, "a");
    }

    if (manager->jobmanager_log_fp != NULL)
    {
        int fd;

	setbuf(manager->jobmanager_log_fp, NULL);

        fd = fileno(manager->jobmanager_log_fp);

        while(fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        {
            if(errno != EINTR)
            {
                break;
            }
        }
    }

    return;
}
/* globus_l_gram_job_manager_open_logfile() */

int
globus_gram_job_manager_read_rsl(
    globus_gram_job_manager_t *         manager,
    char **                             rsl,
    char **                             contact,
    int *                               job_state_mask)
{
    int                                 rc;
    char *                              args_fd_str;
    int                                 args_fd;
    globus_size_t                       jrbuf_size;
    globus_byte_t                       buffer[
                                        GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];

    args_fd_str = getenv("GRID_SECURITY_HTTP_BODY_FD");
    if ((!args_fd_str) || ((args_fd = atoi(args_fd_str)) == 0))
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    jrbuf_size = (globus_size_t) lseek(args_fd, 0, SEEK_END);
    (void) lseek(args_fd, 0, SEEK_SET);
    if (jrbuf_size > GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE)
    {
        globus_gram_job_manager_log(manager, "JM: RSL file too big\n");
        return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    if (read(args_fd, buffer, jrbuf_size) != jrbuf_size)
    {
        globus_gram_job_manager_log(
                manager,
                "JM: Error reading the RSL file\n");
        return GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED;
    }
    close(args_fd);

    rc = globus_gram_protocol_unpack_job_request(
            buffer,
            jrbuf_size,
            job_state_mask,
            contact,
            rsl);
    if(rc != GLOBUS_SUCCESS)
    {
        globus_gram_job_manager_log(
                manager,
                "JM: request unpack failed because %s\n",
                globus_gram_protocol_error_string(rc));
        return rc;
    }
    return rc;
}
/* globus_gram_job_manager_read_rsl() */


int
globus_gram_job_manager_log(
    globus_gram_job_manager_t *         manager,
    const char *                        format,
    ...)
{
    struct tm *                         curr_tm;
    time_t                              curr_time;
    int                                 rc;
    va_list                             ap;

    if (!manager)
    {
        return -1;
    }

    if ( !manager->jobmanager_log_fp)
    {
        return -1;
    }

    time(&curr_time);
    curr_tm = localtime(&curr_time);

    fprintf(manager->jobmanager_log_fp,
            "%d/%d %02d:%02d:%02d ",
             curr_tm->tm_mon + 1, curr_tm->tm_mday,
             curr_tm->tm_hour, curr_tm->tm_min,
             curr_tm->tm_sec );

    va_start(ap, format);
    rc = vfprintf(manager->jobmanager_log_fp, format, ap);
    va_end(ap);

    return rc;
}
/* globus_gram_job_manager_log() */
