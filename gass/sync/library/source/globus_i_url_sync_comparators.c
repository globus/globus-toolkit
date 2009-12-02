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
 * @file globus_i_url_sync_comparators.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_url_sync.h"
#include "globus_i_url_sync.h"
#include "globus_i_url_sync_handle.h"
#include "globus_i_url_sync_log.h"
#include "globus_ftp_client.h"
#include "globus_common.h"
#include "version.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/* Consts */

const char *        GLOBUS_L_URL_SYNC_MSLT_TYPE_FILE    = "file";
const char *        GLOBUS_L_URL_SYNC_MSLT_TYPE_DIR     = "dir";

/* Types */

typedef struct
{
    globus_mutex_t                          mutex;
    globus_cond_t                           cond;
    globus_bool_t                           done;
} globus_l_url_sync_monitor_t;

static
globus_result_t
globus_l_url_sync_ftpclient_mlst(
    globus_url_sync_endpoint_t *            endpoint);

static
void
globus_l_url_sync_ftpclient_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            handle,
    globus_object_t *                       error);

/* Functions */

/**
 * Existence check function.
 *
 * NOTE: This SHOULD be asynchronous but for now I made it synchronous to
 * simplify it.
 */
globus_result_t
globus_l_url_sync_compare_exists_func(
    void *                                      comparator_arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    globus_url_sync_compare_func_cb_t           callback_func,
    void *                                      callback_arg)
{
    globus_url_sync_comparison_result_t         comparison_result;
    GlobusFuncName(globus_l_url_sync_compare_exists_func);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER();

    /* Stat the source */
    globus_l_url_sync_ftpclient_mlst(source);

    /* Stat the destination */
    globus_l_url_sync_ftpclient_mlst(destination);

    /* Compare existence */
    if (source->stats.exists && destination->stats.exists)
    {
        comparison_result = GLOBUS_URL_SYNC_COMPARISON_SYNCHRONIZED;
    }
    else if (source->stats.exists)
    {
        comparison_result = GLOBUS_URL_SYNC_COMPARISON_RIGHT_OUT_OF_SYNC;
    }
    else
    {
        comparison_result = GLOBUS_URL_SYNC_COMPARISON_LEFT_OUT_OF_SYNC;
    }

    /* Not handling the ftpclient_mlst() results because... the ftp client
     * documentation seems to indicate that if a file does not exist, the
     * mlst operation may return an error. So an error is not really an error
     * in some cases... Ideally this should be better handled or confirmed in
     * the docs. */
    callback_func(callback_arg, source, destination, comparison_result, GLOBUS_NULL);
    return GLOBUS_SUCCESS;
}
/* globus_l_url_sync_compare_exists_func */

/**
 * A helper function for simplifying the MSLT operations.
 */
static
globus_result_t
globus_l_url_sync_ftpclient_mlst(
    globus_url_sync_endpoint_t *            endpoint)
{
    globus_result_t                         result;
    globus_l_url_sync_monitor_t             monitor;
    globus_byte_t *                         buffer;
    globus_size_t                           buffer_length;
    GlobusFuncName(globus_l_url_sync_ftp_mlst);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER();

    /* Initialize monitor */
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;

    /* Initialize buffer */
    buffer = GLOBUS_NULL;
    buffer_length = 0;

    /* MSLT */
    result = globus_ftp_client_mlst(
            endpoint->ftp_handle,
            endpoint->url,
            GLOBUS_NULL, /* operation attribute optional */
            &buffer,
            &buffer_length,
            globus_l_url_sync_ftpclient_complete_cb,
            &monitor);

    if (result != GLOBUS_SUCCESS)
        goto cleanexit;

    /* Wait for completion */
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    /* Parse MSLT buffer */
    if (buffer_length)
    {
        char            type[16];
        unsigned long   size;
        char            name[1024];
        struct tm       time_tm;
        type[0] = '\0';
        name[0] = '\0';
        size = 0;
        memset(&time_tm, 0, sizeof(struct tm));

        globus_assert(buffer);
        globus_i_url_sync_log_debug("buffer: %s\n", buffer);

        sscanf((char*)buffer,
                "Type=%[^;];Modify=%4d%2d%2d%2d%2d%2d;Size=%lu;%*s%s",
                type,
                &(time_tm.tm_year),
                &(time_tm.tm_mon),
                &(time_tm.tm_mday),
                &(time_tm.tm_hour),
                &(time_tm.tm_min),
                &(time_tm.tm_sec),
                &size,
                name);
        time_tm.tm_mon--;
        time_tm.tm_year -= 1900;

        globus_i_url_sync_log_debug(
                "Name: %s, Type: %s, Size: %lu, Modify: %s\n", name, type,
                size, asctime(&time_tm));

        /* Copy to endpoint statistics */
        endpoint->stats.exists = GLOBUS_TRUE;
        endpoint->stats.type = 
                strcmp(GLOBUS_L_URL_SYNC_MSLT_TYPE_DIR, type) ?
                    globus_url_sync_endpoint_type_file :
                    globus_url_sync_endpoint_type_dir;
        endpoint->stats.size = size;
        endpoint->stats.modify_tm = time_tm;

        globus_libc_free(buffer);
    }
    else
    {
        /* Put the error object and assigns the corresponding result */
        result = globus_error_put(
                GLOBUS_I_URL_SYNC_ERROR_REMOTE("FTP client MLST operation failed"));
    }

  cleanexit:
    globus_cond_destroy(&monitor.cond);
    globus_mutex_destroy(&monitor.mutex);
    return result;
}
/* globus_l_url_sync_ftpclient_mlst */

/*
 * The operation complete callback for the ftp client operation.
 */
static
void
globus_l_url_sync_ftpclient_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            handle,
    globus_object_t *                       error)
{
    globus_l_url_sync_monitor_t *           monitor;
    GlobusFuncName(globus_l_url_sync_ftpclient_complete_cb);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER();

    monitor = (globus_l_url_sync_monitor_t *) user_arg;

    if(error)
    {
        globus_i_url_sync_log_error(error);
    }

    /* Signal monitor */
    globus_mutex_lock(&monitor->mutex);
    {
        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}
/* globus_l_url_sync_ftpclient_complete_cb */



/* Variables */

globus_url_sync_comparator_t    globus_url_sync_comparator_exists =
{
    GLOBUS_NULL,
    globus_l_url_sync_compare_exists_func
};

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

