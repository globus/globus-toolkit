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

/*
 * $RCSfile$
 * $Date$
 * $Revision$
 */

#include "globus_i_url_sync_args.h"
#include "globus_url_sync.h"
#include "globus_ftp_client.h"
#include "globus_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Macros */

#define GLOBUS_L_URL_SYNC_DEBUG_PRINTF(...)         \
    if (globus_i_url_sync_args_debug)               \
    {                                               \
        globus_libc_fprintf(stderr, "%s (%d) %s: ", \
            __FILE__, __LINE__, _globus_func_name); \
        globus_libc_fprintf(stderr, __VA_ARGS__);   \
    }

#define GLOBUS_L_URL_SYNC_DEBUG_ENTER()             \
    if (globus_i_url_sync_args_debug)               \
    {                                               \
        globus_libc_fprintf(stderr, "%s (%d) %s: enter\n", \
            __FILE__, __LINE__, _globus_func_name); \
    }
#define GLOBUS_L_URL_SYNC_DEBUG_EXIT()             \
    if (globus_i_url_sync_args_debug)               \
    {                                               \
        globus_libc_fprintf(stderr, "%s (%d) %s: exit\n", \
            __FILE__, __LINE__, _globus_func_name); \
    }

/* Types */

typedef struct
{
    globus_mutex_t                          mutex;
    globus_cond_t                           cond;
    globus_bool_t                           done;
} globus_l_url_sync_main_monitor_t;

static void             globus_l_url_sync_cleanup(int m);

static void             globus_l_url_sync_main_complete_cb(
    void *                                  user_arg,
    globus_url_sync_handle_t                handle,
    globus_object_t *                       error);

static void             globus_l_url_sync_main_result_cb(
    void *					user_arg,
    globus_url_sync_handle_t                    handle,
    globus_object_t *				error,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int                                         result);

static
void
main_ftpclient_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            handle,
    globus_object_t *                       error);

static
void
globus_l_url_sync_ftpclient_nlst_read_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            handle,
    globus_object_t *                       error,
    globus_byte_t *                         buffer,
    globus_size_t                           length,
    globus_off_t                            offset,
    globus_bool_t                           eof);

/* Constants */

static const int                                   BUFLEN = 1024;

/* Static Variables */

static globus_module_descriptor_t   *modules[] = {
  GLOBUS_COMMON_MODULE,
  GLOBUS_FTP_CLIENT_MODULE,
  GLOBUS_URL_SYNC_MODULE
};
static int                          num_modules = 
    (sizeof(modules) / sizeof(globus_module_descriptor_t *));

/* Functions */

/*
 * main
 * The main routine for the 'globus-url-sync' program.
 */
int
main(int argc, char *argv[])
{
    globus_result_t                         result;
    globus_url_sync_handle_t                handle;
    int                                     i;
    globus_l_url_sync_main_monitor_t        monitor;
	globus_url_sync_comparator_t            chained_comparator;
    GlobusFuncName(main);

    /* Parse arguments */
    if ((result = globus_i_url_sync_parse_args(argc, argv)) != GLOBUS_SUCCESS)
    {
        globus_l_url_sync_cleanup(0);
        exit(EXIT_FAILURE);
    }

    GLOBUS_L_URL_SYNC_DEBUG_PRINTF("args parsed\n");

    /* Activate modules */
    for (i = 0; i < num_modules; i++)
    {
        if ((result = globus_module_activate(modules[i])) != GLOBUS_SUCCESS)
        {
            globus_libc_fprintf(stderr, 
                    "globus_module_activate(%d): %d\n", i, result);
            globus_l_url_sync_cleanup(i);
            exit(EXIT_FAILURE);
        }
    }

    GLOBUS_L_URL_SYNC_DEBUG_PRINTF("modules activated\n");

    /* Set log level, debug takes precedence over verbose */
    if (globus_i_url_sync_args_debug)
        globus_url_sync_log_set_level(GLOBUS_URL_SYNC_LOG_LEVEL_DEBUG);
    else if (globus_i_url_sync_args_verbose)
        globus_url_sync_log_set_level(GLOBUS_URL_SYNC_LOG_LEVEL_VERBOSE);

    /* Initialize monitor */
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;

	/* Initialize chain of comparators */
	globus_url_sync_chained_comparator_init(&chained_comparator);

	if (globus_i_url_sync_args_modify)
	{
		/* ...modify */
		globus_url_sync_chained_comparator_add(
				&chained_comparator,
				&globus_url_sync_comparator_modify);
	}

	if (globus_i_url_sync_args_size)
	{
		/* ...size */
		globus_url_sync_chained_comparator_add(
				&chained_comparator,
				&globus_url_sync_comparator_size);
	}

	/* ...exists, always checked, including filetype checking */
	globus_url_sync_chained_comparator_add(
			&chained_comparator,
			&globus_url_sync_comparator_exists);

	/* Initialize sync handle */
	globus_url_sync_handle_init(&handle, &chained_comparator);
	globus_url_sync_handle_set_cache_connections(handle,
			globus_i_url_sync_args_cache);
    GLOBUS_L_URL_SYNC_DEBUG_PRINTF("calling globus_url_sync\n");

    result = globus_url_sync(
            handle,
            globus_i_url_sync_args_source,
            globus_i_url_sync_args_destination,
            globus_l_url_sync_main_complete_cb,
            globus_l_url_sync_main_result_cb,
            &monitor);

    GLOBUS_L_URL_SYNC_DEBUG_PRINTF("called globus_url_sync\n");

    if (result != GLOBUS_SUCCESS)
    {
        GLOBUS_L_URL_SYNC_DEBUG_PRINTF("globus_url_sync failed\n");
        globus_libc_fprintf(stderr, "%s\n", globus_object_printable_to_string(
            globus_error_get(result)));
    }
    else
    {
        GLOBUS_L_URL_SYNC_DEBUG_PRINTF("waiting for complete callback\n");
        
        /* Wait for completion */
        globus_mutex_lock(&monitor.mutex);
        {
            while(!monitor.done)
            {
                globus_cond_wait(&monitor.cond, &monitor.mutex);
            }
        }
        globus_mutex_unlock(&monitor.mutex);
    }

    globus_url_sync_handle_destroy(&handle);
	globus_url_sync_chained_comparator_destroy(&chained_comparator);

    /* Destroy monitor */
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    /* Clean up and exit */
    globus_l_url_sync_cleanup(num_modules);
    exit(EXIT_SUCCESS);
}
/* main */

int
main_TESTING(int argc, char *argv[])
{

    #define                                 CRASH

    globus_ftp_client_handleattr_t          handleattr;
    globus_ftp_client_handle_t              handle;
    globus_result_t                         result;
    globus_l_url_sync_main_monitor_t        monitor;
    int                                     i;
    globus_byte_t *                         buffer;
    globus_size_t                           buffer_length;

    globus_libc_printf("Entering main()\n");

    char * url;
    if (argc < 2)
        url = "gsiftp://pooka.isi.edu/tmp";
    else
        url = argv[1];

    globus_libc_printf("URL Argument: %s\n", url);

    /* Activate modules */
    for (i = 0; i < num_modules; i++)
    {
        if ((result = globus_module_activate(modules[i])) != GLOBUS_SUCCESS)
        {
            globus_libc_fprintf(stderr, 
                    "globus_module_activate(%d): %d\n", i, result);
            globus_l_url_sync_cleanup(i);
            exit(EXIT_FAILURE);
        }
    }

    /* Initialize buffer length */
    buffer_length = 0;

    /* Initialize FTP handle and attributes */
    globus_ftp_client_handleattr_init(&handleattr);
    globus_ftp_client_handleattr_set_cache_all(&handleattr, GLOBUS_TRUE);
    globus_ftp_client_handle_init(&handle, &handleattr);

    /* Initialize monitor */
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;

    globus_libc_printf("Call 1st MLST\n");

    /* FTP operation */
    result = globus_ftp_client_mlst(
            &handle,
            url,
            GLOBUS_NULL,
            &buffer,
            &buffer_length,
            main_ftpclient_complete_cb,
            &monitor);
    
    if (result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(stderr, "%s\n",
				globus_error_print_friendly(globus_error_get(result)));
        exit(EXIT_FAILURE);
    }

    /* Wait for completion */
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    globus_libc_printf("Finished 1st MLST\n");

    if (buffer_length)
        globus_libc_free(buffer);


    #if defined (CRASH)

    globus_libc_printf("Call 2nd MLST\n");

    /* FTP operation */
    result = globus_ftp_client_mlst(
            &handle,
            url,
            GLOBUS_NULL,//&attr,
            &buffer,
            &buffer_length,
            main_ftpclient_complete_cb,
            &monitor);

    if (result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(stderr, "%s\n",
				globus_error_print_friendly(globus_error_get(result)));
        exit(EXIT_FAILURE);
    }

    /* Wait for completion */
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);
        }
    }
    globus_mutex_unlock(&monitor.mutex);

    globus_libc_printf("Finished 2nd MLST\n");

    if (buffer_length)
        globus_libc_free(buffer);

    #endif /* CRASH */

    /* Destroy FTP handle and attributes */
    globus_ftp_client_handle_destroy(&handle);
    globus_ftp_client_handleattr_destroy(&handleattr);

    globus_libc_printf("Cleaning up and exiting\n");

    /* Clean up and exit */
    globus_l_url_sync_cleanup(num_modules);
    exit(EXIT_SUCCESS);
}
/* main_TESTING */

/*
 * The operation complete callback for the ftp client operation.
 */
static
void
main_ftpclient_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            handle,
    globus_object_t *                       error)
{
    globus_l_url_sync_main_monitor_t *      monitor;

    if (error)
    {
        globus_libc_fprintf(stderr, "%s\n",
				globus_error_print_friendly(error));
    }

    /* Signal monitor */
    monitor = (globus_l_url_sync_main_monitor_t *) user_arg;
    globus_mutex_lock(&monitor->mutex);
    {
        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);

    globus_libc_printf("FTP operation completed\n");
}
/* main_ftpclient_complete_cb */

/*
 * globus_l_url_sync_cleanup
 * Cleans up resources used by the program.
 */
static
void
globus_l_url_sync_cleanup(int m)
{
    while (--m >= 0)
        globus_module_deactivate(modules[m]);
}

/*
 * globus_l_url_sync_main_complete_cb
 */
static
void
globus_l_url_sync_main_complete_cb(
    void *                                  user_arg,
    globus_url_sync_handle_t                handle,
    globus_object_t *                       error)
{
    globus_l_url_sync_main_monitor_t *      monitor;
    GlobusFuncName(globus_l_url_sync_main_complete_cb);
    GLOBUS_L_URL_SYNC_DEBUG_ENTER();

    if (error)
    {
        globus_libc_fprintf(stderr, "%s\n",
				globus_error_print_friendly(error));
    }

    /* Signal monitor */
    GLOBUS_L_URL_SYNC_DEBUG_PRINTF("signalling condition\n");
    monitor = (globus_l_url_sync_main_monitor_t *) user_arg;
    globus_mutex_lock(&monitor->mutex);
    {
        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
    GLOBUS_L_URL_SYNC_DEBUG_EXIT();
}
/* globus_l_url_sync_main_complete_cb */


/*
 * globus_l_url_sync_main_result_cb
 */
static
void
globus_l_url_sync_main_result_cb(
    void *					user_arg,
    globus_url_sync_handle_t                    handle,
    globus_object_t *                           error,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int                                         result)
{
    GlobusFuncName(globus_l_url_sync_main_result_cb);
    GLOBUS_L_URL_SYNC_DEBUG_ENTER();

    globus_assert(handle);
    globus_assert(source);
    globus_assert(source->url);
    globus_assert(destination);
    globus_assert(destination->url);

    if (globus_i_url_sync_args_verbose || globus_i_url_sync_args_debug)
    {
        /* Verbose results format */
        globus_libc_printf("%d {%s%s} \"%s\" \"%s\"\n",
				result,
				(error) ? "ERROR=" : "",
				(error) ? globus_error_get_short_desc(error) : "",
				source->url,
				destination->url);

	/* Additional details for debug usage */
	if (globus_i_url_sync_args_debug)
	{
	    globus_libc_fprintf(stderr, "%s\n",
				globus_error_print_friendly(error));
	}
    }
    else if (error)
    {
        /* print readable error message to stderr */
        globus_libc_fprintf(stderr, "ERROR=%s; \"%s\" \"%s\"\n",
			    globus_error_get_short_desc(error),
			    source->url, destination->url);
    }
    else if (result)
    {
        if (source->stats.type != globus_url_sync_endpoint_type_dir)
	    /* globus-url-copy format */
	    globus_libc_printf("\"%s\" \"%s\"\n", source->url, destination->url);
    }
    GLOBUS_L_URL_SYNC_DEBUG_EXIT();
}
/* globus_l_url_sync_main_result_cb */


/*
 * The data callback for the nlst operation.
 */
static
void
globus_l_url_sync_ftpclient_nlst_read_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            handle,
    globus_object_t *                       error,
    globus_byte_t *                         buffer,
    globus_size_t                           length,
    globus_off_t                            offset,
    globus_bool_t                           eof)
{
    globus_result_t                         result;
    char                                    buf[length+1];

    if (error)
    {
        globus_libc_fprintf(stderr, "%s\n",
            globus_object_printable_to_string(error));
    }
    else if (!eof)
    {
        globus_libc_fprintf(stdout, 
                "globus_l_url_sync_ftpclient_nlst_read_cb: %d bytes read\n", 
                (int) length);
        globus_libc_snprintf(buf, length, "%s", buffer);
        globus_libc_fprintf(stdout, "%s\n", buf);

        /* Register read operation */
        result = globus_ftp_client_register_read(handle, buffer, BUFLEN, 
                globus_l_url_sync_ftpclient_nlst_read_cb, GLOBUS_NULL);

        /* Report error and abort, if failed */
        if (result != GLOBUS_SUCCESS)
        {
            globus_libc_fprintf(stderr, "%s\n",
                globus_object_printable_to_string(globus_error_get(result)));

            globus_ftp_client_abort(handle);
        }
    }
    else
    {
        globus_libc_fprintf(stdout, 
          "globus_l_url_sync_ftpclient_nlst_read_cb: eof reached (%d bytes remain)\n",
	  (int) length);
        globus_libc_snprintf(buf, length, "%s", buffer);
        globus_libc_fprintf(stdout, "%s\n", buf);
    }
}
/* globus_l_url_sync_ftpclient_nlst_read_cb */


