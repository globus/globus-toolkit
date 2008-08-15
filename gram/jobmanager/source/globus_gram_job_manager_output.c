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
#include "globus_gass_transfer.h"
#include "globus_ftp_client.h"
#include "globus_io.h"
#include <string.h>

/*
 * Module-specific constants
 */
enum
{
    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_POLL_PERIOD = 10,
    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_BUFFER_SIZE = 4096
};

typedef enum
{
    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_NEW,
    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_OPEN,
    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_VALID,
    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_CLOSE,
    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_FAILED,
    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID
}
globus_gram_job_manager_output_destination_state_t;

/*
 * Module specific types.
 */
typedef struct globus_l_gram_job_manager_output_info_t
{
    int					stdout_fd;
    int					stderr_fd;
    globus_list_t *			stdout_destinations;
    globus_list_t *			stderr_destinations;
    globus_off_t			stdout_size;
    globus_off_t			stderr_size;
    globus_callback_handle_t		callback_handle;
    globus_bool_t			close_flag;
    int					pending_opens;
    int					open_failure_code;
}
globus_l_gram_job_manager_output_info_t;

typedef enum
{
    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_UNKNOWN,
    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FILE,
    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_CACHE,
    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_GASS,
    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FTP
}
globus_gram_job_manager_output_destination_type_t;

typedef enum
{
    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDOUT,
    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDERR
}
globus_gram_job_manager_output_which_t;

typedef struct
{
    globus_gram_jobmanager_request_t *	request;
    globus_gram_job_manager_output_destination_type_t
					type;
    globus_gram_job_manager_output_destination_state_t
    					state;
    globus_gram_job_manager_output_which_t
					which;

    char *				url;
    char *				tag;
    globus_off_t			position;

    union
    {
	globus_io_handle_t		file;
	globus_gass_transfer_request_t	gass;
	globus_ftp_client_handle_t	ftp;
    }
    handle;
    int 				callback_count;
    int					possible_write_count;

}
globus_l_gram_job_manager_output_destination_t;

/*
 * Module Specific Prototypes
 */
static
int
globus_l_gram_job_manager_output_insert_urls(
    globus_gram_jobmanager_request_t *	request,
    globus_list_t *			value_list,
    globus_gram_job_manager_output_which_t
    					which,
    globus_bool_t			recursive);

static
int
globus_l_gram_job_manager_output_get_positions(
    globus_gram_jobmanager_request_t *	request,
    globus_list_t *			value_list,
    globus_list_t *			destinations);

static
void
globus_l_gram_job_manager_output_poll(
    void *				user_arg);

static
void
globus_l_gram_job_manager_output_close_kickout(
    void *				user_arg);

static
void
globus_l_gram_job_manager_output_poll_locked(
    globus_gram_jobmanager_request_t *	request);

static
globus_bool_t
globus_l_gram_job_manager_url_is_dev_null(
    const char *			url);

static
int
globus_l_gram_job_manager_output_destination_flush(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination,
    unsigned char *			buffer);

static
int
globus_l_gram_job_manager_output_destination_open(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination);
static
void
globus_l_gram_job_manager_output_destination_close(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination);
static
void
globus_l_gram_job_manager_output_get_type(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
					destination,
    char *				filename);

static
void
globus_l_gram_job_manager_gass_open_callback(
    void *				arg,
    globus_gass_transfer_request_t	gass_request);

static
void
globus_l_gram_job_manager_output_file_write_callback(
    void *				user_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes);

static
void
globus_l_gram_job_manager_output_gass_write_callback(
    void *				arg,
    globus_gass_transfer_request_t	gass_request,
    globus_byte_t *			bytes,
    globus_size_t			length,
    globus_bool_t			last_data);

static
void
globus_l_gram_job_manager_output_ftp_write_callback(
    void *				arg,
    globus_ftp_client_handle_t *	handle,
    globus_object_t *			error,
    globus_byte_t *			buffer,
    globus_size_t			length,
    globus_off_t			offset,
    globus_bool_t			eof);

static
void
globus_l_gram_job_manager_file_close_callback(
    void *				user_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);

static
void
globus_l_gram_job_manager_output_gass_close_callback(
    void *				arg,
    globus_gass_transfer_request_t 	gass_request,
    globus_byte_t *			bytes,
    globus_size_t			length,
    globus_bool_t			last_data);

static
void
globus_l_gram_job_manager_output_ftp_close_callback(
    void *				arg,
    globus_ftp_client_handle_t *	handle,
    globus_object_t *			error);

static
void
globus_l_gram_job_manager_output_file_close(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination);
static
void
globus_l_gram_job_manager_output_gass_close(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination);

static
void
globus_l_gram_job_manager_output_ftp_close(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination);
static
void
globus_l_gram_job_manager_output_close_done(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
					destination);

/**
 * Initialize the output information structure. This structure
 * is used to keep track of the destinations where we will be sending stdout
 * and stderr.
 */
int
globus_gram_job_manager_output_init(
    globus_gram_jobmanager_request_t *	request)
{
    request->output = globus_libc_malloc(
	    sizeof(globus_l_gram_job_manager_output_info_t));

    if(!request->output)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

    request->output->stdout_fd = -1;
    request->output->stderr_fd = -1;
    request->output->stdout_destinations = NULL;
    request->output->stderr_destinations = NULL;
    request->output->callback_handle = GLOBUS_HANDLE_TABLE_NO_HANDLE;
    request->output->pending_opens = 0;
    request->output->close_flag = GLOBUS_FALSE;
    request->output->open_failure_code = 0;

    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_output_init() */

/**
 * Configure the request to send output to the specified URLs.
 *
 * This function creates a list of destination structures which
 * are initialized to the values of the URLs and positions indicated
 * by the values of the stdout and stdout_position or stderr and
 * stderr_position RSL relations.
 *
 * @param request
 *        The GRAM Job Request
 * @param type
 *        A string containing either GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM or
 *        GLOBUS_GRAM_PROTOCOL_STDERR_PARAM
 * @param url_list
 *        List of the values of the stdout or stderr relation.
 * @param position_list
 *        List of the values of the stdout_position or stderr_position
 *        relation.
 */
int
globus_gram_job_manager_output_set_urls(
    globus_gram_jobmanager_request_t *	request,
    const char *			type,
    globus_list_t *			url_list,
    globus_list_t *			position_list)
{
    int					rc = GLOBUS_SUCCESS;
    globus_list_t *			tmp_list;
    globus_list_t **			destinations;
    globus_l_gram_job_manager_output_destination_t *
					destination;
    globus_gram_job_manager_output_which_t
					which;

    if(strcmp(type, GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM) == 0)
    {
	destinations = &request->output->stdout_destinations;
	which = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDOUT;
    }
    else
    {
	globus_assert(strcmp(type, GLOBUS_GRAM_PROTOCOL_STDERR_PARAM) == 0);

	destinations = &request->output->stderr_destinations;
	which = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDERR;
    }

    /*
     * If this is called for a restart RSL, and we have
     * stdout (or stderr) in the new RSL, we will throw away the destinations
     * in the original RSL---the same effect as a stdio_update signal.
     */
    if(request->jm_restart && url_list != NULL)
    {
	while(!globus_list_empty(*destinations))
	{
	    destination = globus_list_remove(destinations, *destinations);

	    globus_libc_free(destination->url);
	    if(destination->tag)
	    {
		globus_libc_free(destination->tag);
	    }
	    globus_libc_free(destination);
	}
    }

    /* Get URL strings from url_list */
    rc = globus_l_gram_job_manager_output_insert_urls(
	    request,
	    url_list,
	    which,
	    GLOBUS_FALSE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    tmp_list = *destinations;
    *destinations = NULL;

    /*
     * Reverse the list to match the order of the position_list.
     */
    while(!globus_list_empty(tmp_list))
    {
	globus_list_insert(destinations,
		           globus_list_remove(&tmp_list, tmp_list));
    }

    /* Get positions from the position_list */
    rc = globus_l_gram_job_manager_output_get_positions(
	    request,
	    position_list,
	    *destinations);
    if(rc != GLOBUS_SUCCESS)
    {
	return GLOBUS_FAILURE;
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_output_set_urls() */

/**
 * Open output destinations.
 *
 * Open the (potentially remote) output locations for the stdout and
 * stderr files for this job request. This will register a callback
 * which processes the state machine once the output URLs are open.
 *
 * @param request
 *        The job request we are processing.
 */
int
globus_gram_job_manager_output_open(
    globus_gram_jobmanager_request_t *	request)
{
    globus_l_gram_job_manager_output_destination_t *
					destination;
    globus_list_t *			destinations;
    globus_reltime_t			delay;
    globus_reltime_t			period;
    char *				out_cache_name;
    char *				err_cache_name;
    int					rc = GLOBUS_SUCCESS;

    request->output->close_flag = GLOBUS_FALSE;

    globus_gram_job_manager_request_log(
	    request,
	    "JM: Opening output destinations\n");

    rc = globus_gram_job_manager_output_get_cache_name(
		    request,
		    "stdout",
                    &out_cache_name);
    if (rc != 0)
    {
        goto failed_out_cache_name_exit;
    }
    globus_gram_job_manager_request_log(
	    request,
	    "JM: stdout goes to %s\n",
	    out_cache_name);

    rc = globus_gram_job_manager_output_get_cache_name(
		    request,
		    "stderr",
                    &err_cache_name);
    if (rc != 0)
    {
        goto failed_err_cache_name_exit;
    }
    globus_gram_job_manager_request_log(
	    request,
	    "JM: stderr goes to %s\n",
	    err_cache_name);

    if(!globus_l_gram_job_manager_url_is_dev_null(request->local_stdout))
    {
	request->output->stdout_fd =
	    globus_libc_open(request->local_stdout, O_RDONLY|O_CREAT,
                    S_IRUSR|S_IWUSR);
        if (request->output->stdout_fd == -1)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDOUT;

            goto error_exit;
        }
        fcntl(request->output->stdout_fd, F_SETFD, FD_CLOEXEC);
	destinations = request->output->stdout_destinations;

	while(!globus_list_empty(destinations))
	{
	    destination = globus_list_first(destinations);
	    destinations = globus_list_rest(destinations);

	    /* Don't bother to open /dev/null, and avoid feedback loops */
	    if((!globus_l_gram_job_manager_url_is_dev_null(destination->url))
	       && strcmp(destination->url, out_cache_name) != 0
	       && strcmp(destination->url, err_cache_name) != 0)
	    {
		rc = globus_l_gram_job_manager_output_destination_open(
			request,
			destination);
		if(rc != GLOBUS_SUCCESS)
		{
		    goto error_exit;
		}
	    }
	    else
	    {
		destination->state =
		    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
	    }
	}
    }

    if(!globus_l_gram_job_manager_url_is_dev_null(request->local_stderr))
    {
	request->output->stderr_fd =
	    globus_libc_open(request->local_stderr, O_RDONLY|O_CREAT,
                    S_IRUSR|S_IWUSR);

        if (request->output->stderr_fd == -1)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDERR;

            goto error_exit;
        }

        fcntl(request->output->stderr_fd, F_SETFD, FD_CLOEXEC);
	destinations = request->output->stderr_destinations;
	while(!globus_list_empty(destinations))
	{
	    destination = globus_list_first(destinations);
	    destinations = globus_list_rest(destinations);

	    /* Don't bother to open /dev/null, and avoid feedback loops */
	    if((!globus_l_gram_job_manager_url_is_dev_null(destination->url))
		&& strcmp(destination->url, out_cache_name) != 0
		&& strcmp(destination->url, err_cache_name) != 0)
	    {
		rc = globus_l_gram_job_manager_output_destination_open(
			request,
			destination);
		if(rc != GLOBUS_SUCCESS)
		{
		    goto error_exit;
		}
	    }
	    else
	    {
		destination->state =
		    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
	    }
	}
    }

error_exit:

failed_err_cache_name_exit:
    globus_libc_free(err_cache_name);
failed_out_cache_name_exit:
    globus_libc_free(out_cache_name);

    if(request->output->stderr_fd != -1 ||
       request->output->stdout_fd != -1)
    {
	globus_gram_job_manager_request_log(
		request,
		"stdout or stderr is being used, starting to poll\n");
	
	GlobusTimeReltimeSet(delay,
			     GLOBUS_GRAM_JOB_MANAGER_OUTPUT_POLL_PERIOD,
			     0);
	GlobusTimeReltimeSet(period,
			     GLOBUS_GRAM_JOB_MANAGER_OUTPUT_POLL_PERIOD,
			     0);

	globus_callback_register_periodic(
		&request->output->callback_handle,
		&delay,
		&period,
		globus_l_gram_job_manager_output_poll,
		request);
    }

    else
    {
	globus_gram_job_manager_request_log(
		request,
		"ignoring stdout and stderr\n");
    }
    if(request->output->pending_opens == 0)
    {
	globus_gram_job_manager_request_log(
		request,
		"no opens in progress, registering state machine callback\n");
	GlobusTimeReltimeSet(delay, 0, 0);

	globus_callback_register_oneshot(
		&request->poll_timer,
		&delay,
		globus_gram_job_manager_state_machine_callback,
		request);
    }

    globus_gram_job_manager_request_log(
	    request,
	    "JM: Finished opening output destinations\n");
    return rc;
}
/* globus_l_gram_job_manager_output_open() */

/**
 * Close output destinations.
 *
 * Close the destinations associated with stdout and stderr.
 * This will register a callback which processes the state machine once the
 * output URLs are open.

 * @param request
 *        The job request we are processing.
 */
int
globus_gram_job_manager_output_close(
    globus_gram_jobmanager_request_t *	request)
{
    globus_l_gram_job_manager_output_destination_t *
					destination;
    struct stat				file_status;
    globus_list_t *			tmp_list;
    globus_reltime_t			delay;
    globus_list_t *			node;

    request->output->close_flag = GLOBUS_TRUE;

    if(request->output->stdout_fd != -1)
    {
	fstat(request->output->stdout_fd, &file_status);
	request->output->stdout_size = file_status.st_size;
    }

    tmp_list = request->output->stdout_destinations;
    while(!globus_list_empty(tmp_list))
    {
	node = tmp_list;
	destination = globus_list_first(tmp_list);
	tmp_list = globus_list_rest(tmp_list);

	if(destination->state == 
	       GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID ||
	   destination->state ==
	       GLOBUS_GRAM_JOB_MANAGER_DESTINATION_NEW)
	{
	    globus_list_remove(
		    &request->output->stdout_destinations,
		    node);
	}
    }
    if(request->output->stderr_fd != -1)
    {
	fstat(request->output->stderr_fd, &file_status);
	request->output->stderr_size = file_status.st_size;
    }

    tmp_list = request->output->stderr_destinations;
    while(!globus_list_empty(tmp_list))
    {
	node = tmp_list;
	destination = globus_list_first(tmp_list);
	tmp_list = globus_list_rest(tmp_list);

	if(destination->state == 
	       GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID ||
	   destination->state ==
	       GLOBUS_GRAM_JOB_MANAGER_DESTINATION_NEW)
	{
	    globus_list_remove(
		    &request->output->stderr_destinations,
		    node);
	}
    }
    if(globus_list_empty(request->output->stdout_destinations) &&
       globus_list_empty(request->output->stderr_destinations))
    {
	if(request->output->stderr_fd != -1)
	{
	    globus_libc_close(request->output->stderr_fd);
	    request->output->stderr_fd  = -1;
	}
	if(request->output->stdout_fd != -1)
	{
	    globus_libc_close(request->output->stdout_fd);
	    request->output->stdout_fd  = -1;
	}
	GlobusTimeReltimeSet(delay, 0, 0);

	globus_callback_register_oneshot(
		&request->poll_timer,
		&delay,
		globus_gram_job_manager_state_machine_callback,
		request);
    }
    else
    {
	globus_l_gram_job_manager_output_poll_locked(request);
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_output_close() */

/**
 * Generate a filename to store output locally.
 *
 * This function allocates and returns a filename where all output data
 * should be stored for the output stream named by @a type, using
 * the @a destinations list to decide if the output needs to be stored at all.
 *
 * @param request
 *        The request associated with this job.
 * @param type
 *        The type of output (either GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM or
 *        GLOBUS_GRAM_PROTOCOL_STDERR_PARAM)
 */
char *
globus_gram_job_manager_output_local_name(
    globus_gram_jobmanager_request_t *	request,
    const char *			type)
{
    globus_l_gram_job_manager_output_destination_t *
					destination;
    char *				out_file;
    globus_list_t *			destinations;
    int                                 rc;

    if(strcmp(type, GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM) == 0)
    {
	destinations = request->output->stdout_destinations;
    }
    else if(strcmp(type, GLOBUS_GRAM_PROTOCOL_STDERR_PARAM) == 0)
    {
	destinations = request->output->stderr_destinations;
    }
    else
    {
	return GLOBUS_NULL;
    }

    while(!globus_list_empty(destinations))
    {
	destination = globus_list_first(destinations);
	destinations = globus_list_rest(destinations);

	if(!globus_l_gram_job_manager_url_is_dev_null(destination->url))
	{
	    /* We have at least one valid destination, create cache
	     * entry for stdout
	     */
	    rc = globus_gram_job_manager_output_get_cache_name(
		    request,
		    type,
                    &out_file);
            if (rc != 0)
            {
                return NULL;
            }

	    return out_file;
	}
    }
    return globus_libc_strdup("/dev/null");
}
/* globus_l_gram_job_manager_output_local_name() */

/**
 * Determine name of cache entry used for storing stdout or stderr.
 *
 * This function allocates and returns a string which we be the
 * name of the URL inserted into the cache to store stdout or stderr
 * (depending on the @a type parameter). The string must be freed by
 * the caller.
 *
 * @note This function must be called after the request's uniq_id
 *       field has been initialized.
 *
 * @param request
 *        The job request structure.
 * @param type
 *        The type of output file to get the name of (intended to be
 *        used with "stdout", "stderr", or "x509_up).
 * @param output_name
          Pointer to char to be set to the value of the name.
 */
extern
int
globus_gram_job_manager_output_get_cache_name(
    globus_gram_jobmanager_request_t *	request,
    const char *			type,
    char **                             output_name)
{
    char *                              out_file;
    int                                 rc;

    if (request->job_dir == NULL)
    {
        rc = globus_gram_job_manager_output_make_job_dir(request);

        if (rc != 0)
        {
            return rc;
        }
    }

    out_file = globus_libc_malloc(strlen(request->job_dir) + strlen(type) + 2);

    if (out_file == NULL)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }
    sprintf(out_file,
		"%s/%s",
		request->job_dir,
                type);

    *output_name = out_file;
    return 0;
}
/* globus_gram_job_manager_output_get_cache_name() */ 

extern
int
globus_gram_job_manager_output_make_job_dir(
    globus_gram_jobmanager_request_t *	request)
{
    char				hostname[MAXHOSTNAMELEN];
    const char *                        dir_format = "%s/.globus/job/%s/%s";
    char *				out_file;
    char *                              tmp;
    int                                 rc;
    struct stat                         statbuf;

    globus_libc_gethostname(hostname, sizeof(hostname));

    out_file = globus_libc_malloc(
                strlen(dir_format) +
                strlen(request->home) +
		strlen(hostname) +
		strlen(request->uniq_id) + 2);

    sprintf(out_file,
		dir_format,
                request->home,
		hostname,
		request->uniq_id);


    if ((rc = stat(out_file, &statbuf)) < 0)
    {
        tmp = out_file;

        while (tmp != NULL)
        {
            tmp = strchr(tmp+1, '/');
            if (tmp != out_file)
            {
                if (tmp != NULL)
                {
                    *tmp = '\0';
                }
                if ((rc = stat(out_file, &statbuf)) < 0)
                {
                    mkdir(out_file, S_IRWXU);
                }
                if ((rc = stat(out_file, &statbuf)) < 0)
                {
                    globus_gram_job_manager_request_log(
                        request,
                        "JMI: Unable to create part of job dir path: %s\n",
                        out_file);
                    rc = GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;

                    goto error_exit;
                }
                if (tmp != NULL)
                {
                    *tmp = '/';
                }
            }
        }
    }

    request->job_dir = out_file;
    return 0;
error_exit:
    globus_libc_free(out_file);
    return rc;
}
/* globus_gram_job_manager_output_make_job_dir() */

/**
 * Get size of standard out
 *
 * @param request
 *        Request that we are checking the size of the output file of.
 * @param type
 *        Must be either "stdout" or "stderr".
 * @param size
 *        Pointer to memory to hold result.
 *
 * @retval GLOBUS_SUCCESS (or GLOBUS_FAILURE if you pass in bogus arguments)
 */
int
globus_gram_job_manager_output_get_size(
    globus_gram_jobmanager_request_t *	request,
    const char *			type,
    globus_off_t *                      size
    )
{
    if(!size || !request || !request->output) {
        return GLOBUS_FAILURE;
    }

    if(strcmp(type, "stdout") == 0)
    {
        *size = request->output->stdout_size;
        return GLOBUS_SUCCESS;
    }
    else if(strcmp(type, "stderr") == 0)
    {
        *size = request->output->stderr_size;
        return GLOBUS_SUCCESS;
    }

    return GLOBUS_FAILURE;
}
/* globus_gram_job_manager_output_get_size() */

/**
 * Check size of output files
 *
 * Verifies that the size of the stdout or stderr file is exactly @a size
 * bytes long.
 *
 * @param request
 *        Request that we are checking the size of the output file of.
 * @param type
 *        Must be either "stdout" or "stderr".
 * @param size
 *        The size to compare against.
 *
 * @retval GLOBUS_SUCCESS
 *         The size matches.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_STDIO_SIZE
 *         The size does not match and the file has been completely streamed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_STILL_STREAMING
 *         The job manager is still streaming output for that file.
 */
int
globus_gram_job_manager_output_check_size(
    globus_gram_jobmanager_request_t *	request,
    const char *			type,
    globus_off_t			size)
{
    globus_off_t			actual_size;
    globus_l_gram_job_manager_output_info_t *
					info;
    globus_list_t *                     destinations;
    globus_l_gram_job_manager_output_destination_t *
                                        dest;

    info = request->output;

    if(strcmp(type, "stdout") == 0)
    {
	actual_size = info->stdout_size;
        destinations = info->stdout_destinations;
    }
    else
    {
	globus_assert(strcmp(type, "stderr") == 0);
	actual_size = info->stderr_size;
        destinations = info->stderr_destinations;
    }

    while (!globus_list_empty(destinations))
    {
        dest = globus_list_first(destinations);
        destinations = globus_list_rest(destinations);

        if (dest->state != GLOBUS_GRAM_JOB_MANAGER_DESTINATION_FAILED &&
            dest->state != GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID)
        {
            return GLOBUS_GRAM_PROTOCOL_ERROR_STILL_STREAMING;
        }
    }

    if (size == actual_size)
    {
        return GLOBUS_SUCCESS;
    }
    else
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_STDIO_SIZE;
    }
}
/* globus_gram_job_manager_output_check_size() */

/**
 * Periodically poll output destinations.
 *
 * This function is called periodically as the job manager is running.
 * It locks the request mutex and calls the
 * globus_l_gram_job_manager_output_poll_locked() which coordinates the
 * real work.
 * @param user_arg a void * casting of the job request structure.
 */
static
void
globus_l_gram_job_manager_output_poll(
    void *				user_arg)
{
    globus_gram_jobmanager_request_t *	request;
    request = user_arg;

    globus_mutex_lock(&request->mutex);
    request->in_handler = GLOBUS_TRUE;
    globus_l_gram_job_manager_output_poll_locked(request);

    request->in_handler = GLOBUS_FALSE;
    globus_mutex_unlock(&request->mutex);
}
/* globus_gram_job_manager_output_poll() */

/**
 * Poll output files for new data to send to destinations.
 *
 * This function checks the destinations for stdout and stderr
 * being handled by the job manager, and if the stdout or stderr files
 * generated by the job are larger than what has been sent to the
 * destination, new data will be sent. This is invoked as a 
 * periodic event by the callback code, so we must handle locking
 * the request ourselves here.
 *
 * @param request
 *        The job request structure for the job we are monitoring.
 *
 */
static
void
globus_l_gram_job_manager_output_poll_locked(
    globus_gram_jobmanager_request_t *	request)
{
    struct stat				file_status;
    globus_list_t *			tmp_list;
    globus_l_gram_job_manager_output_destination_t *
					destination;

    if(request->output->stdout_fd != -1)
    {
	if(!request->output->close_flag)
	{
	    fstat(request->output->stdout_fd, &file_status);
	    request->output->stdout_size = file_status.st_size;
	}

	tmp_list = request->output->stdout_destinations;
	while(!globus_list_empty(tmp_list))
	{
	    destination = globus_list_first(tmp_list);
	    tmp_list = globus_list_rest(tmp_list);

	    globus_l_gram_job_manager_output_destination_flush(
		    request,
		    destination,
		    NULL);

	}
    }
    if(request->output->stderr_fd != -1)
    {
	if(!request->output->close_flag)
	{
	    fstat(request->output->stderr_fd, &file_status);
	    request->output->stderr_size = file_status.st_size;
	}

	tmp_list = request->output->stderr_destinations;
	while(!globus_list_empty(tmp_list))
	{
	    destination = globus_list_first(tmp_list);
	    tmp_list = globus_list_rest(tmp_list);

	    globus_l_gram_job_manager_output_destination_flush(
		    request,
		    destination,
		    NULL);
	}
    }
}
/* globus_l_gram_job_manager_output_poll_locked() */

/**
 * Write output information to state file.
 *
 * Writes the information about stdout and stderr to the job's state
 * file, when the save_state RSL attribute is set to yes. Information
 * about each output destination is stored in the state file, so that
 * if the job manager is stopped and restarted, it can resume sending
 * output to the same URLs from the state position in the output stream.
 *
 * @param request
 *        The job request which is being stored to disk.
 * @param fp
 *        A FILE pointer to which the output information should be
 *        written.
 */
int
globus_gram_job_manager_output_write_state(
    globus_gram_jobmanager_request_t *	request,
    FILE *				fp)
{
    globus_list_t *			tmp_list;
    globus_l_gram_job_manager_output_info_t *
					info;
    globus_l_gram_job_manager_output_destination_t *
					dest;
    int                                 rc;

    info = request->output;

    rc = fprintf(fp, "%d\n", globus_list_size(info->stdout_destinations));

    if(rc < 0)
    {
        return GLOBUS_FAILURE;
    }
    tmp_list = info->stdout_destinations;
    while(!globus_list_empty(tmp_list))
    {
	dest = globus_list_first(tmp_list);
	tmp_list = globus_list_rest(tmp_list);

	rc = fprintf(fp,
		"%s\n%s\n%"GLOBUS_OFF_T_FORMAT"\n",
		dest->url,
		dest->tag ? dest->tag : "",
		dest->position);
        if(rc < 0)
        {
            return GLOBUS_FAILURE;
        }
    }

    rc = fprintf(fp, "%d\n", globus_list_size(info->stderr_destinations));
    if(rc < 0)
    {
        return GLOBUS_FAILURE;
    }
    tmp_list = info->stderr_destinations;
    while(!globus_list_empty(tmp_list))
    {
	dest = globus_list_first(tmp_list);
	tmp_list = globus_list_rest(tmp_list);

	rc = fprintf(fp,
		"%s\n%s\n%"GLOBUS_OFF_T_FORMAT"\n",
		dest->url,
		dest->tag ? dest->tag : "",
		dest->position);
        if(rc < 0)
        {
            return GLOBUS_FAILURE;
        }
    }
    return 0;
}
/* globus_gram_job_manager_output_write_state() */

/**
 * Read output information from state file.
 *
 * Reads the information about stdout and stderr from the job's state
 * file to implement restarting a job manager that will resume writing
 * the output and error streams to the same URLs as in the original job
 * request.
 *
 * @param request
 *        The job request which is being stored to disk.
 * @param fp
 *        A FILE pointer from which the output information should be
 *        read.
 */
int
globus_gram_job_manager_output_read_state(
    globus_gram_jobmanager_request_t *	request,
    FILE *				fp)
{
    globus_l_gram_job_manager_output_destination_t *
					destination;
    int					count;
    int					i;
    char 				buffer[4096];
    globus_size_t			bufsize;

    bufsize = sizeof(buffer);

    if(fscanf(fp, "%d\n", &count) < 1)
    {
        return GLOBUS_FAILURE;
    }

    for(i = 0; i < count; i++)
    {
	destination = globus_libc_malloc(
		sizeof(globus_l_gram_job_manager_output_destination_t));

	if (fgets(buffer, bufsize, fp) == NULL)
        {
            return GLOBUS_FAILURE;
        }
	destination->request = request;
	destination->url = globus_libc_strdup(buffer); 

	if (fgets(buffer, bufsize, fp) == NULL)
        {
            return GLOBUS_FAILURE;
        }
	if(strlen(buffer) != 0)
	{
	    destination->tag = globus_libc_strdup(buffer);
	}
	else
	{
	    destination->tag = NULL;
	}
	if (fscanf(fp, "%"GLOBUS_OFF_T_FORMAT"\n", &destination->position) < 1)
        {
            return GLOBUS_FAILURE;
        }
	destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_NEW;
	destination->which = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDOUT;

	/* This will insert the destinations in the reverse order of
	 * the RSL. When we process the RSL, it'll be reversed in the
	 * set_urls function above.
	 */
	globus_list_insert(&request->output->stdout_destinations, destination);
    }

    if(fscanf(fp, "%d\n", &count) < 1)
    {
        return GLOBUS_FAILURE;
    }
    for(i = 0; i < count; i++)
    {
	destination = globus_libc_malloc(
		sizeof(globus_l_gram_job_manager_output_destination_t));

	if (fgets(buffer, bufsize, fp) == NULL)
        {
            return GLOBUS_FAILURE;
        }
	destination->request = request;
	destination->url = globus_libc_strdup(buffer); 

	if (fgets(buffer, bufsize, fp) == NULL)
        {
            return GLOBUS_FAILURE;
        }
	if(strlen(buffer) != 0)
	{
	    destination->tag = globus_libc_strdup(buffer);
	}
	else
	{
	    destination->tag = NULL;
	}
	if(fscanf(fp, "%"GLOBUS_OFF_T_FORMAT"\n", &destination->position) < 1)
        {
            return GLOBUS_FAILURE;
        }
	destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_NEW;
	destination->which = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDERR;

	globus_list_insert(&request->output->stderr_destinations, destination);
    }
    return GLOBUS_SUCCESS;
}
/* globus_gram_job_manager_output_read_state() */

/**
 * Create destination structures for stdout and stderr values.
 *
 * This function creates a new destination structure for each
 * value in the passed value list. This function handles both the
 * old (GRAM 1.5 and earlier) and new (GRAM 1.6) formats for
 * stdout and stderr attribute values.
 *
 * @param request
 *        The request which is being handled by the job manager
 * @param value_list
 *        The list of RSL values to be processed.
 * @param destinations
 *        The list which the new destinations should be inserted.
 * @param recursive
 *        Must be set to GLOBUS_TRUE when this function is called
 *        recusively, so that it will deal with the value list
 *        properly.
 *
 * @return 
 * This function returns GLOBUS_SUCCESS if the rsl value list is
 * syntactically valid and the destinations were created; otherwise,
 * GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDOUT or
 * GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDERR will be returned.
 */
static
int
globus_l_gram_job_manager_output_insert_urls(
    globus_gram_jobmanager_request_t *	request,
    globus_list_t *			value_list,
    globus_gram_job_manager_output_which_t
    					which,
    globus_bool_t			recursive)
{
    globus_rsl_value_t *		value;
    char *				filename;
    char *				tag;
    globus_l_gram_job_manager_output_destination_t *
					destination;
    int					rc;
    globus_list_t **			destinations;
    int					error_value;

    if(which == GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDOUT)
    {
	destinations = &request->output->stdout_destinations;
	error_value = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDOUT;
    }
    else
    {
	globus_assert(which == GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDERR);
	destinations = &request->output->stderr_destinations;
	error_value = GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDERR;
    }
    globus_gram_job_manager_request_log(
	request,
	"JMI: Getting RSL output value%s\n",
	recursive ? " recursively" : "");

    if(value_list == NULL)
    {
	return GLOBUS_SUCCESS;
    }

    value = globus_list_first(value_list);
    if(globus_rsl_value_is_literal(value))
    {
	/* Old style stdout or stderr rsl (stdout = url [tag]) */
	if(globus_list_size(value_list) > 2)
	{
	    return error_value;
	}
	filename = globus_rsl_value_literal_get_string(value);

	if(globus_list_size(value_list) == 2)
	{
	    value = globus_list_first(globus_list_rest(value_list));

	    if(!globus_rsl_value_is_literal(value))
	    {
		return error_value;
	    }
	    tag = globus_rsl_value_literal_get_string(value);
	}
	else
	{
	    tag = GLOBUS_NULL;
	}

	destination = globus_libc_malloc(
		sizeof(globus_l_gram_job_manager_output_destination_t));
	destination->request = request;
	destination->tag = tag ? globus_libc_strdup(tag) : NULL;
	destination->position = 0;
	destination->callback_count = 0;
	destination->possible_write_count = 0;
	destination->which = which;
	globus_l_gram_job_manager_output_get_type(
		request,
		destination,
		filename);

	destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_NEW;

	globus_list_insert(destinations, destination);

        if (destination->type == GLOBUS_GRAM_JOB_MANAGER_OUTPUT_UNKNOWN)
        {
            return error_value;
        }
	return GLOBUS_SUCCESS;
    }
    else if(globus_rsl_value_is_sequence(value) && !recursive)
    {
	/* New style stdout or stderr rsl
	 * (stdout = (url [tag]) [(url [tag])])
	 */
	while(!globus_list_empty(value_list))
	{
	    value = globus_list_first(value_list);
	    value_list = globus_list_rest(value_list);

	    rc = globus_l_gram_job_manager_output_insert_urls(
		    request,
		    globus_rsl_value_sequence_get_value_list(value),
		    which,
		    GLOBUS_TRUE);

	    if(rc != GLOBUS_SUCCESS)
	    {
		return rc;
	    }
	}
	return GLOBUS_SUCCESS;
    }
    else
    {
	return error_value;
    }
}
/* globus_l_gram_job_manager_output_insert_urls() */


/**
 * Process stdout_position or stderr_position RSL values.
 *
 * This function processes the value list of a stdout_position
 * or stderr_position relation in a job request RSL. The positions
 * in the passed * destination list will be updated with new position
 * values.
 *
 * @param request
 *        The job request being processed.
 * @param value_list
 *        The list of globus_rsl_value_t values from the position
 *        relation.
 * @param destinations
 *        List of destination structures associated with each
 *        stdout or stderr destination.
 */
static
int
globus_l_gram_job_manager_output_get_positions(
    globus_gram_jobmanager_request_t *	request,
    globus_list_t *			value_list,
    globus_list_t *			destinations)
{
    globus_rsl_value_t *		value;
    globus_l_gram_job_manager_output_destination_t *
					destination;
    char *				value_str;

    globus_gram_job_manager_request_log(
	    request,
	    "JMI: Processing output positions\n");

    if(globus_list_size(value_list) > globus_list_size(destinations))
    {
	return GLOBUS_FAILURE;
    }
    while(!globus_list_empty(value_list))
    {
	value = globus_list_first(value_list);
	destination = globus_list_first(destinations);

	value_list = globus_list_rest(value_list);
	destinations = globus_list_rest(destinations);

	if(globus_rsl_value_is_literal(value))
	{
	    value_str = globus_rsl_value_literal_get_string(value);

	    sscanf(value_str, "%"GLOBUS_OFF_T_FORMAT, &destination->position);
	}
	else
	{
	    return GLOBUS_FAILURE;
	}
    }
    return GLOBUS_SUCCESS;
}
/* globus_l_gram_job_manager_output_get_positions() */

/**
 * Check whether URL string is a variation on /dev/null.
 *
 * Checks the given @a url against several variations on /dev/null
 * which we might encounter.
 *
 * @param URL
 *        URL string to check.
 */
static
globus_bool_t
globus_l_gram_job_manager_url_is_dev_null(
    const char *			url)
{
    return (strcmp(url, "/dev/null") == 0 ||
	    strcmp(url, "file:/dev/null") == 0 ||
	    strcmp(url, "file:///dev/null") == 0);
}

/**
 * Flush data to output destinations.
 */
static
int
globus_l_gram_job_manager_output_destination_flush(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination,
    unsigned char *			buffer)
{
    ssize_t				read_amt;
    globus_off_t			size;
    int					fd;
    globus_result_t			result;
    int					rc;

    if(destination->which == GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDOUT)
    {
	size = request->output->stdout_size;
	fd = request->output->stdout_fd;
    }
    else if(destination->which == GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDERR)
    {
	size = request->output->stderr_size;
	fd = request->output->stderr_fd;
    }
    else
    {
	return GLOBUS_FAILURE;
    }

    if(destination->state == GLOBUS_GRAM_JOB_MANAGER_DESTINATION_VALID
	    && destination->position < size)
    {
	lseek(fd, destination->position, SEEK_SET);
	while(destination->state ==
		    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_VALID &&
	      destination->possible_write_count != 0 &&
	      destination->position < size)
	{
	    if(buffer == NULL)
	    {
		buffer = globus_libc_malloc(
                    GLOBUS_GRAM_JOB_MANAGER_OUTPUT_BUFFER_SIZE);
	    }

	    do
	    {
		read_amt = globus_libc_read(
				fd,
				buffer,
				GLOBUS_GRAM_JOB_MANAGER_OUTPUT_BUFFER_SIZE);
	    }
	    while(read_amt < 0 && (errno == EAGAIN || errno == EINTR));

	    if(read_amt < 0)
	    {
		break;
	    }

	    switch(destination->type)
	    {
		case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_CACHE:
		case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FILE:
		    result = globus_io_register_write(
			&destination->handle.file,
			buffer,
			read_amt,
			globus_l_gram_job_manager_output_file_write_callback,
			request);
		    if(result == GLOBUS_SUCCESS)
		    {
			destination->possible_write_count--;
			destination->callback_count++;
		    }
		    else
		    {
			destination->state =
			    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_FAILED;

			read_amt = 0;
		    }
		    break;

		case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_GASS:
		    rc = globus_gass_transfer_send_bytes(
			destination->handle.gass,
			buffer,
			read_amt,
			GLOBUS_FALSE,
			globus_l_gram_job_manager_output_gass_write_callback,
			request);
		    if(rc == GLOBUS_SUCCESS)
		    {
			destination->possible_write_count--;
			destination->callback_count++;
		    }
		    else
		    {
			destination->state =
			    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_FAILED;

			read_amt = 0;
		    }
		    break;
		case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FTP:
		    result = globus_ftp_client_register_write(
			&destination->handle.ftp,
			buffer,
			read_amt,
			0,
			GLOBUS_FALSE,
			globus_l_gram_job_manager_output_ftp_write_callback,
			request);

		    if(result == GLOBUS_SUCCESS)
		    {
			destination->callback_count++;
		    }
		    else
		    {
			destination->state =
			    GLOBUS_GRAM_JOB_MANAGER_DESTINATION_FAILED;

			read_amt = 0;
		    }
		default:
		    break;
	    }
	    destination->position += read_amt;
	    buffer = NULL;
	}
    }

    if(buffer != NULL)
    {
	globus_libc_free(buffer);
    }

    switch(destination->state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_DESTINATION_NEW:
      case GLOBUS_GRAM_JOB_MANAGER_DESTINATION_OPEN:
      case GLOBUS_GRAM_JOB_MANAGER_DESTINATION_CLOSE:
      case GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID:
	/* Nothing to see here. */
        break;
      case GLOBUS_GRAM_JOB_MANAGER_DESTINATION_VALID:
	/* If we've already pushed all of the data to the server, and
	 * close_flag is set, then it's time to close this destination
	 */
	if(destination->callback_count == 0 &&
	   request->output->close_flag &&
	   destination->position >= size)
	{
	    globus_l_gram_job_manager_output_destination_close(
		    request,
		    destination);
	}
	break;
      case GLOBUS_GRAM_JOB_MANAGER_DESTINATION_FAILED:
	/* If the send failed above, then we should close this destination
	 * as well.
	 */
	globus_l_gram_job_manager_output_destination_close(
		request,
		destination);
    }
    return GLOBUS_SUCCESS;
}
/* globus_l_gram_job_manager_output_destination_flush() */

/**
 * Open a new destination for stdout or stderr.
 *
 * @param request
 *        The job request structure for the job we are monitoring.
 * @param destination
 *        The information about the output destination, including
 *        the URL for that destination.
 */
static
int
globus_l_gram_job_manager_output_destination_open(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination)
{
    int					rc = GLOBUS_SUCCESS;
    globus_result_t			result;
    char *				local_filename = NULL;
    unsigned long			timestamp;
    globus_ftp_client_operationattr_t	attr;

    globus_gram_job_manager_request_log(
	    request,
	    "JM: Opening %s\n",
	    destination->url);

    switch(destination->type)
    {
      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_CACHE:
        rc = globus_gass_cache_add(
		request->cache_handle,
		destination->url,
               destination->tag ? destination->tag : request->cache_tag,
		GLOBUS_TRUE,
		&timestamp,
		&local_filename);
	if(rc != GLOBUS_GASS_CACHE_ADD_NEW &&
	   rc != GLOBUS_GASS_CACHE_ADD_EXISTS)
	{
	    break;
	}
	rc = globus_gass_cache_add_done(
		request->cache_handle,
		destination->url,
               destination->tag ? destination->tag : request->cache_tag,
		0);
	if(rc != GLOBUS_SUCCESS)
	{
	    break;
	}
	globus_gram_job_manager_request_log(
		request,
		"JM: %s maps to %s\n",
		destination->url,
		local_filename);

	/* FALLSTHROUGH */
      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FILE:
	result = globus_io_file_open(
		local_filename ? local_filename : destination->url,
		GLOBUS_IO_FILE_CREAT|
		GLOBUS_IO_FILE_WRONLY|
		GLOBUS_IO_FILE_APPEND,
		GLOBUS_IO_FILE_IRUSR|GLOBUS_IO_FILE_IWUSR,
		GLOBUS_NULL,
		&destination->handle.file);
	if(result == GLOBUS_SUCCESS)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "JM: Opened file handle %p.\n",
		    &destination->handle.file);

	    destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_VALID;
	    globus_io_handle_set_user_pointer(
		    &destination->handle.file,
		    destination);
	    destination->possible_write_count = 1;
	}
	else
	{
	    destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
	    rc = GLOBUS_FAILURE;
	}
	if(local_filename)
	{
	    globus_libc_free(local_filename);
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_GASS:
	request->streaming_requested = GLOBUS_TRUE;
	rc = globus_gass_transfer_register_append(
		&destination->handle.gass,
		GLOBUS_NULL,
		destination->url,
		GLOBUS_GASS_TRANSFER_LENGTH_UNKNOWN,
		globus_l_gram_job_manager_gass_open_callback,
		request);
	if(rc == GLOBUS_SUCCESS)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "JM: Opened GASS handle %d.\n",
		    destination->handle.gass);
	    destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_OPEN;
	    request->output->pending_opens++;
	    globus_gass_transfer_request_set_user_pointer(
		    destination->handle.gass,
		    destination);
	}
	else
	{
	    destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
	    rc = GLOBUS_FAILURE;
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FTP:
	request->streaming_requested = GLOBUS_TRUE;
	globus_ftp_client_operationattr_init(&attr);
	globus_ftp_client_operationattr_set_append(
		&attr,
		GLOBUS_TRUE);
	globus_ftp_client_handle_init(
		&destination->handle.ftp,
		NULL);
	globus_ftp_client_handle_set_user_pointer(
		&destination->handle.ftp,
		destination);
	result = globus_ftp_client_put(
		&destination->handle.ftp,
		destination->url,
		&attr,
		GLOBUS_NULL,
		globus_l_gram_job_manager_output_ftp_close_callback,
		request);

	if(result == GLOBUS_SUCCESS)
	{
	    globus_gram_job_manager_request_log(
		    request,
		    "JM: Opened FTP handle %p.\n",
		    &destination->handle.ftp);
	    destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_VALID;
	    destination->possible_write_count = -1;
	}
	else
	{
	    destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
	    rc = GLOBUS_FAILURE;
	}
	break;

      default:
	globus_gram_job_manager_request_log(
		request,
		"JM: Can't open unknown output type.\n");
	destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
	rc = GLOBUS_FAILURE;
	break;
    }
    globus_gram_job_manager_request_log(
	    request,
	    "JM: "
	    "exiting globus_l_gram_job_manager_output_destination_open()\n");
    if(rc != GLOBUS_SUCCESS)
    {
	if(destination->which == GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDOUT)
	{
	    return GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDOUT;
	}
	else
	{
	    globus_assert(destination->which ==
		          GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDERR);

	    return GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDERR;
	}
    }
    return GLOBUS_SUCCESS;
}
/* globus_l_gram_job_manager_output_destination_open() */

static
void
globus_l_gram_job_manager_output_destination_close(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination)
{
    globus_result_t			result;
    int					rc;
    globus_reltime_t			delay;

    globus_gram_job_manager_request_log(
	    request,
	    "closing destination %s\n",
	    destination->url);

    GlobusTimeReltimeSet(delay, 0, 0);

    switch(destination->type)
    {
      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_CACHE:
      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FILE:
	result = globus_io_register_close(
		&destination->handle.file,
		globus_l_gram_job_manager_file_close_callback,
		request);

	destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_CLOSE;

	if(result != GLOBUS_SUCCESS)
	{
	    globus_callback_register_oneshot(
		NULL,
		&delay,
		globus_l_gram_job_manager_output_close_kickout,
		destination);
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_GASS:
	rc = globus_gass_transfer_send_bytes(
		destination->handle.gass,
		globus_libc_malloc(1),
		0,
		GLOBUS_TRUE,
		globus_l_gram_job_manager_output_gass_close_callback,
		request);
	destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_CLOSE;
	if(rc == GLOBUS_SUCCESS)
	{
	    destination->callback_count++;
	}
	else
	{
            if (rc == GLOBUS_GASS_TRANSFER_ERROR_REQUEST_FAILED)
            {
                request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_OUT_FAILED;
                request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
            }

	    globus_callback_register_oneshot(
		NULL,
		&delay,
		globus_l_gram_job_manager_output_close_kickout,
		destination);
	}
	break;

      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FTP:
	result = globus_ftp_client_register_write(
		&destination->handle.ftp,
		globus_libc_malloc(1),
		0,
		0,
		GLOBUS_TRUE,
		globus_l_gram_job_manager_output_ftp_write_callback,
		request);

	if(result == GLOBUS_SUCCESS)
	{
	    destination->callback_count++;
	}
	else
	{
	    globus_callback_register_oneshot(
		NULL,
		&delay,
		globus_l_gram_job_manager_output_close_kickout,
		destination);
	}
	break;

      default:
	break;
    }
    globus_gram_job_manager_request_log(
	    request,
	    "JM: "
	    "exiting globus_l_gram_job_manager_output_destination_close()\n");
}
/* globus_l_gram_job_manager_output_destination_close() */

static
void
globus_l_gram_job_manager_gass_open_callback(
    void *				arg,
    globus_gass_transfer_request_t	gass_request)
{
    globus_gram_jobmanager_request_t *	request;
    globus_gass_transfer_request_status_t
					status;
    globus_l_gram_job_manager_output_destination_t *
    					destination;
    globus_gass_transfer_referral_t 	referral;
    int					rc;
    globus_bool_t			event_registered;
    char *				new_url;
    globus_gram_job_manager_query_t *
					query;

    request = arg;

    globus_mutex_lock(&request->mutex);
    status = globus_gass_transfer_request_get_status(gass_request);
    destination = globus_gass_transfer_request_get_user_pointer(gass_request);
    request->output->pending_opens--;

    switch(status)
    {
	case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
	  destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_VALID;
	  destination->possible_write_count = 2;
	  break;

	case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
	  if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT)
	  {
	      globus_gass_transfer_request_get_referral(
		      gass_request,
		      &referral);
	      new_url = globus_gass_transfer_referral_get_url(&referral, 0);
	      rc = globus_gass_transfer_register_append(
		      &destination->handle.gass,
		      GLOBUS_NULL,
		      new_url,
		      GLOBUS_GASS_TRANSFER_LENGTH_UNKNOWN,
		      globus_l_gram_job_manager_gass_open_callback,
		      request);
	      if(rc == GLOBUS_SUCCESS)
	      {
		  destination->callback_count++;
		  globus_gass_transfer_request_set_user_pointer(
			  destination->handle.gass,
			  destination);
		  request->output->pending_opens++;
	      }
	  }
	  globus_gass_transfer_referral_destroy(&referral);
	  break;

	case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
	  destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
	  if(destination->which == GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDOUT)
	  {
	      request->output->open_failure_code =
		  GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDOUT;
	  }
	  else
	  {
	      request->output->open_failure_code =
		  GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDERR;
	  }
          globus_gass_transfer_request_destroy(gass_request);

	  break;
	case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
	case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
	case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
	case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
	default:
	  globus_assert(/* This oughtn't happen */ 0);
	  break;
    }
    if((request->jobmanager_state ==
	    GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT ||
	request->jobmanager_state == 
	    GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN) &&
       request->output->pending_opens == 0)
    {
	if(request->jobmanager_state ==
	    GLOBUS_GRAM_JOB_MANAGER_STATE_OPEN_OUTPUT &&
	    request->output->open_failure_code != GLOBUS_SUCCESS)
	{
	    request->failure_code = request->output->open_failure_code;
	    request->jobmanager_state =
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED;
	}
	else if(request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN &&
		request->output->open_failure_code != GLOBUS_SUCCESS)
	{
	    query = globus_fifo_peek(&request->pending_queries);
	    query->failure_code = request->output->open_failure_code;
	}
	do
	{
	    event_registered = globus_gram_job_manager_state_machine(request);
	}
	while(!event_registered);
    }
    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_gass_open_callback() */

static
void
globus_l_gram_job_manager_output_file_write_callback(
    void *				user_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes)
{
    globus_object_t *			err;
    globus_l_gram_job_manager_output_destination_t *
    					destination;
    globus_gram_jobmanager_request_t *	request;
    globus_bool_t			eof = GLOBUS_FALSE;

    request = user_arg;
    globus_mutex_lock(&request->mutex);

    globus_io_handle_get_user_pointer(
	    handle,
	    (void **) &destination);
    /* Ignore EOF */
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);

	if(globus_io_eof(err))
	{
	    result = GLOBUS_SUCCESS;
	    eof = GLOBUS_TRUE;
	}
	globus_object_free(err);
	err = NULL;
    }

    destination->possible_write_count++;
    destination->callback_count--;

    if(result)
    {
	destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
	globus_libc_free(buf);
    }
    else if(eof)
    {
	globus_libc_free(buf);
    }
    else
    {
	globus_l_gram_job_manager_output_destination_flush(
		request,
		destination,
		buf);
    }

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_output_file_write_callback() */

static
void
globus_l_gram_job_manager_output_gass_write_callback(
    void *				arg,
    globus_gass_transfer_request_t	gass_request,
    globus_byte_t *			bytes,
    globus_size_t			length,
    globus_bool_t			last_data)
{
    globus_gram_jobmanager_request_t *	request;
    globus_l_gram_job_manager_output_destination_t *
    					destination;

    request = arg;

    globus_mutex_lock(&request->mutex);
    destination = globus_gass_transfer_request_get_user_pointer(gass_request);
    destination->callback_count--;
    destination->possible_write_count++;
    if(last_data)
    {
	globus_libc_free(bytes);
    }
    else
    {
	globus_l_gram_job_manager_output_destination_flush(
		request,
		destination,
		bytes);
    }
    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_output_gass_write_callback() */

static
void
globus_l_gram_job_manager_output_ftp_write_callback(
    void *				arg,
    globus_ftp_client_handle_t *	handle,
    globus_object_t *			error,
    globus_byte_t *			buffer,
    globus_size_t			length,
    globus_off_t			offset,
    globus_bool_t			eof)
{
    globus_gram_jobmanager_request_t *	request;
    globus_l_gram_job_manager_output_destination_t *
    					destination;

    request = arg;

    globus_mutex_lock(&request->mutex);

    globus_ftp_client_handle_get_user_pointer(
	    handle,
	    (void *) &destination);
    destination->callback_count--;

    if(eof)
    {
	globus_libc_free(buffer);
    }
    else
    {
	globus_l_gram_job_manager_output_destination_flush(
		request,
		destination,
		buffer);
    }

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_output_ftp_write_callback() */

static
void
globus_l_gram_job_manager_file_close_callback(
    void *				user_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_gram_jobmanager_request_t *	request;
    globus_l_gram_job_manager_output_destination_t *
    					destination;

    request = user_arg;

    globus_mutex_lock(&request->mutex);
    globus_io_handle_get_user_pointer(
	    handle,
	    (void **) &destination);

    globus_l_gram_job_manager_output_file_close(request, destination);

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_file_close_callback() */

static
void
globus_l_gram_job_manager_output_file_close(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination)
{
    globus_assert(destination->callback_count == 0);

    destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
    globus_l_gram_job_manager_output_close_done(request, destination);
}
/* globus_l_gram_job_manager_output_file_close() */

static
void
globus_l_gram_job_manager_output_gass_close_callback(
    void *				arg,
    globus_gass_transfer_request_t 	gass_request,
    globus_byte_t *			bytes,
    globus_size_t			length,
    globus_bool_t			last_data)
{
    globus_gram_jobmanager_request_t *	request;
    globus_l_gram_job_manager_output_destination_t *
    					destination;

    request = arg;

    globus_mutex_lock(&request->mutex);
    destination = globus_gass_transfer_request_get_user_pointer(gass_request);
    destination->callback_count--;
    globus_l_gram_job_manager_output_gass_close(request, destination);

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_output_gass_close_callback() */

static
void
globus_l_gram_job_manager_output_gass_close(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination)
{
    globus_assert(destination->callback_count == 0);

    globus_gass_transfer_request_destroy(destination->handle.gass);

    destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
    globus_l_gram_job_manager_output_close_done(request, destination);
}
/* globus_l_gram_job_manager_output_gass_close() */

static
void
globus_l_gram_job_manager_output_ftp_close_callback(
    void *				arg,
    globus_ftp_client_handle_t *	handle,
    globus_object_t *			error)
{
    globus_gram_jobmanager_request_t *	request;
    globus_l_gram_job_manager_output_destination_t *
    					destination;
    request = arg;

    globus_mutex_lock(&request->mutex);

    globus_ftp_client_handle_get_user_pointer(
	    handle,
	    (void *) &destination);

    globus_l_gram_job_manager_output_ftp_close(request, destination);

    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_output_ftp_close_callback() */

static
void
globus_l_gram_job_manager_output_ftp_close(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination)
{
    globus_assert(destination->callback_count == 0);
    globus_ftp_client_handle_destroy(&destination->handle.ftp);

    destination->state = GLOBUS_GRAM_JOB_MANAGER_DESTINATION_INVALID;
    globus_l_gram_job_manager_output_close_done(request, destination);

}
/* globus_l_gram_job_manager_output_ftp_close() */

static
void
globus_l_gram_job_manager_output_close_done(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
					destination)
{
    globus_bool_t			event_registered;
    globus_list_t *			node;

    if(destination->url)
    {
	globus_libc_free(destination->url);
    }
    if(destination->tag)
    {
	globus_libc_free(destination->tag);
    }
    if(destination->which == GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDOUT)
    {
	node = globus_list_search(request->output->stdout_destinations,
				  destination);

	if(node)
	{
	    globus_list_remove(&request->output->stdout_destinations,
			       node);
	}
    }
    else
    {
	globus_assert(destination->which ==
		      GLOBUS_GRAM_JOB_MANAGER_OUTPUT_STDERR);
	node = globus_list_search(request->output->stderr_destinations,
				  destination);

	if(node)
	{
	    globus_list_remove(&request->output->stderr_destinations,
			       node);
	}
    }
    globus_libc_free(destination);

    if(request->output->close_flag)
    {
	if((request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT ||
	    request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_EARLY_FAILED_CLOSE_OUTPUT ||
	    request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT ||
	    request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_CLOSE ||
	    request->jobmanager_state ==
		GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT) &&
	    globus_list_empty(request->output->stdout_destinations) &&
	    globus_list_empty(request->output->stderr_destinations))
	{
	    if(request->output->stderr_fd != -1)
	    {
		globus_libc_close(request->output->stderr_fd);
		request->output->stderr_fd  = -1;
	    }
	    if(request->output->stdout_fd != -1)
	    {
		globus_libc_close(request->output->stdout_fd);
		request->output->stdout_fd  = -1;
	    }
	    globus_callback_unregister(request->output->callback_handle,
	                               NULL,
	                               NULL,
				       NULL);
	    request->output->callback_handle =
		GLOBUS_HANDLE_TABLE_NO_HANDLE;
	    do
	    {
		event_registered =
		    globus_gram_job_manager_state_machine(request);
	    }
	    while(!event_registered);
	}
    }
}
/* globus_l_gram_job_manager_output_close_done() */

static
void
globus_l_gram_job_manager_output_get_type(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
					destination,
    char *				filename)
{
    int					rc;
    globus_url_t			url;
    globus_bool_t                       destroy_url = GLOBUS_FALSE;
    char **                             values = NULL;

    rc = globus_url_parse(filename, &url);
    if(rc == GLOBUS_SUCCESS)
    {
        destroy_url = GLOBUS_TRUE;
	if(url.scheme_type == GLOBUS_URL_SCHEME_FTP ||
	   url.scheme_type == GLOBUS_URL_SCHEME_GSIFTP)
	{
	    destination->type = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FTP;
	    destination->url = globus_libc_strdup(filename);
	}
	else if(url.scheme_type == GLOBUS_URL_SCHEME_HTTP ||
		url.scheme_type == GLOBUS_URL_SCHEME_HTTPS)
	{
	    destination->type = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_GASS;
	    destination->url = globus_libc_strdup(filename);
	}
	else if(url.scheme_type == GLOBUS_URL_SCHEME_FILE)
	{
	    destination->type = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FILE;
	    destination->url = globus_libc_strdup(url.url_path);
	}
	else if(url.scheme_type == GLOBUS_URL_SCHEME_X_GASS_CACHE)
	{
	    destination->type = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_CACHE;
	    destination->url = globus_libc_strdup(filename);
	}
	else
	{
            goto free_url_exit;
	}
	globus_url_destroy(&url);
    }
    else
    {
	destination->type = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FILE;

        if (filename[0] == '/')
        {
            destination->url = globus_libc_strdup(filename);
        }
        else
        {
            rc = globus_rsl_param_get(request->rsl,
                    GLOBUS_RSL_VALUE_LITERAL,
                    GLOBUS_GRAM_PROTOCOL_DIR_PARAM, 
                    &values);
            if (rc == GLOBUS_SUCCESS)
            {
                destination->url = globus_libc_malloc(strlen(filename) +
                        strlen(values[0]) + 2);
                if (destination->url == NULL)
                {
                    goto free_values_exit;
                }
                sprintf(destination->url, "%s/%s", values[0], filename);
                globus_libc_free(values);
            }
            else
            {
                destination->url = globus_libc_malloc(strlen(request->home) +
                        strlen(filename) + 2);
                if (destination->url == NULL)
                {
                    goto error_exit;
                }
                sprintf(destination->url, "%s/%s", request->home, filename);
            }
        }
    }
    return;

free_values_exit:
    if (values != NULL)
    {
        globus_libc_free(values);
    }
free_url_exit:
    if (destroy_url)
    {
        globus_url_destroy(&url);
    }
error_exit:
    destination->type = GLOBUS_GRAM_JOB_MANAGER_OUTPUT_UNKNOWN;
}
/* globus_l_gram_job_manager_output_get_type() */

static
void
globus_l_gram_job_manager_output_close_kickout(
    void *				user_arg)
{
    globus_gram_jobmanager_request_t *	request;
    globus_l_gram_job_manager_output_destination_t *
					destination;
    destination = user_arg;
    request = destination->request;

    globus_mutex_lock(&request->mutex);
    switch(destination->type)
    {
      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_UNKNOWN:
        /* ! */
	break;
      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_CACHE:
      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FILE:
	globus_l_gram_job_manager_output_file_close(
		request,
		destination);
	break;
      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_GASS:
	globus_l_gram_job_manager_output_gass_close(
		request,
		destination);
	break;
      case GLOBUS_GRAM_JOB_MANAGER_OUTPUT_FTP:
	globus_l_gram_job_manager_output_ftp_close(
		request,
		destination);
	break;
    }
    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_output_close_kickout() */
