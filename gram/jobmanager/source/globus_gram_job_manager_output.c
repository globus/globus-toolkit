#include "globus_gram_job_manager.h"
#include "globus_gass_file.h"

#define GLOBUS_GRAM_JOB_MANAGER_OUTPUT_POLL_PERIOD 10

typedef struct globus_l_gram_job_manager_output_info_t
{
    int					stdout_fd;
    int					stderr_fd;
    globus_list_t *			stdout_destinations;
    globus_list_t *			stderr_destinations;
    globus_off_t			stdout_size;
    globus_off_t			stderr_size;
    globus_callback_handle_t		callback_handle;
    globus_byte_t			buffer[4096];
}
globus_l_gram_job_manager_output_info_t;

/*
 * Module specific types.
 */
typedef struct
{
    char *				url;
    char *				tag;
    globus_off_t			position;
    int					fd;
}
globus_l_gram_job_manager_output_destination_t;

/*
 * Module Specific Prototypes
 */
static
int
globus_l_gram_job_manager_output_get_urls(
    globus_gram_jobmanager_request_t *	request,
    globus_list_t *			value_list,
    globus_list_t **			destinations,
    globus_bool_t			recursive);

static
int
globus_l_gram_job_manager_output_get_positions(
    globus_gram_jobmanager_request_t *	request,
    globus_list_t *			value_list,
    globus_list_t *			destinations);

static
globus_bool_t
globus_l_gram_job_manager_output_poll(
    globus_abstime_t *			time_stop,
    void *				user_arg);

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
    const char *			type);

int
globus_i_gram_job_manager_output_init(
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
    request->output->callback_handle = -1;

    return GLOBUS_SUCCESS;
}
/* globus_i_gram_job_manager_output_init() */

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
globus_i_gram_job_manager_output_set_urls(
    globus_gram_jobmanager_request_t *	request,
    const char *			type,
    globus_list_t *			url_list,
    globus_list_t *			position_list)
{
    int					rc;
    globus_list_t *			tmp_list;
    globus_list_t **			destinations;

    if(strcmp(type, GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM) == 0)
    {
	destinations = &request->output->stdout_destinations;
    }
    else if(strcmp(type, GLOBUS_GRAM_PROTOCOL_STDERR_PARAM) == 0)
    {
	destinations = &request->output->stderr_destinations;
    }
    else
    {
	return GLOBUS_FAILURE;
    }

    /* Get URL strings from url_list */
    rc = globus_l_gram_job_manager_output_get_urls(
	    request,
	    url_list,
	    destinations,
	    GLOBUS_FALSE);
    if(rc != GLOBUS_SUCCESS)
    {
	return GLOBUS_FAILURE;
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
/* globus_i_gram_job_manager_output_set_urls() */

/**
 * Open output destinations.
 *
 * Open the (potentially remote) output locations for the stdout and
 * stderr files for this job request.
 *
 * @param request
 *        The job request we are processing.
 */
int
globus_i_gram_job_manager_output_open(
    globus_gram_jobmanager_request_t *	request)
{
    globus_l_gram_job_manager_output_destination_t *
					destination;
    globus_list_t *			destinations;
    globus_reltime_t			delay;
    globus_reltime_t			period;
    char *				out_cache_name;
    char *				err_cache_name;

    out_cache_name = globus_i_gram_job_manager_output_get_cache_name(
		    request,
		    "stdout");

    err_cache_name = globus_i_gram_job_manager_output_get_cache_name(
		    request,
		    "stderr");

    if(!globus_l_gram_job_manager_url_is_dev_null(request->local_stdout))
    {

	request->output->stdout_fd =
	    globus_libc_open(request->local_stdout, O_RDONLY);
	destinations = request->output->stdout_destinations;

	while(!globus_list_empty(destinations))
	{
	    destination = globus_list_first(destinations);
	    destinations = globus_list_rest(destinations);

	    /* Don't bother to open /dev/null, and avoid feedback loops */
	    if((!globus_l_gram_job_manager_url_is_dev_null(destination->url)) &&
		strcmp(destination->url, out_cache_name) != 0 &&
		strcmp(destination->url, err_cache_name) != 0)
	    {
		destination->fd = globus_gass_open(
			destination->url,
			O_CREAT|O_WRONLY|O_APPEND, 0700);
	    }
	}
    }

    if(!globus_l_gram_job_manager_url_is_dev_null(request->local_stderr))
    {
	request->output->stderr_fd =
	    globus_libc_open(request->local_stderr, O_RDONLY);
	destinations = request->output->stderr_destinations;
	while(!globus_list_empty(destinations))
	{
	    destination = globus_list_first(destinations);
	    destinations = globus_list_rest(destinations);

	    /* Don't bother to open /dev/null, and avoid feedback loops */
	    if((!globus_l_gram_job_manager_url_is_dev_null(destination->url)) &&
		strcmp(destination->url, out_cache_name) != 0 &&
		strcmp(destination->url, err_cache_name) != 0)
	    {
		destination->fd = globus_gass_open(
			destination->url,
			O_CREAT|O_WRONLY|O_APPEND, 0700);
	    }
	}
    }

    globus_libc_free(out_cache_name);
    globus_libc_free(err_cache_name);

    GlobusTimeReltimeSet(delay, GLOBUS_GRAM_JOB_MANAGER_OUTPUT_POLL_PERIOD, 0);
    GlobusTimeReltimeSet(period, GLOBUS_GRAM_JOB_MANAGER_OUTPUT_POLL_PERIOD, 0);

    globus_callback_register_periodic(
	    &request->output->callback_handle,
	    &delay,
	    &period,
	    globus_l_gram_job_manager_output_poll,
	    request,
	    NULL,
	    NULL);


    return GLOBUS_SUCCESS;
}
/* globus_i_gram_job_manager_output_destinations_open() */

/**
 * Close output destinations.
 *
 * Close the destinations associated with stdout and stderr. This
 * will block until the data is written, or an error occurs writing it.
 *
 * @param request
 *        The job request we are processing.
 * @note Called with the request locked.
 */
int
globus_i_gram_job_manager_output_close(
    globus_gram_jobmanager_request_t *	request)
{
    globus_l_gram_job_manager_output_destination_t *
					destination;
    globus_list_t *			tmp_list;
    struct stat				file_status;

    /* Disable any further polling of stdout and stderr files */
    globus_callback_unregister(request->output->callback_handle);

    if(request->output->stdout_fd != -1)
    {
	fstat(request->output->stdout_fd, &file_status);
	request->output->stdout_size = file_status.st_size;

	tmp_list = request->output->stdout_destinations;
	while(!globus_list_empty(tmp_list))
	{
	    destination = globus_list_first(tmp_list);
	    tmp_list = globus_list_rest(tmp_list);

	    globus_l_gram_job_manager_output_destination_flush(
		    request,
		    destination,
		    "stdout");
	    globus_gass_close(destination->fd);
	    destination->fd = -1;
	}
    }
    if(request->output->stderr_fd != -1)
    {
	fstat(request->output->stderr_fd, &file_status);
	request->output->stderr_size = file_status.st_size;

	tmp_list = request->output->stderr_destinations;
	while(!globus_list_empty(tmp_list))
	{
	    destination = globus_list_first(tmp_list);
	    tmp_list = globus_list_rest(tmp_list);

	    globus_l_gram_job_manager_output_destination_flush(
		    request,
		    destination,
		    "stderr");
	    globus_gass_close(destination->fd);
	    destination->fd = -1;
	}
    }
    return GLOBUS_SUCCESS;
}
/* globus_i_gram_job_manager_output_destinations_close() */

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
globus_i_gram_job_manager_output_local_name(
    globus_gram_jobmanager_request_t *	request,
    const char *			type)
{
    globus_l_gram_job_manager_output_destination_t *
					destination;
    char *				out_file;
    char *				fname;
    unsigned long			timestamp;
    globus_list_t *			destinations;

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
	    out_file = globus_i_gram_job_manager_output_get_cache_name(
		    request,
		    type);
	    globus_gass_cache_add(
		    &request->cache_handle,
		    out_file,
		    request->cache_tag,
		    GLOBUS_TRUE,
		    &timestamp,
		    &fname);

	    globus_gass_cache_add_done(
		    &request->cache_handle,
		    out_file,
		    request->cache_tag,
		    timestamp);

	    globus_libc_free(out_file);

	    return fname;
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
 *        The type of output file to get the name of. Only 
 *        "stdout" or "stderr" will return meaningful values.
 */
extern
char *
globus_i_gram_job_manager_output_get_cache_name(
    globus_gram_jobmanager_request_t *	request,
    const char *			type)
{
    char				hostname[MAXHOSTNAMELEN];
    char *				out_file;

    globus_libc_gethostname(hostname, sizeof(hostname));

    out_file = globus_libc_malloc(
		strlen("x-gass-cache://%s/%s/dev/%s") +
		strlen(hostname) +
		strlen(request->uniq_id) +
		strlen(type));

    sprintf(out_file,
		"x-gass-cache://%s/%s/dev/%s",
		hostname,
		request->uniq_id,
		type);

    return out_file;
}
/* globus_i_gram_job_manager_output_get_cache_name() */ 

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
 * @param time_stop
 *        Absolute time indicating when the callback should return by,
 *        if it is to be friendly to other registered events.
 * @param user_arg
 *        A void * casting of the job request structure.
 *
 */
static
globus_bool_t
globus_l_gram_job_manager_output_poll(
    globus_abstime_t *			time_stop,
    void *				user_arg)
{
    struct stat				file_status;
    globus_gram_jobmanager_request_t *	request;
    globus_list_t *			tmp_list;
    globus_bool_t			handled = GLOBUS_FALSE;
    globus_l_gram_job_manager_output_destination_t *
					destination;

    request = user_arg;

    globus_mutex_lock(&request->mutex);
    request->in_handler = GLOBUS_TRUE;

    if(request->output->stdout_fd != -1)
    {
	fstat(request->output->stdout_fd, &file_status);
	request->output->stdout_size = file_status.st_size;

	tmp_list = request->output->stdout_destinations;
	while(!globus_list_empty(tmp_list))
	{
	    destination = globus_list_first(tmp_list);
	    tmp_list = globus_list_rest(tmp_list);

	    globus_l_gram_job_manager_output_destination_flush(
		    request,
		    destination,
		    "stdout");
	}
    }
    if(request->output->stderr_fd != -1)
    {
	fstat(request->output->stderr_fd, &file_status);
	request->output->stderr_size = file_status.st_size;

	tmp_list = request->output->stderr_destinations;
	while(!globus_list_empty(tmp_list))
	{
	    destination = globus_list_first(tmp_list);
	    tmp_list = globus_list_rest(tmp_list);

	    globus_l_gram_job_manager_output_destination_flush(
		    request,
		    destination,
		    "stderr");
	}
    }
    request->in_handler = GLOBUS_FALSE;
    globus_mutex_unlock(&request->mutex);
    return handled;
}
/* globus_i_gram_job_manager_output_poll() */

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
 * GLOBUS_FAILURE is returned.
 */
static
int
globus_l_gram_job_manager_output_get_urls(
    globus_gram_jobmanager_request_t *	request,
    globus_list_t *			value_list,
    globus_list_t **			destinations,
    globus_bool_t			recursive)
{
    globus_rsl_value_t *		value;
    char *				filename;
    char *				tag;
    globus_l_gram_job_manager_output_destination_t *
					destination;
    int					rc;

    globus_jobmanager_log(
	request->jobmanager_log_fp,
	"JMI: Getting RSL output value%s\n",
	recursive ? " recursively" : "");

    value = globus_list_first(value_list);
    if(globus_rsl_value_is_literal(value))
    {
	/* Old style stdout or stderr rsl (stdout = url [tag]) */
	if(globus_list_size(value_list) > 2)
	{
	    return GLOBUS_FAILURE;
	}
	filename = globus_rsl_value_literal_get_string(value);

	if(globus_list_size(value_list) == 2)
	{
	    value = globus_list_first(globus_list_rest(value_list));

	    if(!globus_rsl_value_is_literal(value))
	    {
		return GLOBUS_FAILURE;
	    }
	    tag = globus_rsl_value_literal_get_string(value);
	}
	else
	{
	    tag = GLOBUS_NULL;
	}

	destination = globus_libc_malloc(
		sizeof(globus_l_gram_job_manager_output_destination_t));
	destination->url = globus_libc_strdup(filename);
	destination->tag = tag ? globus_libc_strdup(tag) : NULL;
	destination->position = 0;
	destination->fd = -1;

	globus_list_insert(destinations, destination);

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

	    rc = globus_l_gram_job_manager_output_get_urls(
		    request,
		    globus_rsl_value_sequence_get_value_list(value),
		    destinations,
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
	return GLOBUS_FAILURE;
    }
}
/* globus_l_gram_job_manager_output_get_urls() */


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

    globus_jobmanager_log(
	    request->jobmanager_log_fp,
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

static
globus_bool_t
globus_l_gram_job_manager_url_is_dev_null(
    const char *			url)
{
    return (strcmp(url, "/dev/null") == 0 ||
	    strcmp(url, "file:/dev/null") == 0 ||
	    strcmp(url, "file:///dev/null") == 0);
}

static
int
globus_l_gram_job_manager_output_destination_flush(
    globus_gram_jobmanager_request_t *	request,
    globus_l_gram_job_manager_output_destination_t *
    					destination,
    const char *			type)
{
    ssize_t				read_amt;
    ssize_t				write_amt;
    globus_off_t			size;
    int					fd;

    if(strcmp(type, "stdout") == 0)
    {
	size = request->output->stdout_size;
	fd = request->output->stdout_fd;
    }
    else if(strcmp(type, "stderr") == 0)
    {
	size = request->output->stderr_size;
	fd = request->output->stderr_fd;
    }
    else
    {
	return GLOBUS_FAILURE;
    }

    if(destination->fd != -1 && destination->position < size)
    {
	lseek(fd, destination->position, SEEK_SET);
    }
    while(destination->fd != -1 &&
	  destination->position < size)
    {
	do
	{
	    read_amt = read(fd,
		            request->output->buffer,
			    sizeof(request->output->buffer));
	}
	while(read_amt < 0 && (errno == EAGAIN || errno == EINTR));

	if(read_amt < 0)
	{
	    break;
	}

	do
	{
	    write_amt = write(destination->fd,
		              request->output->buffer,
			      read_amt);
	} while(write_amt < 0 && (errno == EAGAIN || errno == EINTR));

	if(write_amt < 0)
	{
	    break;
	}
	destination->position += write_amt;
    }
    return GLOBUS_SUCCESS;
}
