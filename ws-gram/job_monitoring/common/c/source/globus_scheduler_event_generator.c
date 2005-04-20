/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_common.h"
#include "globus_xio.h"
#include "globus_xio_file_driver.h"
#include "globus_scheduler_event_generator.h"
#include "globus_gram_protocol.h"
#include "version.h"

#include "ltdl.h"

static
int
globus_l_seg_activate(void);

static
int
globus_l_seg_deactivate(void);

static
globus_result_t
globus_l_seg_register_write(
    globus_byte_t *                     buf);

static
globus_result_t
globus_l_scheduler_event_state_change(
    time_t                              timestamp,
    const char *                        jobid,
    globus_gram_protocol_job_state_t    state,
    int                                 exit_code);

static
void
globus_l_xio_read_eof_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
void
globus_l_seg_writev_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

globus_module_descriptor_t globus_i_scheduler_event_generator_module =
{
    "globus_scheduler_event_generator",
    globus_l_seg_activate,
    globus_l_seg_deactivate,
    NULL,
    NULL,
    &local_version,
    NULL
};

static globus_mutex_t                   globus_l_seg_mutex;
static globus_cond_t                    globus_l_seg_cond;
static globus_xio_handle_t              globus_l_seg_output_handle;
static globus_xio_handle_t              globus_l_seg_input_handle;
static globus_xio_stack_t               globus_l_seg_file_stack;
static globus_xio_driver_t              globus_l_seg_file_driver;
static lt_dlhandle                      globus_l_seg_scheduler_handle;
static globus_module_descriptor_t *     globus_l_seg_scheduler_module;
static char                             globus_l_seg_input_buffer[1];
static time_t                           globus_l_seg_timestamp;
static globus_scheduler_event_generator_fault_handler_t
                                        globus_l_seg_fault_handler;
static void *                           globus_l_seg_fault_arg;
static globus_fifo_t                    globus_l_seg_buffers;
static globus_bool_t                    globus_l_seg_write_registered;
static int                              globus_l_seg_shutdown;

static
int
globus_l_seg_activate(void)
{
    globus_result_t                     result;
    globus_xio_attr_t                   out_attr;
    globus_xio_attr_t                   in_attr;
    int                                 rc;

    globus_l_seg_output_handle = NULL;
    globus_l_seg_input_handle = NULL;
    globus_l_seg_file_stack = NULL;
    globus_l_seg_file_driver = NULL;
    globus_l_seg_scheduler_handle = NULL;
    globus_l_seg_scheduler_module = NULL;
    globus_l_seg_timestamp = 0;
    globus_l_seg_fault_handler = NULL;
    globus_l_seg_fault_arg = NULL;
    globus_l_seg_write_registered = GLOBUS_FALSE;
    globus_l_seg_shutdown = 0;

    rc = lt_dlinit();
    if (rc != 0)
    {
        goto error;
    }
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    if (rc != GLOBUS_SUCCESS)
    {
        goto dlexit_error;
    }

    rc = globus_fifo_init(&globus_l_seg_buffers);
    if (rc != GLOBUS_SUCCESS)
    {
        goto deactivate_common_error;
    }

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto destroy_fifo_error;
    }

    result = globus_xio_driver_load("file", &globus_l_seg_file_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto deactivate_xio_error;
    }
    result = globus_xio_stack_init(&globus_l_seg_file_stack, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        goto unload_driver_error;
    }
    result = globus_xio_stack_push_driver(globus_l_seg_file_stack,
            globus_l_seg_file_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_stack_error;
    }

    result = globus_xio_attr_init(&out_attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_stack_error;
    }

    result = globus_xio_attr_cntl(
            out_attr,
            globus_l_seg_file_driver,
            GLOBUS_XIO_FILE_SET_FLAGS,
            GLOBUS_XIO_FILE_WRONLY);
    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_out_attr_error;
    }

    result = globus_xio_attr_cntl(
            out_attr,
            globus_l_seg_file_driver,
            GLOBUS_XIO_FILE_SET_HANDLE,
            fileno(stdout));

    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_out_attr_error;
    }

    result = globus_xio_attr_init(&in_attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_out_attr_error;
    }

    result = globus_xio_attr_cntl(
            in_attr,
            globus_l_seg_file_driver,
            GLOBUS_XIO_FILE_SET_FLAGS,
            GLOBUS_XIO_FILE_RDONLY);

    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_in_attr_error;
    }
    result = globus_xio_attr_cntl(
            in_attr,
            globus_l_seg_file_driver,
            GLOBUS_XIO_FILE_SET_HANDLE,
            fileno(stdin));

    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_in_attr_error;
    }

    result = globus_xio_handle_create(
            &globus_l_seg_output_handle,
            globus_l_seg_file_stack);
    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_in_attr_error;
    }

    result = globus_xio_open(globus_l_seg_output_handle, "", out_attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto close_out_handle_error;
    }

    result = globus_xio_handle_create(
            &globus_l_seg_input_handle,
            globus_l_seg_file_stack);
    if (result != GLOBUS_SUCCESS)
    {

        goto close_out_handle_error;
    
    }

    result = globus_xio_open(globus_l_seg_input_handle, "", in_attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto close_in_handle_error;
    }
    rc = globus_mutex_init(&globus_l_seg_mutex, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        goto close_in_handle_error;
    }
    rc = globus_cond_init(&globus_l_seg_cond, NULL);
    if (rc != GLOBUS_SUCCESS)
    {
        goto destroy_mutex_error;
    }

    result = globus_xio_register_read(
            globus_l_seg_input_handle,
            globus_l_seg_input_buffer,
            sizeof(globus_l_seg_input_buffer),
            1,
            NULL,
            globus_l_xio_read_eof_callback,
            NULL);

    if (result != GLOBUS_SUCCESS)
    {
        goto destroy_cond_error;
    }

    globus_xio_attr_destroy(in_attr);
    globus_xio_attr_destroy(out_attr);

    return 0;

destroy_cond_error:
    globus_cond_destroy(&globus_l_seg_cond);
destroy_mutex_error:
    globus_mutex_destroy(&globus_l_seg_mutex);
close_in_handle_error:
    globus_xio_close(globus_l_seg_input_handle, NULL);
close_out_handle_error:
    globus_xio_close(globus_l_seg_output_handle, NULL);
destroy_in_attr_error:
    globus_xio_attr_destroy(in_attr);
destroy_out_attr_error:
    globus_xio_attr_destroy(out_attr);
destroy_stack_error:
    globus_xio_stack_destroy(globus_l_seg_file_stack);
unload_driver_error:
    globus_xio_driver_unload(globus_l_seg_file_driver);
deactivate_xio_error:
    globus_module_deactivate(GLOBUS_XIO_MODULE);
destroy_fifo_error:
    globus_fifo_destroy(&globus_l_seg_buffers);
deactivate_common_error:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
dlexit_error:
    lt_dlexit();
error:
    return 1;
}
/* globus_l_seg_activate() */

static
int
globus_l_seg_deactivate(void)
{
    if (globus_l_seg_scheduler_module)
    {
        globus_module_deactivate(globus_l_seg_scheduler_module);
        globus_l_seg_scheduler_module = NULL;
    }

    if (globus_l_seg_scheduler_handle)
    {
        lt_dlclose(globus_l_seg_scheduler_handle);
        globus_l_seg_scheduler_handle = NULL;
    }

    globus_mutex_lock(&globus_l_seg_mutex);
    globus_l_seg_shutdown = 1;
    globus_l_seg_fault_handler = NULL;
    globus_l_seg_fault_arg = NULL;

    if (globus_l_seg_write_registered)
    {
        while (globus_l_seg_shutdown == 1)
        {
            globus_cond_wait(&globus_l_seg_mutex, &globus_l_seg_cond);
        }
    }
    globus_fifo_destroy(&globus_l_seg_buffers);
    globus_mutex_unlock(&globus_l_seg_mutex);

    globus_xio_close(globus_l_seg_output_handle, NULL);
    globus_xio_close(globus_l_seg_input_handle, NULL);

    globus_mutex_destroy(&globus_l_seg_mutex);
    globus_cond_destroy(&globus_l_seg_cond);

    globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    lt_dlexit();
    return 0;
}
/* globus_l_seg_deactivate() */

/**
 * Send an arbitrary SEG notification.
 * @ingroup seg_api
 *
 * @param format
 *     Printf-style format of the SEG notification message
 * @param ...
 *     Varargs which will be interpreted as per format.
 *
 * @retval GLOBUS_SUCCESS
 *     Scheduler message sent or queued.
 * @retval GLOBUS_SEG_ERROR_NULL
 *     Null format.
 * @retval GLOBUS_SEG_ERROR_INVALID_FORMAT
 *     Unable to determine length of formatted string.
 */
globus_result_t
globus_scheduler_event(
    const char * format,
    ...)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    char *                              buf;
    va_list                             ap;
    int                                 length;

    if (format == NULL)
    {
        result = GLOBUS_SEG_ERROR_NULL;

        goto error;
    }

    va_start(ap, format);
    length = globus_libc_vprintf_length(format, ap);
    va_end(ap);

    if (length <= 0)
    {
        result = GLOBUS_SEG_ERROR_INVALID_FORMAT(format);

        goto error;
    }

    buf = globus_libc_malloc(length+1);
    if (buf == NULL)
    {
        result = GLOBUS_SEG_ERROR_OUT_OF_MEMORY;

        goto error;
    }

    va_start(ap, format);
    vsprintf(buf, format, ap);
    va_end(ap);

    globus_mutex_lock(&globus_l_seg_mutex);
    result = globus_l_seg_register_write(buf);
    globus_mutex_unlock(&globus_l_seg_mutex);

error:
    return result;
}
/* globus_scheduler_event() */

/**
 * Send a job pending event to the JobSchedulerMonitor implementation.
 * @ingroup seg_api
 *
 * @param timestamp
 *        Timestamp to use for the event. If set to 0, the time which
 *        this function was called is used.
 * @param jobid
 *        String indicating the scheduler-specific name of the job.
 *
 * @retval GLOBUS_SUCCESS
 *     Scheduler message sent or queued.
 * @retval GLOBUS_SEG_ERROR_NULL
 *     Null jobid.
 * @retval GLOBUS_SEG_ERROR_INVALID_FORMAT
 *     Unable to determine length of formatted string.
 */
globus_result_t
globus_scheduler_event_pending(
    time_t                              timestamp,
    const char *                        jobid)
{
    if (jobid == NULL)
    {
        return GLOBUS_SEG_ERROR_NULL;
    }
    return globus_l_scheduler_event_state_change(
            timestamp,
            jobid,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING,
            0);

}
/* globus_scheduler_event_pending() */

/**
 * Send a job active event to the JobSchedulerMonitor implementation.
 * @ingroup seg_api
 *
 * @param timestamp
 *        Timestamp to use for the event. If set to 0, the time which
 *        this function was called is used.
 * @param jobid
 *        String indicating the scheduler-specific name of the job.
 *
 * @retval GLOBUS_SUCCESS
 *     Scheduler message sent or queued.
 * @retval GLOBUS_SEG_ERROR_NULL
 *     Null jobid.
 * @retval GLOBUS_SEG_ERROR_INVALID_FORMAT
 *     Unable to determine length of formatted string.
 */
globus_result_t
globus_scheduler_event_active(
    time_t                              timestamp,
    const char *                        jobid)
{
    if (jobid == NULL)
    {
        return GLOBUS_SEG_ERROR_NULL;
    }
    return globus_l_scheduler_event_state_change(
            timestamp,
            jobid,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0);
}

/**
 * Send a job failed event to the JobSchedulerMonitor implementation.
 * @ingroup seg_api
 *
 * @param timestamp
 *        Timestamp to use for the event. If set to 0, the time which
 *        this function was called is used.
 * @param jobid
 *        String indicating the scheduler-specific name of the job.
 * @param failure_code
 *        Failure code of the process if known.
 *
 * @retval GLOBUS_SUCCESS
 *     Scheduler message sent or queued.
 * @retval GLOBUS_SEG_ERROR_NULL
 *     Null jobid.
 * @retval GLOBUS_SEG_ERROR_INVALID_FORMAT
 *     Unable to determine length of formatted string.
 */
globus_result_t
globus_scheduler_event_failed(
    time_t                              timestamp,
    const char *                        jobid,
    int                                 failure_code)
{
    if (jobid == NULL)
    {
        return GLOBUS_SEG_ERROR_NULL;
    }
    return globus_l_scheduler_event_state_change(
            timestamp,
            jobid,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED,
            failure_code);
}

/**
 * Send a job done event to the JobSchedulerMonitor implementation.
 * @ingroup seg_api
 *
 * @param timestamp
 *        Timestamp to use for the event. If set to 0, the time which
 *        this function was called is used.
 * @param jobid
 *        String indicating the scheduler-specific name of the job.
 * @param exit_code
 *        Exit code of the process if known.
 *
 * @retval GLOBUS_SUCCESS
 *     Scheduler message sent or queued.
 * @retval GLOBUS_SEG_ERROR_NULL
 *     Null jobid.
 * @retval GLOBUS_SEG_ERROR_INVALID_FORMAT
 *     Unable to determine length of formatted string.
 */
globus_result_t
globus_scheduler_event_done(
    time_t                              timestamp,
    const char *                        jobid,
    int                                 exit_code)
{
    if (jobid == NULL)
    {
        return GLOBUS_SEG_ERROR_NULL;
    }
    return globus_l_scheduler_event_state_change(
            timestamp,
            jobid,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE,
            exit_code);
}

/**
 * Get the timestamp for the earliest event an SEG module should send.
 * @ingroup seg_api
 *
 * @param timestamp
 *     Pointer to a time_t which will be set to the timestamp passed to the
 *     SEG executable. The module should not send any events which occur prior
 *     to this timestamp.
 * @retval GLOBUS_SEG_ERROR_NULL
 *     Null timestamp.
 * @retval GLOBUS_SUCCESS
 *     Timestamp value updated. If the timestamp was not set on the SEG
 *     command-line, then the value pointed to by @a timestamp will be set to
 *     0.
 */
globus_result_t
globus_scheduler_event_generator_get_timestamp(
    time_t *                            timestamp)
{
    if (timestamp == NULL)
    {
        return GLOBUS_SEG_ERROR_NULL;
    }
    *timestamp = globus_l_seg_timestamp;

    return GLOBUS_SUCCESS;
}
/* globus_scheduler_event_generator_get_timestamp() */


globus_result_t
globus_scheduler_event_generator_set_timestamp(
    time_t                              timestamp)
{
    globus_result_t                     result = GLOBUS_SUCCESS;

    globus_mutex_lock(&globus_l_seg_mutex);
    if (globus_l_seg_timestamp != 0)
    {
        result = GLOBUS_SEG_ERROR_ALREADY_SET;
        goto error;
    }
    globus_l_seg_timestamp = timestamp;

    globus_mutex_unlock(&globus_l_seg_mutex);

    return GLOBUS_SUCCESS;

error:
    globus_mutex_unlock(&globus_l_seg_mutex);
    return result;
}
/* globus_scheduler_event_generator_set_timestamp() */

/**
 * Load a scheduler event generator module.
 *
 * If the module name begins with "/" then it is interpreted as a path name;
 * otherwise, the name is constructed using the convention:
 * @code $GLOBUS_LOCATION/lib/libglobus_seg_$MODULE_NAME_$FLAVOR.so@endcode,
 * where $GLOBUS_LOCATION is determined from the environment, $MODULE_NAME is
 * determined from the @a module_name parameter to the function, and $FLAVOR
 * is determined at compile time.
 *
 * @param module_name
 *     Name of the shared object to load.
 * @retval GLOBUS_SEG_ERROR_ALREADY_SET
 *     Already loaded a module.
 * @retval GLOBUS_SEG_ERROR_LOADING_MODULE
 *     Unable to load shared module.
 * @retval GLOBUS_SEG_ERROR_INVALID_MODULE
 *     Unable to find the loaded module's globus_module_descriptor_t
 */
globus_result_t
globus_scheduler_event_generator_load_module(
    const char *                        module_name)
{
    globus_result_t                     result;
    int                                 rc;
    const char *                        flavor_name = GLOBUS_FLAVOR_NAME;
    const char *                        symbol_name
            = "globus_scheduler_event_module_ptr";
    char *                              globus_loc = NULL;
    char *                              module_path = NULL;

    globus_mutex_lock(&globus_l_seg_mutex);
    if (globus_l_seg_scheduler_handle != NULL)
    {
        result = GLOBUS_SEG_ERROR_ALREADY_SET;

        goto unlock_error;
    }

    if (module_name[0] != '/')
    {
        result = globus_location(&globus_loc);

        if (result != GLOBUS_SUCCESS)
        {
            result = GLOBUS_SEG_ERROR_OUT_OF_MEMORY;

            goto unlock_error;
        }

        module_path = globus_libc_malloc(strlen(globus_loc) +
                strlen("%s/lib/libglobus_seg_%s_%s.la") + strlen(module_name) +
                strlen(flavor_name));

        if (module_path == NULL)
        {
            result = GLOBUS_SEG_ERROR_OUT_OF_MEMORY;

            goto free_globus_location_error;
        }

        sprintf(module_path, "%s/lib/libglobus_seg_%s_%s.la",
                globus_loc, module_name, flavor_name);
        globus_l_seg_scheduler_handle = lt_dlopen(module_path);
    }
    else
    {
        globus_l_seg_scheduler_handle = lt_dlopen(module_name);
    }

    if (globus_l_seg_scheduler_handle == NULL)
    {
        result = GLOBUS_SEG_ERROR_LOADING_MODULE(module_name,
                lt_dlerror());

        goto free_module_path_error;
    }
    globus_l_seg_scheduler_module = (globus_module_descriptor_t *)
            lt_dlsym(globus_l_seg_scheduler_handle, symbol_name);

    if (globus_l_seg_scheduler_module == NULL)
    {
        result = GLOBUS_SEG_ERROR_INVALID_MODULE(module_name, lt_dlerror());

        goto dlclose_error;
    }

    rc = globus_module_activate(globus_l_seg_scheduler_module);

    if (rc != 0)
    {
        result = GLOBUS_SEG_ERROR_INVALID_MODULE(
                module_name,
                "activation failed");

        goto dlclose_error;
    }

    globus_mutex_unlock(&globus_l_seg_mutex);

    globus_libc_free(globus_loc);
    globus_libc_free(module_path);

    return GLOBUS_SUCCESS;

dlclose_error:
    lt_dlclose(globus_l_seg_scheduler_handle);
    globus_l_seg_scheduler_handle = NULL;
    globus_l_seg_scheduler_module = NULL;
free_module_path_error:
    if (module_path != NULL)
    {
        globus_libc_free(module_path);
    }
free_globus_location_error:
    if (globus_loc != NULL)
    {
        globus_libc_free(globus_loc);
    }
unlock_error:
    globus_mutex_unlock(&globus_l_seg_mutex);
    return result;
}
/* globus_scheduler_event_generator_load_module() */

globus_result_t
globus_scheduler_event_generator_set_fault_handler(
    globus_scheduler_event_generator_fault_handler_t
                                        fault_handler,
    void *                              user_arg)
{
    globus_result_t                     result = GLOBUS_SUCCESS;

    globus_mutex_lock(&globus_l_seg_mutex);

    if (globus_l_seg_fault_handler != NULL)
    {
        result = GLOBUS_SEG_ERROR_ALREADY_SET;

        goto unlock_error;
    }

    globus_l_seg_fault_handler = fault_handler;
    globus_l_seg_fault_arg = user_arg;

    globus_mutex_unlock(&globus_l_seg_mutex);

    return result;

unlock_error:
    globus_mutex_unlock(&globus_l_seg_mutex);

    return result;
}
/* globus_scheduler_event_generator_set_fault_handler() */

/**
 * Format a SEG protocol message out of a job state change.
 *
 * @param timestamp
 *     Time when the job state change occurred. If this is 0, then
 *     the current time will be used.
 * @param jobid
 *     Scheduler-specific jobid value.
 * @param state
 *     New state of the job.
 * @param exit_code
 *     Exit code of the job.
 * @return See globus_scheduler_event() documentation for return values for
 *     this function.
 */
static
globus_result_t
globus_l_scheduler_event_state_change(
    time_t                              timestamp,
    const char *                        jobid,
    globus_gram_protocol_job_state_t    state,
    int                                 exit_code)
{
    if (timestamp == 0)
    {
        timestamp = time(NULL);
    }

    return globus_scheduler_event(
            "001;%lu;%s;%d;%d\n",
            timestamp,
            jobid,
            state,
            exit_code);
}
/* globus_l_scheduler_event_state_change() */

static
void
globus_l_xio_read_eof_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_scheduler_event_generator_fault_handler_t
                                        handler;
    void *                              arg;

    if (result == GLOBUS_SUCCESS)
    {
        /* shouldn't be reading stuff here!?! */
        result = globus_xio_register_read(
                globus_l_seg_input_handle,
                globus_l_seg_input_buffer,
                sizeof(globus_l_seg_input_buffer),
                1,
                NULL,
                globus_l_xio_read_eof_callback,
                NULL);
    }

    globus_mutex_lock(&globus_l_seg_mutex);
    handler = globus_l_seg_fault_handler;
    arg = globus_l_seg_fault_arg;
    globus_mutex_unlock(&globus_l_seg_mutex);

    if (result != GLOBUS_SUCCESS && handler != NULL)
    {
        (*handler)(arg, result);
    }
}
/* globus_l_xio_read_eof_callback() */

static
globus_result_t
globus_l_seg_register_write(
    globus_byte_t *                     buf)
{
    globus_result_t                     result;
    size_t                              cnt;
    globus_xio_iovec_t *                iov;
    size_t                              nbytes=0;
    globus_scheduler_event_generator_fault_handler_t
                                        handler;
    void *                              arg;
    int                                 i;

    if (buf)
    {
        globus_fifo_enqueue(&globus_l_seg_buffers, buf);
    }

    cnt = globus_fifo_size(&globus_l_seg_buffers);
    if ((!globus_l_seg_write_registered) && cnt > 0)
    {

        iov = globus_libc_calloc(cnt, sizeof(globus_xio_iovec_t));
        if (iov == NULL)
        {
            result = GLOBUS_SEG_ERROR_OUT_OF_MEMORY;

            goto call_fault_handler;
        }

        for (i = 0; i < cnt; i++)
        {
            iov[i].iov_base = globus_fifo_dequeue(&globus_l_seg_buffers);
            iov[i].iov_len = strlen((char *)iov[i].iov_base);
            nbytes += iov[i].iov_len;
        }

        result = globus_xio_register_writev(
                globus_l_seg_output_handle,
                iov,
                cnt,
                nbytes,
                NULL,
                globus_l_seg_writev_callback,
                NULL);

        if (result != GLOBUS_SUCCESS)
        {
            goto call_fault_handler;
        }
        globus_l_seg_write_registered = GLOBUS_TRUE;
    }

    return GLOBUS_SUCCESS;

call_fault_handler:
    if (globus_l_seg_fault_handler)
    {
        handler = globus_l_seg_fault_handler;
        arg = globus_l_seg_fault_arg;

        (*handler)(arg, result);
    }
    return result;
}
/* globus_l_seg_register_write() */

/**
 * Callback for writing event to scheduler.
 *
 * @param handle
 * @param result
 * @param iovec
 * @param count
 * @param nbytes
 * @param data_desc
 * @param user_arg
 */
static
void
globus_l_seg_writev_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    int                                 i;
    globus_scheduler_event_generator_fault_handler_t
                                        handler = NULL;
    void *                              arg;
    globus_bool_t                       reregister_write = GLOBUS_FALSE;
    int                                 do_shutdown = 0;

    for (i = 0; i < count; i++)
    {
        globus_libc_free(iovec[i].iov_base);
    }
    globus_libc_free(iovec);

    globus_mutex_lock(&globus_l_seg_mutex);
    globus_l_seg_write_registered = GLOBUS_FALSE;

    if (result != GLOBUS_SUCCESS)
    {
        handler = globus_l_seg_fault_handler;
        arg = globus_l_seg_fault_arg;
    }
    else if (!globus_fifo_empty(&globus_l_seg_buffers))
    {
        reregister_write = GLOBUS_TRUE;
    }
    else if (globus_l_seg_shutdown)
    {
        do_shutdown = 1;
    }
    if (handler)
    {
        (*handler)(arg, result);
    }
    if (reregister_write)
    {
        globus_l_seg_register_write(NULL);
    }

    if (do_shutdown)
    {
        globus_l_seg_shutdown = 2;
        globus_cond_signal(&globus_l_seg_cond);
    }
    globus_mutex_unlock(&globus_l_seg_mutex);
}
/* globus_l_seg_writev_callback() */
