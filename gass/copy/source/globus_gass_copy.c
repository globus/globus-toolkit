
/**
 * @file globus_gass_copy.c
 */

/**
 *
 */
globus_result_t
globus_gass_copy_init(
    globus_gass_copy_handle_t * handle)

globus_result_t
globus_gass_copy_destroy(
    globus_gass_copy_handle_t * handle)

globus_result_t
globus_gass_copy_url2url(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    char * dest_url)

globus_result_t
globus_gass_copy_register_url2url(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    char * dest_url,
    callback_func,
    callback_arg)

globus_result_t
globus_gass_copy_url2fd(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    int dest_fd)

globus_result_t
globus_gass_copy_fd2url(
    globus_gass_copy_handle_t * handle,
    int source_fd,
    char * dest_url)

globus_result_t
globus_gass_copy_fd2fd(
    globus_gass_copy_handle_t * handle,
    int source_fd,
    int dest_fd)



    globus_gass_copy_url2url(handle, gsiftp://pitcairn/foo, ...)
    globus_gass_copy_url2url(handle, gsiftp://pitcairn/bar, ...)
