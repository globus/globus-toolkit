#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_ftp_client.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_ftp_client.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

static int globus_l_ftp_client_activate(void);
static int globus_l_ftp_client_deactivate(void);

/**
 * Default authorization information for GSIFTP.
 */
globus_ftp_control_auth_info_t		globus_i_ftp_client_default_auth_info;


/* @{ */
/**
 * Thread-safety support for deactivation reference counting
 */
static
globus_mutex_t 				globus_l_ftp_client_active_list_mutex;

static
globus_mutex_t 				globus_l_ftp_client_control_list_mutex;

static
globus_cond_t 				globus_l_ftp_client_active_list_cond;

static
globus_cond_t 				globus_l_ftp_client_control_list_cond;
/* @} */

/**
 * List of active client handles.
 *
 * A handle is active if an operation's callback has been associated
 * with it, and the operation's processing has begun.
 */
static
globus_list_t *
globus_l_ftp_client_active_handle_list;

/**
 * List of active control handles.
 *
 * A handle from the time the initial connection callback has been
 * registered until the close or force_close callback has been called.
 */
static
globus_list_t *
globus_l_ftp_client_active_control_list;

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t		globus_i_ftp_client_module =
{
    "globus_ftp_client",
    globus_l_ftp_client_activate,
    globus_l_ftp_client_deactivate,
    GLOBUS_NULL
};

/**
 * Module activation
 */
static
int
globus_l_ftp_client_activate(void)
{
    globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);
    globus_mutex_init(&globus_l_ftp_client_active_list_mutex, GLOBUS_NULL);
    globus_mutex_init(&globus_l_ftp_client_control_list_mutex, GLOBUS_NULL);
    globus_cond_init(&globus_l_ftp_client_active_list_cond, GLOBUS_NULL);
    globus_cond_init(&globus_l_ftp_client_control_list_cond, GLOBUS_NULL);
    globus_l_ftp_client_active_handle_list = GLOBUS_NULL;
    globus_l_ftp_client_active_control_list = GLOBUS_NULL;

    globus_ftp_control_auth_info_init(&globus_i_ftp_client_default_auth_info,
		                      GSS_C_NO_CREDENTIAL,
				      GLOBUS_TRUE,
				      ":globus-mapping:",
				      "",
				      0,
				      0);
    return GLOBUS_SUCCESS;
}

/**
 * Module deactivation
 *
 */
static
int
globus_l_ftp_client_deactivate(void)
{
    globus_mutex_lock(&globus_l_ftp_client_active_list_mutex);

    /* Wait for all client library callbacks to complete.
     */
    while(! globus_list_empty(globus_l_ftp_client_active_handle_list))
    {
	globus_ftp_client_handle_t *tmp;

	tmp = globus_list_first(globus_l_ftp_client_active_handle_list);

	globus_ftp_client_abort(tmp);

	globus_cond_wait(&globus_l_ftp_client_active_list_cond,
			 &globus_l_ftp_client_active_list_mutex);
    }
    globus_mutex_unlock(&globus_l_ftp_client_active_list_mutex);
    /* TODO: Destroy all cached targets. */

    /* Wait for all detached target control library callbacks to
     * complete.
     */
    globus_mutex_lock(&globus_l_ftp_client_control_list_mutex);
    while(! globus_list_empty(globus_l_ftp_client_active_control_list))
    {
	globus_cond_wait(&globus_l_ftp_client_control_list_cond,
			 &globus_l_ftp_client_control_list_mutex);
    }
    globus_mutex_unlock(&globus_l_ftp_client_control_list_mutex);

    globus_mutex_destroy(&globus_l_ftp_client_active_list_mutex);
    globus_cond_destroy(&globus_l_ftp_client_active_list_cond);

    globus_mutex_destroy(&globus_l_ftp_client_control_list_mutex);
    globus_cond_destroy(&globus_l_ftp_client_control_list_cond);
    globus_module_deactivate(GLOBUS_FTP_CONTROL_MODULE);

    return GLOBUS_SUCCESS;
}
/* globus_l_ftp_client_deactivate() */

/**
 *
 * Add a reference to a client handle to the shutdown count.
 *
 * When deactivating, we wait for all callbacks associated with
 * the FTP client library to be completed. This function adds the
 * specified handle to the active handle list, so that deactivation
 * will wait for it.
 * 
 * @param handle
 *        The handle to add to the list.
 */
void
globus_i_ftp_client_handle_is_active(
    globus_ftp_client_handle_t *		handle)
{
    globus_mutex_lock(&globus_l_ftp_client_active_list_mutex);
    globus_list_insert(&globus_l_ftp_client_active_handle_list,
		       handle);
    globus_mutex_unlock(&globus_l_ftp_client_active_list_mutex);
}
/* globus_i_ftp_client_handle_is_active() */

/**
 * Remove a reference to a client handle to the shutdown count.
 *
 * When deactivating, we wait for all callbacks associated with
 * the FTP client library to be completed. This function removes the
 * specified handle to the active handle list, so that deactivation
 * will not wait for it any more.
 *
 * This funciton also wakes up the deactivation function if it is
 * waiting for this handle's callbacks to terminate.
 * 
 * @param handle
 *        The handle to remove to the list.
 */
void
globus_i_ftp_client_handle_is_not_active(
    globus_ftp_client_handle_t *		handle)
{
    globus_list_t * node;

    globus_mutex_lock(&globus_l_ftp_client_active_list_mutex);
    node = globus_list_search(globus_l_ftp_client_active_handle_list,
			      handle);
    globus_assert(node);
    globus_list_remove(&globus_l_ftp_client_active_handle_list,
		       node);
    globus_cond_signal(&globus_l_ftp_client_active_list_cond);
    globus_mutex_unlock(&globus_l_ftp_client_active_list_mutex);
}
/* globus_i_ftp_client_handle_is_not_active() */


/**
 *
 * Add a reference to a control handle to the shutdown count.
 *
 * When deactivating, we wait for all callbacks associated with
 * the FTP client library to be completed. This function adds the
 * specified handle to the active control handle list, so that
 * deactivation will wait for it.
 * 
 * @param handle
 *        The handle to add to the list.
 */
void
globus_i_ftp_client_control_is_active(
    globus_ftp_control_handle_t *		handle)
{
    globus_mutex_lock(&globus_l_ftp_client_control_list_mutex);
    globus_list_insert(&globus_l_ftp_client_active_control_list,
		       handle);
    globus_mutex_unlock(&globus_l_ftp_client_control_list_mutex);
}
/* globus_i_ftp_client_control_is_active() */

/**
 * Remove a reference to a control handle to the shutdown count.
 *
 * When deactivating, we wait for all callbacks associated with
 * the FTP client library to be completed. This function removes the
 * specified handle to the active handle list, so that deactivation
 * will not wait for it any more.
 *
 * This funciton also wakes up the deactivation function if it is
 * waiting for this handle's callbacks to terminate.
 * 
 * @param handle
 *        The handle to remove to the list.
 */
void
globus_i_ftp_client_control_is_not_active(
    globus_ftp_control_handle_t *		handle)
{
    globus_list_t * node;

    globus_mutex_lock(&globus_l_ftp_client_control_list_mutex);
    node = globus_list_search(globus_l_ftp_client_active_control_list,
			      handle);
    globus_assert(node);
    globus_list_remove(&globus_l_ftp_client_active_control_list,
		       node);
    globus_cond_signal(&globus_l_ftp_client_control_list_cond);
    globus_mutex_unlock(&globus_l_ftp_client_control_list_mutex);
}
/* globus_i_ftp_client_control_is_not_active() */

/**
 * Convert and FTP operation into a string.
 *
 * This function is used in various error message generators in
 * the ftp client library.
 *
 * @param op
 *        The operation to stringify.
 *
 * @return This function returns a static string representation
 *         of the operation. The string MUST NOT be modified or
 *         freed by the caller.
 */
const char *
globus_i_ftp_op_to_string(
    globus_i_ftp_client_operation_t		op)
{
    static const char * get      = "GLOBUS_FTP_CLIENT_GET";
    static const char * list     = "GLOBUS_FTP_CLIENT_LIST";
    static const char * nlst     = "GLOBUS_FTP_CLIENT_NLST";
    static const char * delete   = "GLOBUS_FTP_CLIENT_DELETE";
    static const char * mkdir    = "GLOBUS_FTP_CLIENT_MKDIR";
    static const char * rmdir    = "GLOBUS_FTP_CLIENT_RMDIR";
    static const char * move     = "GLOBUS_FTP_CLIENT_MOVE";
    static const char * put      = "GLOBUS_FTP_CLIENT_PUT";
    static const char * transfer = "GLOBUS_FTP_CLIENT_TRANSFER";
    static const char * idle     = "GLOBUS_FTP_CLIENT_IDLE";

    switch(op)
    {
    case GLOBUS_FTP_CLIENT_MKDIR:
	return mkdir;
    case GLOBUS_FTP_CLIENT_RMDIR:
	return rmdir;
    case GLOBUS_FTP_CLIENT_MOVE:
	return move;
    case GLOBUS_FTP_CLIENT_LIST:
	return list;
    case GLOBUS_FTP_CLIENT_NLST:
	return nlst;
    case GLOBUS_FTP_CLIENT_DELETE:
	return delete;
    case GLOBUS_FTP_CLIENT_GET:
	return get;
    case GLOBUS_FTP_CLIENT_PUT:
	return put;
    case GLOBUS_FTP_CLIENT_TRANSFER:
	return transfer;
    case GLOBUS_FTP_CLIENT_IDLE:
	return idle;
    default:
	return "INVALID OPERATION";
    }
}
/* globus_i_ftp_op_to_string() */

/**
 * Count the number of digits in an offset.
 *
 * This function is used by various string generators to figure
 * out how large a data buffer to allocate to hold the string
 * representation of a number.
 *
 * @param num 
 *        The number to check.
 *
 * @return The numbe of digits (plus 1 for negative numbers) in
 *         an offset.
 */
int
globus_i_ftp_client_count_digits(globus_off_t num)
{
    int digits = 1;

    if(num < 0)
    {
	digits++;
	num = -num;
    }
    while(0 < (num = (num / 10))) digits++;

    return digits;
}
/* globus_i_ftp_client_count_digits() */


#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

