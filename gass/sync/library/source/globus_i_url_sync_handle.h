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
 * @file globus_i_url_sync.h
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _GLOBUS_I_URL_SYNC_HANDLE_H
#define	_GLOBUS_I_URL_SYNC_HANDLE_H

#include "globus_url_sync.h"
#include "globus_common_include.h"

#ifndef EXTERN_C_BEGIN
#   ifdef  __cplusplus
#       define EXTERN_C_BEGIN extern "C" {
#       define EXTERN_C_END }
#   else
#       define EXTERN_C_BEGIN
#       define EXTERN_C_END
#   endif
#endif

EXTERN_C_BEGIN

/**
 * Locks a mutex associated with the handle.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  GLOBUS_SUCCESS
 *          The handle was successfully locked
 * @retval  Error
 *          An error as defined by globus_mutex_lock()
 */
int
globus_i_url_sync_handle_lock(
    globus_url_sync_handle_t                handle);

/**
 * Unlocks a mutex associated with the handle.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  GLOBUS_SUCCESS
 *          The handle was successfully unlocked
 * @retval  Error
 *          An error as defined by globus_mutex_unlock()
 */
int
globus_i_url_sync_handle_unlock(
    globus_url_sync_handle_t                handle);

/**
 * Gets the source endpoint.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  globus_i_url_sync_endpoint_t *
 *          Pointer to the source endpoint.
 */
globus_url_sync_endpoint_t *
globus_i_url_sync_handle_get_source(
    globus_url_sync_handle_t                handle);

/**
 * Sets the source endpoint.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @param   source
 *          Pointer to the source endpoint.
 */
void
globus_i_url_sync_handle_set_source(
    globus_url_sync_handle_t                handle,
    globus_url_sync_endpoint_t *            source);

/**
 * Gets the destination endpoint.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  globus_i_url_sync_endpoint_t *
 *          Pointer to the destination endpoint.
 */
globus_url_sync_endpoint_t *
globus_i_url_sync_handle_get_destination(
    globus_url_sync_handle_t                handle);

/**
 * Sets the destination endpoint.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @param   destination
 *          Pointer to the destination endpoint.
 */
void
globus_i_url_sync_handle_set_destination(
    globus_url_sync_handle_t                handle,
    globus_url_sync_endpoint_t *            destination);

/**
 * Checks active state.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  GLOBUS_TRUE
 *          Handle is active.
 * @retval  GLOBUS_FALSE
 *          Handle is not active.
 */
globus_bool_t
globus_i_url_sync_handle_is_active(
    globus_url_sync_handle_t                handle);

/**
 * Activates the handle. The handle's state will be set to active after this
 * call returns successfully.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  GLOBUS_SUCCESS
 *          Handle has been activated.
 * @retval  Error
 *          An error object.
 */
globus_result_t
globus_i_url_sync_handle_activate(
    globus_url_sync_handle_t                handle);

/**
 * Checks inactive state.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  GLOBUS_TRUE
 *          Handle is inactive.
 * @retval  GLOBUS_FALSE
 *          Handle is not inactive.
 * @see globus_i_url_sync_endpoint_t
 */
globus_bool_t
globus_i_url_sync_handle_is_inactive(
    globus_url_sync_handle_t                handle);

/**
 * Sets the complete callback.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @param   complete_callback
 *          Complete callback function.
 * @see globus_url_sync_complete_callback_t
 */
void
globus_i_url_sync_handle_set_complete_callback(
    globus_url_sync_handle_t                handle,
    globus_url_sync_complete_callback_t     complete_callback);

/**
 * Gets the complete callback.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  globus_url_sync_complete_callback_t
 *          Complete callback function.
 * @see globus_url_sync_complete_callback_t
 */
globus_url_sync_complete_callback_t
globus_i_url_sync_handle_get_complete_callback(
    globus_url_sync_handle_t                handle);

/**
 * Sets the result callback.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @param   result_callback
 *          Result callback function.
 * @see globus_url_sync_result_callback_t
 */
void
globus_i_url_sync_handle_set_result_callback(
    globus_url_sync_handle_t                handle,
    globus_url_sync_result_callback_t     result_callback);

/**
 * Gets the result callback.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  globus_url_sync_result_callback_t
 *          Result callback function.
 * @see globus_url_sync_result_callback_t
 */
globus_url_sync_result_callback_t
globus_i_url_sync_handle_get_result_callback(
    globus_url_sync_handle_t                handle);

/**
 * Sets the user argument.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @param   user_arg
 *          User argument passed to callback functions.
 * @see globus_url_sync_complete_callback_t
 */
void
globus_i_url_sync_handle_set_user_arg(
    globus_url_sync_handle_t                handle,
    void *                                  user_arg);

/**
 * Gets the user argument.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  void *
 *          User callback argument.
 * @see globus_url_sync_complete_callback_t
 */
void *
globus_i_url_sync_handle_get_user_arg(
    globus_url_sync_handle_t                handle);

/**
 * Gets the comparator.
 * @ingroup globus_url_sync_handle
 *
 * @param   handle
 *          URL Sync Handle.
 * @retval  globus_url_sync_comparator_t *
 *          A pointer to the synchronization comparator.
 */
globus_url_sync_comparator_t *
globus_i_url_sync_handle_get_comparator(
    globus_url_sync_handle_t                handle);

/**
 * Initializes the endpoint structure.
 * @ingroup globus_url_sync_handle
 *
 * @param   endpoint_out
 *          A newly allocated and initialized endpoint structure pointer will
 *          be assigned to the given address.
 * @param   url
 *          The endpoint url, given as a flat character string.
 * @param   ftp_handle,
 *          The FTP handle for corresponding to the url.
 * @retval  GLOBUS_SUCCESS
 *          Returns GLOBUS_SUCCESS or an error code if the operation failed.
 */
globus_result_t
globus_i_url_sync_endpoint_init(
    globus_url_sync_endpoint_t **           endpoint_out,
    const char *                            url,
    globus_ftp_client_handle_t *            ftp_handle);

/**
 * Destroys the endpoint structure.
 * @ingroup globus_url_sync_handle
 *
 * @param   endpoint
 *          An initialized endpoint.
 * @retval  GLOBUS_SUCCESS
 *          Returns GLOBUS_SUCCESS or an error code if the operation failed.
 */
globus_result_t
globus_i_url_sync_endpoint_destroy(
    globus_url_sync_endpoint_t *            endpoint);

EXTERN_C_END

#endif	/* _GLOBUS_I_URL_SYNC_HANDLE_H */

#endif  /* GLOBUS_DONT_DOCUMENT_INTERNAL */
