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
 * @file globus_i_url_sync_list.h
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _globus_i_url_sync_list_H
#define	_globus_i_url_sync_list_H

#include "globus_url_sync.h"
#include "globus_common_include.h"
#include "globus_ftp_client.h"

#ifndef EXTERN_C_BEGIN
#   ifdef  __cplusplus
#       define EXTERN_C_BEGIN extern "C" {
#       define EXTERN_C_END }
#   else
#       define EXTERN_C_BEGIN
#       define EXTERN_C_END
#   endif
#endif

/**
 * @defgroup globus_i_url_sync_list URL Directory List Operation
 *
 * The FTP list operations provide a simplified interface to the Grid FTP Client
 * operation for listing entries of a directory.
 */

/**
 * List operation complete callback.
 *
 * @ingroup globus_i_url_sync_list
 *
 * @param user_arg
 *        The user_arg parameter passed to the operation.
 * @param handle
 *        The FTP handle used for the operation.
 * @param error
 *        A Globus error object indicating any problem which occurred,
 *        or GLOBUS_SUCCESS, if the operation completed successfully.
 */
typedef void (*globus_i_url_sync_list_complete_callback_t) (
    void *                                  user_arg,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_object_t *                       error);

/**
 * Creates a list of directory entries for a given URL. This function reuses a
 * FTP client handle if the URL is of scheme "gsiftp". At present this function
 * only supports listings of FTP remote directories.
 *
 * @ingroup globus_i_url_sync_list
 *
 * @param   url
 *          URL for directory listing.
 * @param   ftp_handle
 *          FTP client handle for FTP operations.
 * @param   entries
 *          Address of a globus_list_t structure for results. When the list
 * operation completes, the entries structure will be populated with the parsed
 * directory entries of url. The entries list and its datums must be freed by
 * the caller when they are no longer needed.
 * @param   complete_callback
 *          User callback when operation completes.
 * @param   callback_arg
 *          User argument for callback.
 * @retval  Result
 *          A result value set to GLOBUS_SUCCESS, if successfully. If error,
 *          the result value may be used to retrieve an error object.
 */
globus_result_t
globus_i_url_sync_list(
    const char *                            url,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_list_t **                        entries,
    globus_i_url_sync_list_complete_callback_t
                                            complete_callback,
    void *                                  callback_arg);

/**
 * @ingroup globus_i_url_sync_list
 *
 * Frees a list of directory entries. It frees the contents and the list. There
 * is nothing special (at present) about the entries in the list. They are char*
 * pointers.
 *
 * @param   entries
 *          Pointer to list of entries.
 */
void
globus_i_url_sync_list_free_entries(
    globus_list_t *                         entries);

EXTERN_C_END

#endif	/* _globus_i_url_sync_list_H */

#endif  /* GLOBUS_DONT_DOCUMENT_INTERNAL */
