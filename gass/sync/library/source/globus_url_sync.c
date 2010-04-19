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
 * @file globus_url_sync.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_url_sync.h"
#include "globus_i_url_sync.h"
#include "globus_i_url_sync_list.h"
#include "globus_i_url_sync_log.h"
#include "globus_ftp_client.h"
#include "globus_libc.h"
#include "globus_common.h"
#include "globus_i_url_sync_handle.h"
#include <stdlib.h>
#include <string.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/* Macros */

#define globus_l_url_sync_url2strlen(url)   globus_l_url_sync_BUFLEN

/* Constants */

static const int globus_l_url_sync_BUFLEN = GLOBUS_URL_SYNC_DIR_ENTRY_LENGTH_MAX + 1;

/* Types */

/**
 * @ingroup globus_i_url_sync
 *
 * Maintains state for the sync argument.
 */

static
globus_l_url_sync_arg_t *
globus_l_url_sync_arg_cons(
    globus_url_sync_handle_t                handle,
    globus_url_sync_endpoint_t *            source,
    globus_url_sync_endpoint_t *            destination,
    globus_l_url_sync_arg_t *               parent)
{
    globus_l_url_sync_arg_t *               arg;
    arg = (globus_l_url_sync_arg_t*) globus_libc_malloc(
            sizeof(globus_l_url_sync_arg_t));
    globus_assert(arg);
    arg->handle             = handle;
    arg->entries            = NULL;
    arg->source             = source;
    arg->destination        = destination;
    arg->parent             = parent;

    return arg;
}

/** Makes a new endpoint object by concatenating the base url with the child. */
static
globus_url_sync_endpoint_t *
globus_l_url_sync_make_new_endpoint(
    const globus_url_sync_endpoint_t *      base,
    const char *                            child)
{
    globus_url_sync_endpoint_t *            new_endpoint;
    char *                                  new_url;
    unsigned int                            base_len, child_len;

    globus_assert(base);
    globus_assert(base->url);
    globus_assert(child);

    base_len = globus_libc_strlen(base->url);
    globus_assert(base_len);
    child_len = globus_libc_strlen(child);
    globus_assert(child_len);

    /* Allocate new url and pad with room for '/' and '\0' */
    new_url = globus_libc_malloc(sizeof(char) * (base_len + 1 + child_len + 1));

    /* Concat urls to form new url */
    strcpy(new_url, base->url);
    if (*(new_url+base_len-1) != '/')
    {
        *(new_url+(base_len)) = '/';
	base_len++;
    }
    strcpy((new_url+base_len), child);

    /* Init new endpoint */
    globus_i_url_sync_endpoint_init(&new_endpoint, new_url, base->ftp_handle);
    globus_assert(new_endpoint);

    /* Free the new url, and return new endpoint */
    globus_libc_free(new_url);
    return new_endpoint;
} /* globus_l_url_sync_make_new_endpoint */

/** Makes a new source endpoint object by parsing mlst results and
    concatenating the base url with the child. */
static
globus_url_sync_endpoint_t *
globus_l_url_sync_make_src_endpoint(
				    const globus_url_sync_endpoint_t *      base,
				    const char *                            mlst_results,
				    char * child)
{
    globus_url_sync_endpoint_t *            new_endpoint;
    char *                                  new_url;
    unsigned int                            base_len, child_len;
  
    globus_assert(base);
    globus_assert(base->url);
    globus_assert(child);
  
    base_len = globus_libc_strlen(base->url);
    globus_assert(base_len);
  
    new_endpoint = globus_libc_malloc(sizeof(globus_url_sync_endpoint_t));
  
    memset(new_endpoint, 0, sizeof(globus_url_sync_endpoint_t));
    globus_assert(new_endpoint);
  
    parse_mlst_buffer(new_endpoint, (char *)mlst_results, child);
    child_len = globus_libc_strlen(child);
    globus_assert(child_len);
  
    /* Allocate new url and pad with room for '/' and '\0' */
    new_url = globus_libc_malloc(sizeof(char) * (base_len + 1 + child_len + 1));
    globus_assert(new_url);
  
    /* Concat urls to form new url */
    strcpy(new_url, base->url);
    if (*(new_url+base_len-1) != '/')
    {
        *(new_url+(base_len)) = '/';
	base_len++;
    }
    strcpy((new_url+base_len), child);
  
    /* Init new endpoint */
    new_endpoint->url = strdup(new_url);
    new_endpoint->ftp_handle = base->ftp_handle;
  
    /* Free the new url, and return new endpoint */
    globus_libc_free(new_url);
    return new_endpoint;
} /* globus_l_url_sync_make_src_endpoint */

static
void
globus_l_url_sync_arg_destroy(
    globus_l_url_sync_arg_t *               arg)
{
    globus_assert(arg);
    globus_i_url_sync_list_free_entries(arg->entries);
    globus_libc_free(arg);
}

/** The compare function callback. This cb is used for the top-level comarison,
 *  for the first source, destination pair entered in the globus-url-sync call.
 **/
static
void
globus_l_url_sync_compare_func_top_cb(
    void *                                      arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int         				compare_result,
    globus_object_t *                           error);

/** The compare function callback. This cb is used for any recursively listed
 *  and compared files throughout the directory hierarchy below the top-level
 *  source, destination.
 **/
static
void
globus_l_url_sync_compare_func_recurse_cb(
    void *                                      arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int         				compare_result,
    globus_object_t *                           error);

/* Declarations */

/**
 * @ingroup globus_i_url_sync
 *
 * Helper function to convert a globus_url_t url into a char* url. At present,
 * this function assumes a maximum URL length as defined by the macro
 * GLOBUS_URL_SYNC_DIR_ENTRY_LENGTH_MAX.
 *
 * @param   url
 *          The URL structure.
 * @param   str
 *          The string buffer to be filled by the function.
 * @param   len
 *          The size of the string buffer.
 *
 * @see GLOBUS_URL_SYNC_DIR_ENTRY_LENGTH_MAX
 */
static
char *
globus_l_url_sync_url2str(
    const globus_url_t *                    url,
    char *                                  str,
    int                                     len);

/**
 * @ingroup globus_l_url_sync
 *
 * An internal implementation of the globus_url_sync operation.
 *
 * @param handle
 *        Handle for the synchronize operation
 * @param source_url
 *        Source URL
 * @param destination_url
 *        Destination URL
 * @param complete_callback
 *        User callback when operation complete
 * @param callback_arg
 *        User argument for callback
 * @retval GLOBUS_SUCCESS
 *         The operation has started successfully.
 */
static
globus_result_t
globus_l_url_sync(
    globus_url_sync_handle_t                handle,
    globus_url_sync_endpoint_t *            source,
    globus_url_sync_endpoint_t *            destination);


static void     globus_l_url_sync_list_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_object_t *                       error);


/* Functions */

globus_result_t
globus_url_sync(
    globus_url_sync_handle_t                handle,
    globus_url_t *                          source_url,
    globus_url_t *                          destination_url,
    globus_url_sync_complete_callback_t     complete_callback,
    globus_url_sync_result_callback_t       result_callback,
    void *                                  callback_arg)
{
    globus_url_sync_endpoint_t *            source;
    globus_url_sync_endpoint_t *            destination;
    globus_ftp_client_handleattr_t *        ftp_attr;
    globus_result_t                         result;
    char                                    source_str[globus_l_url_sync_BUFLEN];
    char                                    destination_str[globus_l_url_sync_BUFLEN];
    GlobusFuncName(globus_url_sync);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(0, "");

    if(handle == GLOBUS_NULL)
    {
	result = globus_error_put(
		GLOBUS_I_URL_SYNC_ERROR_NULL_PARAMETER("handle"));
	goto exit;
    }

    if(source_url == GLOBUS_NULL)
    {
	result = globus_error_put(
		GLOBUS_I_URL_SYNC_ERROR_NULL_PARAMETER("source"));
	goto exit;
    }

    if(destination_url == GLOBUS_NULL)
    {
	result = globus_error_put(
		GLOBUS_I_URL_SYNC_ERROR_NULL_PARAMETER("dest"));
	goto exit;
    }

    if(complete_callback == GLOBUS_NULL)
    {
	result = globus_error_put(
		GLOBUS_I_URL_SYNC_ERROR_NULL_PARAMETER("complete_callback"));
	goto exit;
    }

    if(result_callback == GLOBUS_NULL)
    {
	result = globus_error_put(
		GLOBUS_I_URL_SYNC_ERROR_NULL_PARAMETER("result_callback"));
	goto exit;
    }

    /* Copy URL structs to char* buffers */
	switch(source_url->scheme_type) {
		case GLOBUS_URL_SCHEME_GSIFTP:
		case GLOBUS_URL_SCHEME_SSHFTP:
			globus_l_url_sync_url2str(source_url, source_str, globus_l_url_sync_BUFLEN);
			globus_i_url_sync_log_debug("source: %s\n", source_str);
			break;
		case GLOBUS_URL_SCHEME_FILE:
			globus_l_url_sync_url2str(source_url, source_str, globus_l_url_sync_BUFLEN);
			globus_i_url_sync_log_debug("source: %s ('file' not currrently supported)\n", source_str);
			/* fall through */
		default:
			result = globus_error_put(
				GLOBUS_I_URL_SYNC_ERROR_INVALID_PARAMETER("source scheme"));
			goto exit;
	}
	switch (destination_url->scheme_type) {
		case GLOBUS_URL_SCHEME_GSIFTP:
		case GLOBUS_URL_SCHEME_SSHFTP:
			globus_l_url_sync_url2str(destination_url, destination_str, globus_l_url_sync_BUFLEN);
			globus_i_url_sync_log_debug("destination: %s\n", destination_str);
			break;
		case GLOBUS_URL_SCHEME_FILE:		
			globus_l_url_sync_url2str(destination_url, destination_str, globus_l_url_sync_BUFLEN);
			globus_i_url_sync_log_debug("destination: %s ('file' not currrently supported)\n", destination_str);
			/* fall through */
	default:
			result = globus_error_put(
				GLOBUS_I_URL_SYNC_ERROR_INVALID_PARAMETER("destination scheme"));
			goto exit;
	}

    /* Populate handle with caller's settings */
    globus_i_url_sync_handle_lock(handle);
    {
        if (globus_i_url_sync_handle_is_active(handle))
        {
            globus_i_url_sync_handle_unlock(handle);
            globus_i_url_sync_log_write(GLOBUS_URL_SYNC_LOG_LEVEL_ERROR,
                    "handle (%p) is already in use\n", handle);
            result = globus_error_put(
                    GLOBUS_I_URL_SYNC_ERROR_HANDLE_IN_USE());
	    goto exit;
        }

        if (globus_i_url_sync_handle_activate(handle))
        {
            globus_i_url_sync_handle_unlock(handle);
            globus_i_url_sync_log_write(GLOBUS_URL_SYNC_LOG_LEVEL_ERROR,
                    "handle (%p) could not be activated\n", handle);
            result = globus_error_put(
                    GLOBUS_I_URL_SYNC_ERROR_HANDLE_IN_USE());
	    goto exit;
        }

        ftp_attr = GLOBUS_NULL;

        /* Initialize source endpoint */
        globus_i_url_sync_endpoint_init(&source, source_str,
                (globus_ftp_client_handle_t *)
                globus_libc_malloc(sizeof(globus_ftp_client_handle_t)));
	if (globus_url_sync_handle_get_cache_connections(handle))
	{
		/* CAUSES EVENTUAL MEMORY VIOLATION in < GT5 GridFTP API */
		ftp_attr = 
		  (globus_ftp_client_handleattr_t *)
		  globus_libc_malloc(sizeof(globus_ftp_client_handleattr_t));
		globus_ftp_client_handleattr_init(ftp_attr);
		globus_ftp_client_handleattr_set_cache_all(ftp_attr, GLOBUS_TRUE);
		globus_ftp_client_handle_init(source->ftp_handle, ftp_attr);
		globus_ftp_client_handleattr_destroy(ftp_attr);
	} else {
		globus_ftp_client_handle_init(source->ftp_handle, ftp_attr);
	}

        globus_i_url_sync_handle_set_source(handle, source);

        /* Initialize destination endpoint */
        globus_i_url_sync_endpoint_init(&destination, destination_str,
                (globus_ftp_client_handle_t *)
                globus_libc_malloc(sizeof(globus_ftp_client_handle_t)));
	if (globus_url_sync_handle_get_cache_connections(handle))
	{
		/* CAUSES EVENTUAL MEMORY VIOLATION in < GT5 GridFTP API */
		ftp_attr = 
		  (globus_ftp_client_handleattr_t *)
		  globus_libc_malloc(sizeof(globus_ftp_client_handleattr_t));
		globus_ftp_client_handleattr_init(ftp_attr);
		globus_ftp_client_handleattr_set_cache_all(ftp_attr, GLOBUS_TRUE);
		globus_ftp_client_handle_init(destination->ftp_handle, ftp_attr);
		globus_ftp_client_handleattr_destroy(ftp_attr);
	} else {
		globus_ftp_client_handle_init(destination->ftp_handle, ftp_attr);
	}
        globus_i_url_sync_handle_set_destination(handle, destination);

        /* Initialize callback and arg */
        globus_i_url_sync_handle_set_complete_callback(handle, complete_callback);
        globus_i_url_sync_handle_set_result_callback(handle, result_callback);
        globus_i_url_sync_handle_set_user_arg(handle, callback_arg);
    }
    globus_i_url_sync_handle_unlock(handle);

    /* Call sync implementation */
    result = globus_l_url_sync(handle, source, destination);

    if (result != GLOBUS_SUCCESS)
    {
        globus_i_url_sync_log_error(globus_error_peek(result));
    }

 exit:
    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(0, "");
    return result;
}
/* globus_url_sync */

static
globus_result_t
globus_l_url_sync(
    globus_url_sync_handle_t                handle,
    globus_url_sync_endpoint_t *            source,
    globus_url_sync_endpoint_t *            destination)
{
    globus_result_t                         result;
    globus_url_sync_comparator_t *          comparator;
    GlobusFuncName(globus_l_url_sync);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(0, "");

    /* Get comparator */
    comparator = globus_i_url_sync_handle_get_comparator(handle);

    /* Compare source and destination */
    result = comparator->compare_func(
            comparator->comparator_arg,
            source,
            destination,
            globus_l_url_sync_compare_func_top_cb,
            (void*) handle);

    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(0, "");
    return result;
}
/* globus_l_url_sync */


/** The compare function callback **/
static
void
globus_l_url_sync_compare_func_top_cb(
    void *                                      arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int         								compare_result,
    globus_object_t *                           error)
{
    globus_url_sync_handle_t                    handle;
    globus_url_sync_result_callback_t           result_callback;
    globus_url_sync_complete_callback_t         complete_callback;
    void *                                      callback_arg;
    globus_l_url_sync_arg_t *                   sync_arg;
    GlobusFuncName(globus_l_url_sync_compare_func_top_cb);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(0, "");

    /* Get the callbacks and user argument from the handle */
    globus_assert(arg);
    handle = (globus_url_sync_handle_t) arg;
    globus_i_url_sync_handle_lock(handle);
    {
        result_callback   = globus_i_url_sync_handle_get_result_callback(handle);
        complete_callback = globus_i_url_sync_handle_get_complete_callback(handle);
        callback_arg      = globus_i_url_sync_handle_get_user_arg(handle);
    }
    globus_i_url_sync_handle_unlock(handle);

    /* Return results to user */
    result_callback(callback_arg, handle, error, source, destination, compare_result);

    /* If source and destination are both directories and both exist, then we
     * need to check the synchronization of the contents.
     */
    if (((!compare_result) &&
	 source->stats.type == globus_url_sync_endpoint_type_dir &&
	 destination->stats.type == globus_url_sync_endpoint_type_dir) ||
	(globus_url_sync_handle_get_recursion(handle) &&
	 (!error) &&
	 source->stats.type == globus_url_sync_endpoint_type_dir))
    {
        globus_result_t result;
        globus_i_url_sync_log_debug("Need to perform a directory listing");

        /* Construct sync argument */
        sync_arg = globus_l_url_sync_arg_cons(
                handle,
                source,
                destination,
                GLOBUS_NULL);

        /* List of Source */
        result = globus_i_url_sync_list(
            source->url,
            source->ftp_handle,
            &(sync_arg->entries),
            globus_l_url_sync_list_complete_cb,
            sync_arg);

        if (result != GLOBUS_SUCCESS)
        {
            globus_i_url_sync_log_error(globus_error_peek(result));

            globus_l_url_sync_arg_destroy(sync_arg);

            /* TODO: create error object, with above error as 'cause' */
            complete_callback(callback_arg, handle, GLOBUS_NULL);
        }
    }
    else
    {
        /* done */
        complete_callback(callback_arg, handle, GLOBUS_NULL);

        /* TODO: need to implement a completion function that cleans up
         * resources for this operation and I think should make the handle
         * inactive.
         */
    }
      GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(0, "");
}
/* globus_l_url_sync_compare_func_top_cb */



/*
 * The operation complete callback for the ftp client list operation.
 */
static
void
globus_l_url_sync_list_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_object_t *                       error)
{
    globus_l_url_sync_arg_t *               sync_arg;
    globus_bool_t                           done;
    GlobusFuncName(globus_l_url_sync_list_complete_cb);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(ftp_handle, "");

    sync_arg = (globus_l_url_sync_arg_t*) user_arg;
    globus_assert(sync_arg);

    if (error)
    {
        globus_i_url_sync_log_error(error);
    }

    /* Done if no more listings to be processed */
    done = globus_list_empty(sync_arg->entries);
    
    if (!done)
    {
        /* If there are entries in the listing, they are processed by
         * constructing source and destination pairs and invoking the
         * comparator. */
        globus_result_t                 result;
        globus_url_sync_handle_t        handle;
        globus_url_sync_comparator_t *  comparator;
        char *                          entry;
	char child[GLOBUS_I_URL_SYNC_FILENAME_BUFLEN];

        /* Get handle */
        handle = sync_arg->handle;

        do {
            /* Remove head */
            entry = (char *) globus_list_remove(
                    &(sync_arg->entries), sync_arg->entries);
            globus_assert(entry);

            /* Get comparator */
            comparator = globus_i_url_sync_handle_get_comparator(handle);

            /* Make new endpoints */
            sync_arg->compare_source =
	      globus_l_url_sync_make_src_endpoint(sync_arg->source, entry, child);

            sync_arg->compare_destination =
                    globus_l_url_sync_make_new_endpoint(sync_arg->destination, child);

            /* Compare source and destination */
            result = comparator->compare_func(
                         comparator->comparator_arg,
			 sync_arg->compare_source,
			 sync_arg->compare_destination,
			 globus_l_url_sync_compare_func_recurse_cb,
			 (void*) sync_arg);

            /* If failed, then clean up the compare source and dest */
            if (result != GLOBUS_SUCCESS)
            {
                globus_i_url_sync_log_error(globus_error_peek(result));
                /* TODO: report error to user result_callback */

                globus_i_url_sync_endpoint_destroy(sync_arg->compare_source);
                sync_arg->compare_source = GLOBUS_NULL;
                globus_i_url_sync_endpoint_destroy(sync_arg->compare_destination);
                sync_arg->compare_destination = GLOBUS_NULL;
            }
        } while (result != GLOBUS_SUCCESS && !globus_list_empty(sync_arg->entries));

        /* Done if we've unsuccessfully processed all entries in the list */
        if (result != GLOBUS_SUCCESS)
            done = GLOBUS_TRUE;
    }

    if (done)
    {
        if (sync_arg->parent)
        {
            /* If this callback is for a nested listing, call function using the parent
             * as argument in order to resume processing of the parent directory. */
            globus_l_url_sync_arg_t *           parent;
            parent = sync_arg->parent;

            /* Free endpoints and callback arg */
            globus_assert(sync_arg->source);
            globus_assert(sync_arg->destination);
            globus_i_url_sync_endpoint_destroy(sync_arg->source);
            globus_i_url_sync_endpoint_destroy(sync_arg->destination);
            globus_l_url_sync_arg_destroy(sync_arg);

            /* Call parent callback */
            globus_l_url_sync_list_complete_cb(parent, GLOBUS_NULL, GLOBUS_NULL);
        }
        else
        {
            /* If there is no parent, call the user callback to return execution to the
             * caller. */
            globus_url_sync_handle_t            handle;
            globus_url_sync_complete_callback_t user_callback;
            void *                              user_arg;

            globus_assert(sync_arg->handle);
            handle = sync_arg->handle;

            /* Free callback arg only */
            globus_l_url_sync_arg_destroy(sync_arg);

            /* Get top-level callback */
            globus_i_url_sync_handle_lock(handle);
            {
                user_callback   = globus_i_url_sync_handle_get_complete_callback(handle);
                user_arg        = globus_i_url_sync_handle_get_user_arg(handle);
            }
            globus_i_url_sync_handle_unlock(handle);

            /* Might be better to invoke this from a one-shot */
            user_callback(user_arg, handle, GLOBUS_NULL);
        }
    }
    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(ftp_handle, "");
}
/* globus_l_url_sync_list_complete_cb */


/** The compare function callback **/
static
void
globus_l_url_sync_compare_func_recurse_cb(
    void *                                      arg,
    globus_url_sync_endpoint_t *                source,
    globus_url_sync_endpoint_t *                destination,
    int         								compare_result,
    globus_object_t *                           error)
{
    globus_url_sync_handle_t                    handle;
    globus_url_sync_result_callback_t           result_callback;
    void *                                      callback_arg;
    globus_l_url_sync_arg_t *                   sync_arg;
    GlobusFuncName(globus_l_url_sync_compare_func_recurse_cb);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(0, "");

    /* Get the callbacks and user argument from the handle */
    globus_assert(arg);
    sync_arg = (globus_l_url_sync_arg_t *) arg;
    handle = sync_arg->handle;
    globus_assert(handle);
    globus_i_url_sync_handle_lock(handle);
    {
        result_callback   = globus_i_url_sync_handle_get_result_callback(handle);
        callback_arg      = globus_i_url_sync_handle_get_user_arg(handle);
        /* do_recursive = get_do_recursive(handle) */
    }
    globus_i_url_sync_handle_unlock(handle);

    /* Return results to user */
    result_callback(callback_arg, handle, error, source, destination, compare_result);

    /* If source and destination are both directories and both exist, then we
     * need to check the synchronization of the contents.
     */
    /* TODO: we should ONLY do a recursive listing IF the sync handle has an
     *  option set by the user instructing us to do the listings recursively. */
    if (((!compare_result) &&
	 source->stats.type == globus_url_sync_endpoint_type_dir &&
	 destination->stats.type == globus_url_sync_endpoint_type_dir) ||
	(globus_url_sync_handle_get_recursion(handle) &&
	 (!error) &&
	 source->stats.type == globus_url_sync_endpoint_type_dir))
    {
        globus_l_url_sync_arg_t *           child;
        globus_result_t                     result;
        globus_i_url_sync_log_debug("check directory contents");

        /* Construct sync argument */
        child = globus_l_url_sync_arg_cons(
                handle,
                source,
                destination,
                sync_arg);

        /* List of Source */
        result = globus_i_url_sync_list(
            source->url,
            source->ftp_handle,
            &(child->entries),
            globus_l_url_sync_list_complete_cb,
            child);

        if (result != GLOBUS_SUCCESS)
        {
            globus_i_url_sync_log_error(globus_error_peek(result));
            globus_l_url_sync_arg_destroy(child);
            globus_i_url_sync_endpoint_destroy(sync_arg->compare_source);
            sync_arg->compare_source = GLOBUS_NULL;
            globus_i_url_sync_endpoint_destroy(sync_arg->compare_destination);
            sync_arg->compare_destination = GLOBUS_NULL;
            globus_l_url_sync_list_complete_cb(sync_arg, GLOBUS_NULL, GLOBUS_NULL);
        }
    }
    else
    {
        /* Done. Call the list_complete_cb to continue processing other siblings. */
        globus_i_url_sync_endpoint_destroy(sync_arg->compare_source);
        sync_arg->compare_source = GLOBUS_NULL;
        globus_i_url_sync_endpoint_destroy(sync_arg->compare_destination);
        sync_arg->compare_destination = GLOBUS_NULL;
        globus_l_url_sync_list_complete_cb(sync_arg, GLOBUS_NULL, GLOBUS_NULL);
    }
    GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(0, "");
}
/* globus_l_url_sync_compare_func_recurse_cb */


static
char *
globus_l_url_sync_url2str(
    const globus_url_t *                    url,
    char *                                  buf,
    int                                     len)
{
    int                                     size;
    char *                                  pstr;

    pstr = buf;

    /* Copy scheme and "://" */
    if (url->scheme != NULL) {
        size = strlen(url->scheme)+3;
	if (len <= size)
	    return NULL;
	globus_libc_snprintf(pstr, len, "%s://", url->scheme);
	pstr += size;
	len -= size;
    } else {
        return NULL;
    }
	
    /* Copy Host */
    if (strcmp(url->scheme, "gsiftp") == 0 ||
	strcmp(url->scheme, "sshftp") == 0) {
        if (url->host != NULL) {
	    size = strlen(url->host);
	    if (len <= size)
	        return NULL;
	    strncpy(pstr, url->host, len);
	    pstr += size;
	    len -= size;
	    
	    /* Copy ":" and Port */
	    if (url->port != 0) {
	        size = 7;
		if (len <= size)
		    return NULL;
		globus_libc_snprintf(pstr, len, ":%d", url->port);
		size = strlen(pstr);
		pstr += size;
		len -= size;
	    }
	} else {
	    return NULL;
	}	
    }
	
    /* Copy Path */
    if (url->url_path != NULL) {
        char *prefix = "";
		
	/* If path is relative, start it with "/~". */
	if ((strncmp(url->url_path, "//", 2) != 0) && 
	    (strncmp(url->url_path, "/~", 2) != 0)) {
	    if ((strncmp(url->url_path, "~", 1) == 0)) {
	        prefix = "/";
	    } else if ((strncmp(url->url_path, "/", 1) == 0)) {
	        prefix = "/~";
	    }
	}
	size = strlen(url->url_path) + strlen(prefix);
	if (len <= size)
	    return NULL;
	globus_libc_snprintf(pstr, len, "%s%s", prefix, url->url_path);
	pstr += size;
	len -= size;
    } else {
        return NULL;
    }
	
    return buf;
} /* globus_l_url_sync_url2str */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
