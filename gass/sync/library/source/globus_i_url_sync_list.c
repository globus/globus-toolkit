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
 * @file globus_url_sync_list_op.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_url_sync.h"
#include "globus_i_url_sync.h"
#include "globus_i_url_sync_log.h"
#include "globus_i_url_sync_handle.h"
#include "globus_i_url_sync_list.h"
#include "globus_ftp_client.h"
#include "globus_libc.h"
#include "globus_list.h"
#include "globus_common.h"
#include <stdlib.h>
#include <string.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL


/*
 * Macros
 */

/** Is the buffer CRLF? */
#define globus_l_url_sync_list_is_crlf(buf)     (*(buf)=='\r' && *((buf)+1)=='\n')
/** Is the buffer self (".")? */
#define globus_l_url_sync_list_is_self(buf)     (*(buf)=='.' && *((buf)+1)=='\0')
/** Is the buffer parent ("..")? */
#define globus_l_url_sync_list_is_parent(buf)   (*(buf)=='.' && *((buf)+1)=='.' && *((buf)+2)=='\0')


/*
 * Constants
 */

static const int globus_l_url_sync_list_CRLF_LENGTH     = 2;
static const int globus_l_url_sync_list_BUFLEN          = GLOBUS_URL_SYNC_DIR_ENTRY_LENGTH_MAX + 1;


/*
 * Types
 */

/**
 * @ingroup globus_i_url_sync_list_arg
 *
 * An argument for the read callback when getting a directory listing from an
 * ftp client.
 */
typedef struct
{
    /** FTP client handle */
    globus_ftp_client_handle_t *            ftp_handle;
    /** Base url in char* format */
    char *                                  url;
    /** Working buffer for raw ftp list op */
    globus_byte_t *                         buffer;
    /** Working buffer length */
    globus_size_t                           buffer_length;
    /** Entry buffer for reading dir entries */
    char *                                  entry;
    /** Entry buffer length */
    globus_size_t                           entry_length;
    /** Position in entry buffer */
    int                                     entry_pos;
    /** Address for entries list structure */
    globus_list_t **                        entries;
    /** User callback */
    globus_i_url_sync_list_complete_callback_t
                                            complete_callback;
    /** User callback argument */
    void *                                  callback_arg;
} globus_l_url_sync_list_arg_t;


/*
 * Functions
 */

/**
 * @ingroup globus_i_url_sync_list
 *
 * Allocates and initializes a globus_l_url_sync_list_arg_t structure. It
 * allocates and initializes the buffer and buffer_length. It copies the url
 * parameter.
 *
 * @param   url
 *          The base url in C string format. This parameter is copied.
 * @param   ftp_handle
 *          The FTP client handle.
 * @param   entries
 *          Address to a globus_list_t structure.
 * @param   complete_callback
 *          The complete callback for the list operation.
 * @param   callback_arg
 *          User argument for the callback.
 * @retval  globus_l_url_sync_list_arg_t *
 *          Pointer to newly allocated globus_l_url_sync_list_arg_t structure
 *          or NULL if allocation or initialization failed.
 *
 * @see globus_l_url_sync_list_arg_destroy()
 */
static
globus_l_url_sync_list_arg_t *
globus_l_url_sync_list_arg_cons(
    const char *                            url,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_list_t **                        entries,
    globus_i_url_sync_list_complete_callback_t
                                            complete_callback,
    void *                                  callback_arg);

/**
 * @ingroup globus_i_url_sync_list
 *
 * Frees the globus_l_url_sync_list_arg_t structure and any fields of the
 * structure that were allocated by the constructor.
 *
 * @param   list_arg
 *          The list argument.
 *
 * @see globus_l_url_sync_list_arg_cons()
 */
static
void
globus_l_url_sync_list_arg_destroy(
    globus_l_url_sync_list_arg_t *          list_arg);

/**
 * @ingroup globus_i_url_sync_list
 *
 * Adds a directory entry to the list argument.
 * @param   list_arg
 *          The list argument.
 * @param   entry
 *          The directory entry to add to the list.
 */
static
void
globus_l_url_sync_list_arg_add_entry(
    globus_l_url_sync_list_arg_t *          list_arg,
    const char *                            entry);

/**
 * @ingroup globus_i_url_sync_list
 *
 * GridFTP Client callback for reading bytes returned by the list operation.
 * The implementation will parse the raw bytes returned by the FTP operation
 * and construct a globus_list_t list of char* directory entries. It will skip
 * self (".") and parent ("..") directories. Until eof is flagged, it will
 * re-register the FTP read operation to continue returning the directory
 * listing.
 * @param   user_arg
 *          Expects argument of type globus_l_url_sync_list_arg_t.
 * @param   handle
 *          FTP handle.
 * @param   error
 *          FTP error.
 * @param   buffer
 *          Raw bytes returned by FTP list operation.
 * @param   length
 *          Number of bytes returned by FTP list operation.
 * @param   offset
 *          Not used.
 * @param   eof
 *          Flag to indicate end-of-file reached.
 *
 * @see globus_l_url_sync_list_arg_t
 */
static
void
globus_l_url_sync_list_ftp_read_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_object_t *                       error,
    globus_byte_t *                         buffer,
    globus_size_t                           length,
    globus_off_t                            offset,
    globus_bool_t                           eof);

/**
 * @ingroup globus_i_url_sync_list
 *
 * GridFTP Client operation complete callback. The function frees internal
 * resources used by the list operation helper and calls the user callback.
 *
 * @param   user_arg
 *          The user argument. Must be a globus_l_url_sync_list_arg_t.
 * @param   ftp_handle
 *          The GridFTP client handle used in the list operation.
 * @param   error
 *          An error returned by the list operation of the FTP client.
 *
 * @see globus_l_url_sync_list_arg_t
 */
static
void
globus_l_url_sync_list_ftp_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_object_t *                       error);


/*
 * Implementation
 */


globus_result_t
globus_i_url_sync_list(
    const char *                            url,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_list_t **                        entries,
    globus_i_url_sync_list_complete_callback_t
                                            complete_callback,
    void *                                  callback_arg)
{
    globus_l_url_sync_list_arg_t *          list_arg;
    globus_result_t                         result;
    GlobusFuncName(globus_i_url_sync_list);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER();

    /* This is not a public API, so asserts will be used to check parameters.
     * FTP handle is optional. */
    globus_assert(url);
    globus_assert(entries);
    globus_assert(complete_callback);

    /* Construct list argument */
    list_arg = globus_l_url_sync_list_arg_cons(
            url, ftp_handle, entries, complete_callback, callback_arg);
    globus_assert(list_arg);

    /* FTP List */
    result = globus_ftp_client_list(
        list_arg->ftp_handle,
        list_arg->url,
        GLOBUS_NULL,
        globus_l_url_sync_list_ftp_complete_cb,
        list_arg);

    if (result == GLOBUS_SUCCESS)
    {
        /* Register read operation */
        result = globus_ftp_client_register_read(
                list_arg->ftp_handle,
                list_arg->buffer,
                list_arg->buffer_length,
                globus_l_url_sync_list_ftp_read_cb,
                list_arg);

        /* Report error and abort, if failed */
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_url_sync_log_error(globus_error_peek(result));
            globus_ftp_client_abort(list_arg->ftp_handle);
        }
    }
    else
    {
        globus_l_url_sync_list_arg_destroy(list_arg);
        globus_i_url_sync_log_error(globus_error_peek(result));
    }

    /* Completed */
    globus_i_url_sync_log_debug(
            "globus_url_sync completed (result: %d)\n", result);
    return result;
}
/* globus_i_url_sync_list */


/*
 * The data callback for the ftp list operation.
 */
static
void
globus_l_url_sync_list_ftp_read_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_object_t *                       error,
    globus_byte_t *                         buffer,
    globus_size_t                           length,
    globus_off_t                            offset,
    globus_bool_t                           eof)
{
    globus_l_url_sync_list_arg_t *          list_arg;
    globus_result_t                         result;
    int                                     buffer_pos;
    GlobusFuncName(globus_l_url_sync_list_ftp_read_cb);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER();
    globus_i_url_sync_log_debug("%d bytes read\n", length);

    if (error)
    {
        globus_i_url_sync_log_error(error);
        return;
    }

    list_arg = (globus_l_url_sync_list_arg_t*) user_arg;
    globus_assert(list_arg);

    /* Copy entries to buffer and add them to the list of entries */
    buffer_pos = 0;
    while (buffer_pos <= length)
    {
        /* At CRLF, add dir_entry (if any) and skip CRLF chars */
        if(globus_l_url_sync_list_is_crlf(buffer+buffer_pos))
        {
            if (list_arg->entry_pos)
            {
                /* Terminate current entry position and reset */
                list_arg->entry[list_arg->entry_pos] = '\0';
                list_arg->entry_pos = 0;
                globus_l_url_sync_list_arg_add_entry(list_arg, list_arg->entry);
            }
            buffer_pos += globus_l_url_sync_list_CRLF_LENGTH;
        }
        else
        {
            list_arg->entry[(list_arg->entry_pos)++] = buffer[buffer_pos++];
        }
    }
    list_arg->entry_pos--; /* rewind last increment */

    /* Check for EOF */
    if (eof)
    {
        globus_i_url_sync_log_debug("end of file (EOF) reached\n");
        return;
    }

    /* Register read operation */
    result = globus_ftp_client_register_read(ftp_handle, buffer, length,
            globus_l_url_sync_list_ftp_read_cb, user_arg);

    /* Report error and abort, if failed */
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_url_sync_log_error(globus_error_get(result));
        globus_ftp_client_abort(ftp_handle);
    }
}
/* globus_l_url_sync_ftp_list_read_cb */


/*
 * The operation complete callback for the ftp client list operation.
 */
static
void
globus_l_url_sync_list_ftp_complete_cb(
    void *                                  user_arg,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_object_t *                       error)
{
    globus_l_url_sync_list_arg_t *          list_arg;
    GlobusFuncName(globus_l_url_sync_list_ftp_complete_cb);
    GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER();

    if (error)
    {
        globus_i_url_sync_log_error(error);
    }

    list_arg = (globus_l_url_sync_list_arg_t*) user_arg;
    globus_assert(list_arg);
    list_arg->complete_callback(list_arg->callback_arg, ftp_handle, error);

    /* Cleanup */
    globus_l_url_sync_list_arg_destroy(list_arg);
}
/* globus_l_url_sync_list_ftp_complete_cb */


static
globus_l_url_sync_list_arg_t *
globus_l_url_sync_list_arg_cons(
    const char *                            url,
    globus_ftp_client_handle_t *            ftp_handle,
    globus_list_t **                        entries,
    globus_i_url_sync_list_complete_callback_t
                                            complete_callback,
    void *                                  callback_arg)
{
    globus_l_url_sync_list_arg_t *          list_arg;

    list_arg = globus_libc_malloc(sizeof(globus_l_url_sync_list_arg_t));
    if (list_arg == NULL)
        return NULL;

    list_arg->ftp_handle        = ftp_handle;
    list_arg->complete_callback = complete_callback;
    list_arg->callback_arg      = callback_arg;

    /* Initialize entries */
    globus_assert(entries);
    *entries            = NULL;     /* NULL = empty globus_list_t list */
    list_arg->entries   = entries;

    /* Copy url */
    list_arg->url = globus_libc_strdup(url);
    globus_assert(list_arg->url);

    /* Allocate buffer */
    list_arg->buffer = (globus_byte_t*) globus_libc_malloc(
            sizeof(globus_byte_t) * globus_l_url_sync_list_BUFLEN);
    globus_assert(list_arg->buffer);
    list_arg->buffer_length = globus_l_url_sync_list_BUFLEN;

    /* Allocate entry */
    list_arg->entry = (char*) globus_libc_malloc(
            sizeof(char) * (globus_l_url_sync_list_BUFLEN+1));
    globus_assert(list_arg->entry);
    list_arg->entry_length = globus_l_url_sync_list_BUFLEN+1;
    list_arg->entry_pos = 0;

    return list_arg;
}
/* globus_l_url_sync_list_arg_cons */


static
void
globus_l_url_sync_list_arg_destroy(
    globus_l_url_sync_list_arg_t *          list_arg)
{
    globus_assert(list_arg);

    list_arg->ftp_handle        = NULL;
    list_arg->entries           = NULL;
    list_arg->complete_callback = NULL;
    list_arg->callback_arg      = NULL;

    if (list_arg->url)
    {
        globus_libc_free(list_arg->url);
        list_arg->url  = NULL;
    }

    if (list_arg->buffer)
    {
        globus_libc_free(list_arg->buffer);
        list_arg->buffer = NULL;
    }
    list_arg->buffer_length = 0;

    if (list_arg->entry)
    {
        globus_libc_free(list_arg->entry);
        list_arg->entry = NULL;
    }
    list_arg->entry_length = 0;
    list_arg->entry_pos = 0;

    globus_libc_free(list_arg);
}
/* globus_l_url_sync_list_arg_destroy */


static
void
globus_l_url_sync_list_arg_add_entry(
    globus_l_url_sync_list_arg_t *          list_arg,
    const char *                            entry)
{
    char *                                  new_entry;
    globus_assert(entry);
    globus_i_url_sync_log_debug("dir entry: %s\n", entry);

    /* Skip if self or parent entry */
    if (globus_l_url_sync_list_is_self(entry) || globus_l_url_sync_list_is_parent(entry))
        return;

    /* Make copy */
    new_entry = globus_libc_strdup(entry);
    globus_assert(new_entry);

    /* Add entry to list */
    *(list_arg->entries) = globus_list_cons(new_entry, *(list_arg->entries));
    globus_assert(*(list_arg->entries));
}
/* globus_l_url_sync_list_arg_add_entry */


void
globus_i_url_sync_list_free_entries(
    globus_list_t *                     entries)
{
    if (entries)
    {
        globus_list_destroy_all(entries, globus_libc_free);
    }
}
/* globus_i_url_sync_list_free_entries */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
