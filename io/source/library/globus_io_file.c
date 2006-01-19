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
 * @file globus_io_file.c Implementation of the file I/O interface.
 *
 * $Source$
 * $Date$
 * $Revision$
 * $State$
 * $Author$
 */
#endif

/*
 * Include header files
 */
#include "globus_l_io.h"

/*
 * Define module specific constants
 */
/* one of the things noone likes about UNIX */
#if defined(EACCES) && !defined(EACCESS)
#   define EACCESS EACCES
#endif

/**
 * Initialize a Globus I/O handle by opening a file.
 *
 * Open the file named by path, and return a file handle in the structure
 * pointed to by handle. The flags and mode arguments are the same as the
 * standard POSIX open() function. The attr argument contains other
 * handle attributes to be associated with the handle or GLOBUS_NULL to
 * indicate default attributes. This is a blocking operation.
 * NOTE: Windows does not support all of the available POSIX options, it
 * supports only the following options:
 * O_RDONLY
 * O_WRONLY
 * O_RDWR
 * O_APPEND
 * O_CREAT
 * O_TRUNC
 * O_EXCL
 * 
 *
 * @param path The path to the file to open.
 * @param flags The flags argument consists of a bitwise-or of the
 * values defined by the globus_io_file_flag_t.
 * @param mode The permissions of the file; it consists of a bitwise-or
 *  of the values defined by the globus_io_file_create_mode_t. 
 * This variable is unused by globus_io_open if the file is opened with the
 * GLOBUS_IO_FILE_CREAT flag.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing to an
 * object of one of the the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle was equal to GLOBUS_NULL, so the registration could not
 * be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The open called failed with an unexpected error. The errno returned
 * by open() is accessible from the error object.
 * @ingroup file
 */
globus_result_t
globus_io_file_open( 
    char *				path, 
    int					flags, 
    int					mode, 
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    int                                 fd;
    globus_result_t			rc;

    char *				myname = "globus_io_file_open";
    
    globus_i_io_debug_printf(3, (stderr, "%s(): entering\n", myname));

    rc = GLOBUS_SUCCESS;

    
    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        "handle",
	        5,
	        myname));
    }
    
    rc = globus_i_io_initialize_handle(handle,
                                       GLOBUS_IO_HANDLE_TYPE_FILE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    globus_i_io_copy_fileattr_to_handle(attr,
					handle);

    /*
     * NETLOGGER
     */
    handle->nl_handle = GLOBUS_NULL;
    handle->nl_event_id = GLOBUS_NULL;
    if(attr != GLOBUS_NULL)
    {
        handle->nl_handle = attr->nl_handle;
    }

#   if defined(TARGET_ARCH_CYGWIN)
    {
	if(handle->file_attr.file_type == GLOBUS_IO_FILE_TYPE_TEXT)
	{
	    flags |= O_TEXT;
	}
	else
	{
	    flags |= O_BINARY;
	}
    }
#   endif
    globus_i_io_mutex_lock();
    {
#ifndef TARGET_ARCH_WIN32
	do
	{
	    fd = open(path, flags | O_NDELAY, mode);
	}
	while (fd < 0 && errno == EINTR);

	if (fd < 0)
	{
	    rc =
		globus_error_put(
		    globus_io_error_construct_system_failure(
			GLOBUS_IO_MODULE,
			GLOBUS_NULL,
			handle,
			errno));
	    handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
	}
        else
	{
            while ((flags = fcntl(fd, F_SETFD, FD_CLOEXEC)) < 0)
            {
                int save_errno = errno;
                if(save_errno != EINTR)
                {
                    rc = globus_error_put(
                            globus_io_error_construct_system_failure(
                                GLOBUS_IO_MODULE,
                                GLOBUS_NULL,
                                handle,
                                errno));
                    handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
                    close(fd);
                    goto error_exit;

                }
            }

	    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
	}
	handle->fd = fd;
#else
	if ( globus_i_io_windows_file_open( handle, path, flags, NULL ) )
	{
		rc = globus_error_put(
				globus_io_error_construct_system_failure(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle,
				errno));
		handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
	}
	else
	{
		handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
		// initialize the WinIoOperation structs
		globus_i_io_windows_init_io_operations( handle );
		/* associate the new file with the completion port */
		if ( CreateIoCompletionPort( handle->io_handle,
			completionPort, (ULONG_PTR)handle, 0 ) == NULL )
		{
			rc= globus_error_put(
					globus_io_error_construct_system_failure(
					GLOBUS_IO_MODULE,
					GLOBUS_NULL,
					handle,
					globus_i_io_windows_get_last_error() ) );
		
			globus_i_io_windows_close( handle );
		}
	}
#endif /* TARGET_ARCH_WIN32 */
    }
error_exit:
    globus_i_io_mutex_unlock();

    globus_i_io_debug_printf(3, (stderr, "%s(): exiting\n", myname));

    return(rc);
}
/* globus_io_file_open() */


/**
 * Seek to a new position on an open file. 
 *
 * @param handle The handle to perform the seek upon.
 * @param offset The new position of the file, relative to the
 * whence parameter.
 * @param whence The whence parameter determines how to interpret the
 * offset.
 *
 * @return
 * This function returns GLOBUS_SUCCESS or a result pointing to an
 * object of one of the the following error types:
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle was equal to GLOBUS_NULL, so the registration could not
 * be processed.
 * @retval GLOBUS_IO_ERROR_TYPE_INVALID_TYPE
 * The type of handle passed to the function by the handle parameter
 * is not one of the types which supports the seek operation.
 * @retval GLOBUS_IO_ERROR_TYPE_SYSTEM_FAILURE
 * The open called failed with an unexpected error. The errno returned
 * by open() is accessible from the error object.
 * @ingroup file
 */
globus_result_t
globus_io_file_seek(
    globus_io_handle_t *		handle,
    globus_io_off_t			offset,
    globus_io_whence_t			whence)
{
    globus_io_off_t			rc;
    static char *                       myname=
	                                "globus_io_file_seek";
    globus_object_t *			err;
#ifdef TARGET_ARCH_WIN32
	LARGE_INTEGER numberOfBytes;
#endif
    
    if(handle == GLOBUS_NULL)
    {
        return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"handle",
		1,
		myname));
    }
    
    if(handle->type != GLOBUS_IO_HANDLE_TYPE_FILE)
    {
	err = globus_io_error_construct_invalid_type(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname,
	    "GLOBUS_IO_HANDLE_TYPE_FILE");

	goto error_exit;
    }

#ifndef TARGET_ARCH_WIN32
    rc = lseek(handle->fd,
	       offset,
	       whence);
    if (rc != -1)
#else
	numberOfBytes.QuadPart= offset;
	rc= globus_i_io_windows_seek( handle, numberOfBytes, whence, NULL );
    if ( rc == 0 )
#endif
    {
	return GLOBUS_SUCCESS;
    }
    else
    {
	globus_result_t result;

	result =
	    globus_error_put(
		globus_io_error_construct_system_failure(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    handle,
		    errno));
	return result;
    }

  error_exit:
    return globus_error_put(err);
}

/**
 * Convert a POSIX-style file descriptor to a Globus I/O handle.
 * @param fd The file descriptor to be used with Globus I/O. The
 * descriptor should not be used once this function
 * returns. 
 * @param attributes The attributes which will be applied to the socket when
 * possible. 
 * @param handle The new handle which can be used to refer to this
 * file.  All subsequent I/O on this file should be done using the
 * Globus I/O interface with this handle.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle was equal to GLOBUS_NULL.
 * @ingroup file
 */
#ifndef TARGET_ARCH_WIN32
globus_result_t
globus_io_file_posix_convert(
    int					fd,
    globus_io_attr_t *			attr,
    globus_io_handle_t *		handle)
{
    globus_result_t rc;
    static char *                       myname=
	                                "globus_io_file_posix_convert";

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"handle",
		6,
		myname));
    }
    rc = globus_i_io_initialize_handle(handle,
                                       GLOBUS_IO_HANDLE_TYPE_FILE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
     
    handle->fd = fd;
    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
    globus_i_io_copy_fileattr_to_handle(attr,
					handle);

#   if defined(TARGET_ARCH_CYGWIN)
    {
	if(handle->file_attr.file_type == GLOBUS_IO_FILE_TYPE_TEXT)
	{
	    setmode(handle->fd,
		    O_TEXT);
	}
	else
	{
	    setmode(handle->fd,
		    O_BINARY);
	}
    }
#   endif
    return GLOBUS_SUCCESS;
}
#endif /* TARGET_ARCH_WIN32 */

/**
 * @name File Attributes
 */
/* @{ */
/**
 * Initialize a file attribute structure.
 *
 * @param attr Attribute to initialize. 
 *
 * <b>Default File Attributes:</b>
 * @code
 * file_type: GLOBUS_IO_FILE_TYPE_BINARY
 * @endcode
 * 
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The attr was GLOBUS_NULL.
 *
 * @see globus_io_fileattr_destroy()
 * @ingroup attr
 */
globus_result_t
globus_io_fileattr_init(
    globus_io_attr_t * attr)
{
     static char *                       myname = "globus_io_fileattr_init";
     
     if(attr == GLOBUS_NULL)
     {
	 return globus_error_put(
	     globus_io_error_construct_null_parameter(
		 GLOBUS_IO_MODULE,
		 GLOBUS_NULL,
		 "attr",
		 1,
		 myname));
     }
	 
    attr->attr = globus_i_io_fileattr_construct();

    /*
     *  NETLOGGER
     */
    attr->nl_handle = GLOBUS_NULL;
    
    return GLOBUS_SUCCESS;
}

/* globus_io_fileattr_init() */

/**
 * Destroy a previously allocated file attribute structure.
 *
 * All memory allocated upon creation of the attribute structure is
 * freed. The attribute is no longer usable in any Globus I/O file
 * open calls.
 *
 * @param attr The attribute structure to destroy.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The attr parameter was equal to GLOBUS_NULL.
 *
 * @see globus_io_fileattr_init()
 * @ingroup attr
 */
globus_result_t
globus_io_fileattr_destroy(
    globus_io_attr_t * attr)
{
    static char *			myname = "globus_io_fileattr_destroy";

    if(attr == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"attr",
		1,
		myname));
    }
    
    globus_object_free(attr->attr);
    attr->attr = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}
/* globus_io_fileattr_destroy() */
/* @} */
