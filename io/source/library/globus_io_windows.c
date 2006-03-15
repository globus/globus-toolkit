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

/**
 * @file globus_io_windows.c Globus I/O toolset
 *
 *   This file is a stop-gap measure to supply Windows functionality
 *   for the Globus I/O library. 
 *
 * $Source: 
 * $Date: 
 * $Revision: 
 * $State: 
 * $Author: Michael Lebman
 */

#include "globus_l_io.h"

// globals

HANDLE completionPort;

/* globus_i_io_windows_init_io_operation()
*
*	This function will initialize certain members of a
*	WinIoOperation struct.
*/
void globus_i_io_windows_init_io_operations( 
	globus_io_handle_t * handle )
{
	globus_l_io_windows_init_io_operation( 
	 &(handle->winIoOperation_read) );
	globus_l_io_windows_init_io_operation( 
	 &(handle->winIoOperation_write) );
	globus_l_io_windows_init_io_operation( 
	 &(handle->winIoOperation_structure) );
}

void globus_l_io_windows_init_io_operation( 
	WinIoOperation * winIoOperation )
{
	winIoOperation->overlapped.Internal=
	winIoOperation->overlapped.InternalHigh=
	winIoOperation->overlapped.Offset=
	winIoOperation->overlapped.OffsetHigh= 0;
	winIoOperation->overlapped.hEvent= 0;
	winIoOperation->state= WinIoUnknown;
	winIoOperation->flags= 0;
	winIoOperation->acceptedSocket= INVALID_SOCKET;
	winIoOperation->addressInfo= NULL;
}

/* globus_i_io_windows_read()
*
*	This function will attempt to read up to the specified number of 
*	bytes. It assumes that the handle represents either a non-blocking 
*	socket or a file handle. The last parameter controls whether it 
*	uses any asynchronous Windows mechanisms. If called synchronously 
*	and the underlying system call would block, this function causes 
*	errno to be set and then returns without reading any data. If called
*	asynchronously, the result *MUST* be obtained by calling
*	GetQueuedCompletionStatus(). In either case, if an error 
*	occurs it returns -1 and sets errno to an appropriate value.
*/

int globus_i_io_windows_read( 
	globus_io_handle_t * handle,
	globus_byte_t * buf,
	globus_size_t max_nbytes,
	int asynchronous )
{
	if ( handle->type != GLOBUS_IO_HANDLE_TYPE_FILE && 
		handle->type != GLOBUS_IO_HANDLE_TYPE_INTERNAL )
	/* must be a socket */
		return globus_i_io_winsock_read( handle, buf, max_nbytes, 
		 asynchronous );
	else
		return globus_i_io_windows_file_read( handle, buf, max_nbytes, 
		 asynchronous );
} /* globus_i_io_windows_read() */

/* globus_i_io_windows_file_read()
*
*	This function will attempt to read up to the specified number of bytes
*	using the ReadFile() Win32 API call. If it succeeds it returns zero,
*	indicating that the read operation is pending; the result of the
*	read operation must be obtained using GetQueuedCompletionStatus(). If
*	an error occurs it returns -1 and sets errno to an appropriate value.
*	NOTE: Because of the way the Windows API distinguishes between files 
*	that can perform asynchronous I/O and those that cannot, this function 
*	can perform *ONLY* asynchronous operations. If the asynchronous flag is 
*	false (set to zero) this function returns -1 and sets errno to
*	EWOULDBLOCK.
*/
int globus_i_io_windows_file_read( globus_io_handle_t * handle, 
 char * buffer, int maxNumberOfBytesToRead, int asynchronous )
{
	int rc;
	LARGE_INTEGER currentFilePosition;

	if ( !asynchronous )
	{
		errno= EWOULDBLOCK;
		return -1;
	}

	// set the I/O operation state
	handle->winIoOperation_read.state= WinIoReading;
	handle->winIoOperation_read.operationAttempted= 1;

	// get the current file position
	if ( globus_i_io_windows_get_file_pointer( handle, 
	 &currentFilePosition ) )
		return -1;

	// reset the overlapped struct to point to the current file position
	handle->winIoOperation_read.overlapped.Offset= 
	 currentFilePosition.LowPart;
	handle->winIoOperation_read.overlapped.OffsetHigh= 
	 currentFilePosition.HighPart;

	rc= ReadFile( handle->io_handle, buffer, maxNumberOfBytesToRead,
			NULL, &(handle->winIoOperation_read.overlapped) );

	// TESTING!!!
	//fprintf( stderr, "Asynchronous file read: %d bytes requested...", maxNumberOfBytesToRead );
	// END TESTING

	if ( rc == 0 )
	{
		int error;
		error= globus_i_io_windows_get_last_error();
		if ( error != ERROR_IO_PENDING )
		{
			// TESTING!!!
			//fprintf( stderr, "globus_i_io_windows_file_read: error occurred (Windows error is %d)\n", error );
			// END TESTING
			return -1;
		}
	}
	// TESTING!!!
	//fprintf( stderr, "pending\n" );
	// END TESTING

	return 0; // in order to match the success code for WSARecv
} /* globus_i_io_windows_file_read() */

/* globus_i_io_windows_write()
*
*	This function will attempt to write the specified number of bytes.
*	It assumes that the handle represents either a non-blocking socket
*	or a file handle. The last parameter controls whether it uses any
*	asynchronous Windows mechanisms. If called synchronously and the
*	underlying system call would block, this function causes errno 
*	to be set and then returns without writing any data. If called
*	asynchronously, the result *MUST* be obtained by calling
*	GetQueuedCompletionStatus(). In either case, if an error 
*	occurs it returns -1 and sets errno to an appropriate value.
*/

int globus_i_io_windows_write( 
	globus_io_handle_t * handle,
	globus_byte_t * buf,
	globus_size_t max_nbytes,
	int asynchronous,
	int flags )
{
	if ( handle->type != GLOBUS_IO_HANDLE_TYPE_FILE && 
		handle->type != GLOBUS_IO_HANDLE_TYPE_INTERNAL )
	/* must be a socket */
		return globus_i_io_winsock_write( handle, buf, max_nbytes,
		 asynchronous, flags );
	else
		return globus_i_io_windows_file_write( handle, buf, max_nbytes, 
		 asynchronous );
}

/* globus_i_io_windows_file_write()
*
*	This function will attempt to write the specified number of bytes
*	using the WriteFile() Win32 API call. If it succeeds it returns zero,
*	indicating that the write operation is pending; the result of the
*	write operation must be obtained using GetQueuedCompletionStatus(). If
*	an error occurs it returns -1 and sets errno to an appropriate value.
*	NOTE: Because of the way the Windows API distinguishes between files 
*	that can perform asynchronous I/O and those that cannot, this function 
*	can perform *ONLY* asynchronous operations. If the asynchronous flag is 
*	false (set to zero) this function returns -1 and sets errno to
*	EWOULDBLOCK.
*/
int globus_i_io_windows_file_write( globus_io_handle_t * handle, 
 char * buffer, int numberOfBytesToWrite, int asynchronous )
{
	int rc;
	LARGE_INTEGER currentFilePosition;

	if ( !asynchronous )
	{
		errno= EWOULDBLOCK;
		return -1;
	}

	// set the I/O operation state
	handle->winIoOperation_write.state= WinIoWriting;
	handle->winIoOperation_write.operationAttempted= 1;

	// get the current file position
	if ( globus_i_io_windows_get_file_pointer( handle, 
	 &currentFilePosition ) )
		return -1;

	// reset the overlapped struct to point to the current file position
	handle->winIoOperation_write.overlapped.Offset= 
	 currentFilePosition.LowPart;
	handle->winIoOperation_write.overlapped.OffsetHigh= 
	 currentFilePosition.HighPart;

	rc= WriteFile( handle->io_handle, buffer, numberOfBytesToWrite,
			NULL, &(handle->winIoOperation_write.overlapped) );

	// TESTING!!!
	//fprintf( stderr, "Asynchronous file write: %d bytes requested...", numberOfBytesToWrite );
	// END TESTING

	if ( rc == 0 )
	{
		int error;
		error= globus_i_io_windows_get_last_error();
		if ( error != ERROR_IO_PENDING )
		{
			// TESTING!!!
			//fprintf( stderr, "error occurred (Windows error is %d)\n", error );
			// END TESTING
			return -1;
		}
	}
	// TESTING!!!
	//fprintf( stderr, "pending\n" );
	// END TESTING

	return 0; // in order to match the success code for WSASend
} /* globus_i_io_windows_file_write() */

/* globus_i_io_windows_post_completion()
*
*	This function will post a completion packet to the I/O completion
*	port. If the call is successful, it returns 0; otherwise, it returns
*	the error code returned by GetLastError(). The primary purpose of
*	this function is to provide a mechanism for triggering the call to
*	the callback function (typically a read or write) for a handle.
*/
int globus_i_io_windows_post_completion( globus_io_handle_t * handle, 
 char state )
{
	int rc;
	WinIoOperation * operation;

	switch( state )
	{
		case WinIoReading:
			operation= &(handle->winIoOperation_read);
			break;
		case WinIoWriting:
			operation= &(handle->winIoOperation_write);
			break;
		default: // assume a setup/tear down operation
			operation= &(handle->winIoOperation_structure);
	}

	operation->state= state;
	operation->operationAttempted= 0;
	rc= PostQueuedCompletionStatus( completionPort, 0, handle, 
	 &(operation->overlapped) );

	if ( rc == 0 ) // a serious error occurred
		return globus_i_io_windows_get_last_error();

	return 0;
} /* globus_i_io_windows_post_completion() */

/**
 * Convert a connected Windows socket to a Globus I/O handle.
 *
 * @param socket The socket to be used with Globus I/O. The
 * socket should not be used once this function
 * returns. 
 * @param attributes The attributes which will be applied to the socket when
 * possible. Not all attributes can be applied to a socket after it has been
 * connected.
 * @param handle The new handle which can be used to refer to this socket
 * connection. All subsequent I/O on this socket should be done using
 * the Globus I/O interface with this handle.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle was equal to GLOBUS_NULL.
 *
 * @bug The "attributes" parameter is currently ignored.
 * @ingroup tcp
 */
globus_result_t globus_io_tcp_windows_convert(
    SOCKET						socket,
    globus_io_attr_t *			attributes,
    globus_io_handle_t *		handle)
{
    static char *			myname="globus_io_tcp_windows_convert";

    if(handle == GLOBUS_NULL)
    {
		return globus_error_put(
			globus_io_error_construct_null_parameter(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				"handle",
				3,
				myname));
    }
    globus_i_io_initialize_handle(handle,
                                  GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED);
    handle->io_handle = (HANDLE)socket;
    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;

	/* initialize the WinIoOperation structs */
	globus_i_io_windows_init_io_operations( handle );
	/* associate the socket with the completion port */
	if ( CreateIoCompletionPort( handle->io_handle,
		completionPort, (ULONG_PTR)handle, 0 ) == NULL )
	{
		return globus_error_put(
			globus_io_error_construct_system_failure(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle,
				globus_i_io_windows_get_last_error() ) );
	}

    return GLOBUS_SUCCESS;
}
/* globus_io_tcp_windows_convert() */

/**
 * Convert a listening Windows socket to a Globus I/O handle.
 *
 * @param socket
 *        The listening socket to be used with Globus I/O. The
 *        socket should not be used once this function
 *        returns. 
 * @param attributes
 *        The attributes which will be applied to the socket when possible. Not
 *        all attributes can be applied to a socket after it has been
 *        connected.
 * @param handle
 *        The new handle which can be used to refer to this socket listener.
 *        All subsequent I/O on this socket should be done using the Globus I/O
 *        interface with this handle.
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle was equal to GLOBUS_NULL.
 *
 * @bug The "attributes" parameter is currently ignored.
 * @ingroup tcp
 */
globus_result_t globus_io_tcp_windows_convert_listener(
    SOCKET						socket,
    globus_io_attr_t *			attributes,
    globus_io_handle_t *		handle)
{
    static char *			myname="globus_io_tcp_windows_convert_listener";

    if(handle == GLOBUS_NULL)
    {
		return globus_error_put(
			globus_io_error_construct_null_parameter(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				"handle",
				3,
				myname));
    }
    globus_i_io_initialize_handle(handle,
                                  GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED);
    handle->io_handle = (HANDLE)socket;
    handle->state = GLOBUS_IO_HANDLE_STATE_LISTENING;

	/* initialize the WinIoOperation structs */
	globus_i_io_windows_init_io_operations( handle );
	/* associate the socket with the completion port */
	if ( CreateIoCompletionPort( handle->io_handle,
		completionPort, (ULONG_PTR)handle, 0 ) == NULL )
	{
		return globus_error_put(
			globus_io_error_construct_system_failure(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle,
				globus_i_io_windows_get_last_error() ) );
	}

    return GLOBUS_SUCCESS;
}
/* globus_io_tcp_windows_convert_listener() */

/* globus_i_io_windows_file_open()
 *
 *	Opens a file using the following flags:
 *	 O_RDONLY
 *	 O_WRONLY
 *	O_RDWR
 *	O_APPEND
 *	O_CREAT
 *	O_TRUNC
 *	O_EXCL
 *
 *	If this function succeeds, it sets the io_handle member of the handle
 *	this is passed in and returns zero. If an error occurs it returns the
 *	Windows error code and sets errno to an appropriate POSIX error code.
 */
int globus_i_io_windows_file_open( globus_io_handle_t * handle, 
	char * filename, DWORD creationFlags, 
	SECURITY_ATTRIBUTES * securityAttributes )
{
	DWORD accessMode;
	DWORD creationCondition;
	DWORD flags;

	// transpose the POSIX-style flags to Win32 constants
	
	accessMode= 0;
	// NOTE: The value of O_RDONLY is zero, so we cannot use a bit OR to
	// check for this flag
	if ( creationFlags & O_RDWR )
		accessMode= GENERIC_READ | GENERIC_WRITE;
	else if ( creationFlags & O_WRONLY )
		accessMode= GENERIC_WRITE;
	else // presume O_RDONLY
		accessMode= GENERIC_READ;

/*
	The following table maps the POSIX file creation/open flags to the
	constants used by the Win32 CreateFile() function:

	Windows Constants	POSIX Constants
						Does the file exist yet?
							No		Yes
	CREATE_NEW			O_CREAT | O_EXCL
	CREATE_ALWAYS		O_CREAT | O_TRUNC
	OPEN_EXISTING				  O_APPEND
	OPEN_ALWAYS			O_CREAT | O_APPEND
	TRUNCATE_EXISTING			  O_TRUNC

*/
	creationCondition= 0;

	if ( creationFlags & O_CREAT ) // possibly create a new file
	{
		if ( creationFlags & O_EXCL )
			creationCondition= CREATE_NEW;
		else if ( creationFlags & O_TRUNC )
			creationCondition= CREATE_ALWAYS;
		else // assume ( creationFlags & O_APPEND )
			creationCondition= OPEN_ALWAYS;
	}
	else // open an existing file only
	{
		if ( creationFlags & O_TRUNC )
			creationCondition= TRUNCATE_EXISTING;
		else // assume ( creationFlags & O_APPEND )
			creationCondition= OPEN_EXISTING;
	}

	flags= FILE_FLAG_OVERLAPPED;

	handle->io_handle= CreateFile( filename, accessMode, 0, 
		securityAttributes, creationCondition, flags, NULL );

	if ( handle->io_handle == INVALID_HANDLE_VALUE )
		return globus_i_io_windows_get_last_error();

	return 0;
} /* globus_i_io_windows_file_open() */

/* globus_i_io_windows_get_file_pointer()
 *	Retrieves the file pointer as a 64-bit value. The pointer is returned
 *	by using "currentPosition" as an out parameter. If this function 
 *	succeeds, it returns zero; otherwise, it sets errno to an appropriate 
 *	POSIX error code and returns the Windows error number.
 */
int globus_i_io_windows_get_file_pointer( globus_io_handle_t * handle,
	LARGE_INTEGER * currentPosition )
{
	LARGE_INTEGER distance;
	distance.QuadPart= 0;
	return globus_i_io_windows_move_file_pointer( handle, distance, 
	 currentPosition );
} /* globus_i_io_windows_get_file_pointer() */

/* globus_i_io_windows_move_file_pointer()
 *	Moves the file pointer using 64-bit values. It also returns the new
 *	file pointer position using "newPosition" as an out parameter. If the
 *	new position is not desired, the value of this parameter may be set
 *	to NULL. If this function succeeds, it returns zero; otherwise, it sets 
 *	errno to an appropriate POSIX error code and returns the Windows 
 *	error number.
 */
int globus_i_io_windows_move_file_pointer( globus_io_handle_t * handle,
	LARGE_INTEGER numberOfBytes, LARGE_INTEGER * newPosition )
{
/*
	int rc;

	rc= SetFilePointerEx( handle->io_handle, numberOfBytes, newPosition, 
	 FILE_CURRENT );
	if ( rc == 0 )
		return globus_i_io_windows_get_last_error();

	return 0;
*/

	return globus_i_io_windows_seek( handle, numberOfBytes, FILE_CURRENT,
		newPosition );
} /* globus_i_io_windows_move_file_pointer() */


/* globus_i_io_windows_seek()
 *	Moves the file pointer using 64-bit values. It also returns the new
 *	file pointer position using "newPosition" as an out parameter. If the
 *	new position is not desired, the value of this parameter may be set
 *	to NULL. If this function succeeds, it returns zero; otherwise, it sets 
 *	errno to an appropriate POSIX error code and returns the Windows 
 *	error number.
 */

int globus_i_io_windows_seek( globus_io_handle_t * handle,
	LARGE_INTEGER numberOfBytes, DWORD startingPoint,
	LARGE_INTEGER * newPosition )
{
	int rc;

	rc= SetFilePointerEx( handle->io_handle, numberOfBytes, newPosition, 
	 startingPoint );

	if ( rc == 0 )
		return globus_i_io_windows_get_last_error();

	return 0;
} /* globus_i_io_windows_seek() */
/*
int globus_i_io_windows_seek( globus_io_handle_t * handle,
	LARGE_INTEGER numberOfBytes, DWORD startingPoint,
	LARGE_INTEGER * newPosition )
{
	LARGE_INTEGER position;

	position.HighPart= numberOfBytes.HighPart;

	position.LowPart= SetFilePointer( handle->io_handle, 
	 numberOfBytes.LowPart, &position.HighPart, startingPoint );

	if ( position.LowPart == INVALID_SET_FILE_POINTER )
	{
		int rc;
		rc= globus_i_io_windows_get_last_error();
		if ( rc != NO_ERROR )
		{
			if ( newPosition != NULL )
				newPosition->QuadPart= -1; // see Microsoft documentation
			return rc;					   // on SetFilePointer()
		}
	}

	if ( newPosition != NULL )
		*newPosition= position;

	return 0;
} */ /* globus_i_io_windows_seek() */

/**
 * Convert a Win32 file HANDLE to a Globus I/O handle.
 * @param fileHandle The file handle to be used with Globus I/O. The
 * handle should not be used once this function
 * returns. 
 * @param attributes The attributes which will be applied to the socket when
 * possible. ???
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
globus_result_t globus_io_file_windows_convert(
	HANDLE file_handle,
    globus_io_attr_t * attr,
    globus_io_handle_t * handle )
{
    globus_result_t rc;
    static char * myname= "globus_io_file_windows_convert";

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
		return rc;
     
    handle->io_handle = file_handle;
    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
    globus_i_io_copy_fileattr_to_handle(attr,
					handle);

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

    return rc;
}

void globus_i_io_windows_close( globus_io_handle_t * handle )
{
	if ( handle->type != GLOBUS_IO_HANDLE_TYPE_FILE && 
		handle->type != GLOBUS_IO_HANDLE_TYPE_INTERNAL )
	/* must be a socket */
		globus_i_io_winsock_close( handle );
	else
		globus_i_io_windows_file_close( handle );
}

void globus_i_io_windows_file_close( globus_io_handle_t * handle )
{
	BOOL rc;
	rc= CloseHandle( handle->io_handle );
	// if rc == 0, an error occurred; the error code may be retrieved
	// by a call to GetLastError()
	// TODO- add this code and set errno
}

/* globus_i_io_windows_get_last_error()
 *	This function calls GetLastError() to get the error and then sets
 *	errno to an appropriate POSIX error code. Finally, it returns the
 *	Windows error code.
 */
int globus_i_io_windows_get_last_error( void )
{
	int winError;
	winError= GetLastError();
	// TESTING!!!
	//if ( winError != WAIT_TIMEOUT && winError != ERROR_IO_PENDING )
		//fprintf( stderr, "ERROR: GetLastError() returned %d\n", winError );
	// END TESTING
	globus_i_io_windows_set_errno( winError );
	return winError;
}

void globus_i_io_windows_set_errno( int winError )
{
	switch( winError )
	{
		case WSANOTINITIALISED:
		case WSAENETDOWN:
		case WSAENETUNREACH:
			errno= EBADF; // closest thing I could find in a hurry
			break;
		case WSAEINVAL:
		case WSAENOTSOCK: // there is also a POSIX code "ENOTSOCK"
		case WSAEADDRINUSE:
		case WSAEADDRNOTAVAIL:
		case WSAEAFNOSUPPORT:
		case WSAECONNREFUSED: // ??? - should probably be changed
		// TESTING!!!
		case WSAECONNRESET:
		// END TESTING
			errno= EINVAL;
			break;
		case WSAEINTR:
			errno= EINTR;
			break;
		case WSAEINPROGRESS:
		case WSAEALREADY:
			errno= EINPROGRESS;
			break;
		case WSAEFAULT:
			errno= EFAULT;
			break;
		case WSAETIMEDOUT:
		case WAIT_TIMEOUT:
			errno= ETIMEDOUT;
			break;
		case WSAENOBUFS:
			errno= ENOMEM;
			break;
		case WSAEWOULDBLOCK:
			errno= EWOULDBLOCK;
			break;
		case ERROR_HANDLE_EOF:		// The number for this error is 38,
			errno= GLOBUS_WIN_EOF;	// which conflicts with a POSIX
			break;					// error; consequently we have to
									// use a unique number- see the header
									// for the value
		default:
			errno= winError;
	}
}
