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
 * @file globus_io_winsock.c Globus I/O toolset
 *
 *   This file is a stop-gap measure to supply Winsock functionality
 *   for the Fusion project. It is used to redirect calls to read,
 *   write, writev and close.
 *
 * $Source: 
 * $Date: 
 * $Revision: 
 * $State: 
 * $Author: Michael Lebman
 */

#include "globus_l_io.h"
#include <mswsock.h>


/* globus_i_io_winsock_socket_is_readable()
 *
 *	Calls globus_i_io_winsock_will_io_succeed() to determine whether the 
 *	socket passed in is readable. The timeout value passed in is in 
 *	milleseconds.
 */
int globus_i_io_winsock_socket_is_readable( SOCKET socket, int timeout )
{
	return globus_i_io_winsock_will_io_succeed( socket, 1, timeout );
} /* globus_i_io_winsock_socket_is_readable() */


/* globus_i_io_winsock_socket_is_writable()
 *
 *	Calls globus_i_io_winsock_will_io_succeed() to determine whether the 
 *	socket passed in is writable. The timeout value passed in is in 
 *	milleseconds.
 */
int globus_i_io_winsock_socket_is_writable( SOCKET socket, int timeout )
{
	return globus_i_io_winsock_will_io_succeed( socket, 0, timeout );
} /* globus_i_io_winsock_socket_is_writable() */


/* globus_i_io_winsock_will_io_succeed()
 *
 *	Calls select() to determine whether the socket passed in is readable
 *	or writeable, depending on the value of the readOperation flag. The
 *	timeout value passed in is in milleseconds; a value of -1 indicates
 *	that select should block indefinitely.
 *
 *	If select() determines that a read/write operation will likely 
 *	succeed	this function returns 0; otherwise, it returns an appropriate
 *	Windows error code and sets errno to an appropriate POSIX error code.
 */
int globus_i_io_winsock_will_io_succeed( SOCKET socket, 
	int readOperation, int timeout )
{
	fd_set readFdSet, writeFdSet, exceptionFdSet;
	struct timeval timeoutStruct;
	struct timeval * timeoutPtr;
	int rc;

	if ( readOperation )
		FD_ZERO( &readFdSet );
	else
		FD_ZERO( &writeFdSet );
	FD_ZERO( &exceptionFdSet );
	if ( readOperation )
		FD_SET( socket, &readFdSet );
	else
		FD_SET( socket, &writeFdSet );
	FD_SET( socket, &exceptionFdSet );

	if ( timeout >= 0 )
	{
		timeoutStruct.tv_sec= timeout / 1000;
		timeoutStruct.tv_usec= ( timeout % 1000 ) * 1000;

		timeoutPtr= &timeoutStruct;
	}
	else
		timeoutPtr= NULL;

	if ( readOperation )
		rc= select( -1, &readFdSet, NULL, &exceptionFdSet, timeoutPtr );
	else
		rc= select( -1, NULL, &writeFdSet , &exceptionFdSet, timeoutPtr );
	
	if ( rc == 0 ) // timed out
	{
		globus_i_io_windows_set_errno( WSAETIMEDOUT );
		return WSAETIMEDOUT;
	}
	else if ( rc == SOCKET_ERROR )
		return globus_i_io_winsock_get_last_error();

	// select returned properly; check the fd sets
	if ( FD_ISSET( socket, &exceptionFdSet ) )
	{
		int sock_err;
		int sock_errlen;

		sock_errlen= sizeof(int);
		if ( getsockopt( socket, SOL_SOCKET, SO_ERROR, 
			&sock_err, &sock_errlen ) == SOCKET_ERROR )
			return globus_i_io_winsock_get_last_error();

		globus_i_io_windows_set_errno( sock_err );
		return sock_err;			
	}

	// the socket must be set in the appropriate set (read or write),
	// so just return the success code
	return 0;	
} /* globus_i_io_winsock_will_io_succeed */


/* globus_i_io_winsock_read()
*
*	Calls WSARecv() with different semantics, depending on whether the
*	asynchronous flag is set. If the asynchronous flag is true (set to 
*	nonzero), this function returns 0 if the I/O operation was initiated
*	successfully. The result of the operation must be obtained using 
*	GetQueuedCompletionStatus(). If the call is made synchronously, it
*	returns the number of bytes	read. In either case, if an error 
*	occurs it returns -1 and sets errno to an appropriate value.
*
*/

int globus_i_io_winsock_read( globus_io_handle_t * handle, char * buffer, 
 int numberOfBytes, int asynchronous )
{
	int rc;
	DWORD numberOfBytesReceived;

	// set up the WSABUF
	handle->winIoOperation_read.wsaBuf.buf= buffer;
	handle->winIoOperation_read.wsaBuf.len= numberOfBytes;

	// set the I/O operation state
	handle->winIoOperation_read.state= WinIoReading;
	handle->winIoOperation_read.operationAttempted= 1;

	if ( asynchronous )
	{
		rc= WSARecv( (SOCKET)handle->io_handle,
		 (LPWSABUF)&(handle->winIoOperation_read.wsaBuf),
		 1,
		 &numberOfBytesReceived,
		 &handle->winIoOperation_read.flags,
		 &(handle->winIoOperation_read.overlapped), NULL );

		// TESTING!!!
		//fprintf( stderr, "Asynchronous read: %d bytes requested...", numberOfBytes );
		// END TESTING

		if ( rc == SOCKET_ERROR )
		{
			int error;
			error= globus_i_io_winsock_get_last_error();
			if ( error != WSA_IO_PENDING )
			{
				// TESTING!!!
				//fprintf( stderr, "error occurred (error is %d)\n", error );
				// END TESTING
				return -1;
			}
		}
		// TESTING!!!
		//fprintf( stderr, "pending\n" );
		// END TESTING
	}
	else // synchronous
	{
		rc= WSARecv( (SOCKET)handle->io_handle,
		 (LPWSABUF)&(handle->winIoOperation_read.wsaBuf),
		 1,
		 &numberOfBytesReceived,
		 &handle->winIoOperation_read.flags,
		 NULL,
		 NULL );

		// TESTING!!!
		//fprintf( stderr, "Synchronous read: %d bytes requested...", numberOfBytes );
		// END TESTING

		if ( rc == SOCKET_ERROR )
		{
			int error;
			error= globus_i_io_winsock_get_last_error();
			// TESTING!!!
			//fprintf( stderr, "error occurred (error is %d)\n", error );
			// END TESTING
			return -1;
		}

		// TESTING!!!
		//fprintf( stderr, "%d bytes read\n", numberOfBytesReceived );
		// END TESTING

		return numberOfBytesReceived;
	}

	// this line is reached only when the call is asynchronous
	return 0; // the success code for WSARecv
} /* globus_i_io_winsock_read() */

/* globus_i_io_winsock_write()
*
*	Calls WSASend() with different semantics, depending on whether the
*	asynchronous flag is set. If the asynchronous flag is true (set to 
*	nonzero), this function returns 0 if the I/O operation was initiated
*	successfully. The result of the operation must be obtained using 
*	GetQueuedCompletionStatus(). If the call is made synchronously, it
*	returns the number of bytes	written. In either case, if an error 
*	occurs it returns -1 and sets errno to an appropriate value.
*
*/

int globus_i_io_winsock_write( globus_io_handle_t * handle, char * buffer, 
 int numberOfBytes, int asynchronous, int flags )
{
	int rc;
	DWORD numberOfBytesSent;

	// set up the WSABUF
	handle->winIoOperation_write.wsaBuf.buf= buffer;
	handle->winIoOperation_write.wsaBuf.len= numberOfBytes;

	// set the I/O operation state
	handle->winIoOperation_write.state= WinIoWriting;
	handle->winIoOperation_write.operationAttempted= 1;
	handle->winIoOperation_write.flags= flags;

	if ( asynchronous )
	{
		rc= WSASend( (SOCKET)handle->io_handle,
		 (LPWSABUF)&(handle->winIoOperation_write.wsaBuf), 1,
		 &numberOfBytesSent, handle->winIoOperation_write.flags,
		 &(handle->winIoOperation_write.overlapped), NULL );

		// TESTING!!!
		//fprintf( stderr, "Asynchronous write: %d bytes requested...", numberOfBytes );
		// END TESTING

		if ( rc == SOCKET_ERROR )
		{
			int error;
			error= globus_i_io_winsock_get_last_error();
			if ( error != WSA_IO_PENDING )
			{
				// TESTING!!!
				//fprintf( stderr, "Asynchronous write error occurred (error is %d)\n", error );
				// END TESTING
				return -1;
			}
		}
		// TESTING!!!
		//fprintf( stderr, "pending\n" );
		// END TESTING
	}
	else // synchronous
	{
		rc= WSASend( (SOCKET)handle->io_handle,
		 (LPWSABUF)&(handle->winIoOperation_write.wsaBuf), 1,
		 &numberOfBytesSent, handle->winIoOperation_write.flags,
		 NULL, NULL );

		// TESTING!!!
		//fprintf( stderr, "Synchronous write: %d bytes requested...", numberOfBytes );
		// END TESTING

		if ( rc == SOCKET_ERROR )
		{
			globus_i_io_winsock_get_last_error();
			// TESTING!!!
			//fprintf( stderr, "error occurred (errno is %d)\n", errno );
			// END TESTING
			return -1;
		}

		// TESTING!!!
		//fprintf( stderr, "%d bytes written\n", numberOfBytesSent );
		// END TESTING

		return numberOfBytesSent;
	}

	// this line is reached only when the call is asynchronous
	return 0; // the success code for WSASend
} /* globus_i_io_winsock_write() */

/*
int globus_i_io_winsock_writev()
{
}
*/

//void globus_i_io_winsock_close( SOCKET socket )
void globus_i_io_winsock_close( globus_io_handle_t * handle )
{
	// TODO: Depending on how the SO_LINGER option was set, we
	// may need to do one of the following:
	//	1. set the socket to blocking before calling closesocket()
	//	2. continually repeat the call to closesocket() until it
	//	completes or returns an actual error instead of WSAEWOULDBLOCK
	shutdown( (SOCKET)handle->io_handle, SD_SEND );
	/* we should loop within a recv, but this is bubble gum and shoestring code */
	closesocket( (SOCKET)handle->io_handle );

	// free any memory allocated for storing address info
	if ( handle->winIoOperation_structure.addressInfo != NULL )
		free( handle->winIoOperation_structure.addressInfo );
}

int globus_i_io_winsock_get_last_error( void )
{
	int error;
	error= WSAGetLastError();

	// TESTING!!!
	// don't set errno if there was no real error
	if ( error != WSA_IO_PENDING )
		globus_i_io_windows_set_errno( error );
	//globus_i_io_windows_set_errno( error );
	// END TESTING

	return error; // return the Windows error code! If we need the 
				  // POSIX error code, just get errno
}

/* globus_i_io_winsock_accept()
*
*	Calls AcceptEx() asynchronously. The result of the operation must 
*   be obtained using GetQueuedCompletionStatus(). If the call is
*	successful, it returns 0. Otherwise, it returns the Winsock error
*	code and sets errno to an appropriate value.
*
*/

int globus_i_io_winsock_accept( globus_io_handle_t * listenerHandle )
{
	BOOL acceptRC;
	DWORD numberOfBytes;

	// set the I/O operation state
	listenerHandle->winIoOperation_structure.state= WinIoAccepting;
	listenerHandle->winIoOperation_structure.operationAttempted= 1;

	// create a new socket for AcceptEx
	if( ( (SOCKET)listenerHandle->winIoOperation_structure.acceptedSocket
	 = socket( AF_INET, SOCK_STREAM, 0 ) ) == INVALID_SOCKET )
		return globus_i_io_winsock_get_last_error();

	acceptRC= AcceptEx( (SOCKET)listenerHandle->io_handle, 
	 listenerHandle->winIoOperation_structure.acceptedSocket, 
	 listenerHandle->winIoOperation_structure.addressInfo,
	 0, sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16,
	 &numberOfBytes, 
	 &(listenerHandle->winIoOperation_structure.overlapped) );
	if ( acceptRC == FALSE )
	{
		int error;
		error= globus_i_io_winsock_get_last_error();
		if ( error != ERROR_IO_PENDING )
		{
			// cleanup
			closesocket( (SOCKET)
			 listenerHandle->winIoOperation_structure.acceptedSocket );
			listenerHandle->winIoOperation_structure.acceptedSocket= 
			 INVALID_SOCKET;

			return error;
		}
		// TESTING!!!
		//fprintf( stderr, "AcceptEx() posted\n" );
		// END TESTING
	}

	return 0;
} /* globus_i_io_winsock_accept() */

int globus_i_io_winsock_store_addresses( globus_io_handle_t * handle,
 globus_io_handle_t * listenerHandle )
{
	int rc;

	if ( listenerHandle != NULL )
		rc= setsockopt( (SOCKET)handle->io_handle, SOL_SOCKET, 
		 SO_UPDATE_ACCEPT_CONTEXT, (char *)&listenerHandle->io_handle, 
		 sizeof(listenerHandle->io_handle) );
	else
		rc= setsockopt( (SOCKET)handle->io_handle, SOL_SOCKET, 
		 SO_UPDATE_ACCEPT_CONTEXT, NULL, 0 );

	if ( rc == SOCKET_ERROR )
	{
		int error= globus_i_io_winsock_get_last_error();
		// TESTING!!!
		//fprintf( stderr, "cannot update adddres info, error is %d\n",
			//error );
		// END TESTING
		return error;
	}

	return 0;
}
