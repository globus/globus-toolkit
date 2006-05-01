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
 * @file globus_i_io_winsock.h Globus I/O toolset
 *
 *   Header file for globus_io_winsock.c
 *
 * $Source: 
 * $Date: 
 * $Revision: 
 * $State: 
 * $Author: Michael Lebman
 */

#ifndef GLOBUS_I_IO_WINSOCK_H
#define GLOBUS_I_IO_WINSOCK_H

//#include <winsock2.h>

int globus_i_io_winsock_socket_is_readable( SOCKET socket, int timeout );
int globus_i_io_winsock_socket_is_writable( SOCKET socket, int timeout );
int globus_i_io_winsock_will_io_succeed( SOCKET socket, 
	int readOperation, int timeout );
int globus_i_io_winsock_read( globus_io_handle_t * handle, char * buffer, 
 int numberOfBytes, int asynchronous );
int globus_i_io_winsock_write( globus_io_handle_t * handle, char * buffer, 
 int numberOfBytes, int asynchronous, int flags );
void globus_i_io_winsock_close( globus_io_handle_t * handle );
int globus_i_io_winsock_get_last_error( void );
int globus_i_io_winsock_accept( globus_io_handle_t * listenerHandle );
int globus_i_io_winsock_store_addresses( globus_io_handle_t * handle,
 globus_io_handle_t * listenerHandle );

#endif /* GLOBUS_I_IO_WINSOCK_H */
