/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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
