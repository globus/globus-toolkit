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
 * @file globus_i_io_windows.h Globus I/O toolset
 *
 *   Header file for globus_io_windows.c
 *
 * $Source: 
 * $Date: 
 * $Revision: 
 * $State: 
 * $Author: Michael Lebman
 */

#ifndef GLOBUS_I_IO_WINDOWS_H
#define GLOBUS_I_IO_WINDOWS_H

// Create a unique error code for the end of file condition;
// see note in globus_i_io_windows_set_errno()
#define GLOBUS_WIN_EOF 20038

extern HANDLE completionPort;

void globus_i_io_windows_init_io_operations( 
	globus_io_handle_t * handle );

void globus_l_io_windows_init_io_operation( 
	WinIoOperation * winIoOperation );

int globus_i_io_windows_read( 
	globus_io_handle_t * handle,
	globus_byte_t * buf,
	globus_size_t max_nbytes,
	int asynchronous );

int globus_i_io_windows_file_read( 
	globus_io_handle_t * handle, 
	char * buffer, 
	int maxNumberOfBytesToRead, 
	int asynchronous );

int globus_i_io_windows_write( 
	globus_io_handle_t * handle,
	globus_byte_t * buf,
	globus_size_t max_nbytes,
	int asynchronous,
	int flags );

int globus_i_io_windows_file_write( 
	globus_io_handle_t * handle, 
	char * buffer, 
	int numberOfBytesToWrite, 
	int asynchronous );

int globus_i_io_windows_post_completion( globus_io_handle_t * handle, 
 char state );

int globus_i_io_windows_file_open( 
	globus_io_handle_t * handle, 
	char * filename,
	DWORD creationFlags, 
	SECURITY_ATTRIBUTES * securityAttributes );

int globus_i_io_windows_get_file_pointer( globus_io_handle_t * handle,
	LARGE_INTEGER * currentPosition );

int globus_i_io_windows_move_file_pointer( globus_io_handle_t * handle,
	LARGE_INTEGER numberOfBytes, LARGE_INTEGER * newPosition );

int globus_i_io_windows_seek( globus_io_handle_t * handle,
	LARGE_INTEGER numberOfBytes, DWORD startingPoint,
	LARGE_INTEGER * newPosition );

/*
globus_result_t globus_io_file_windows_convert(
	HANDLE file_handle,
    globus_io_attr_t * attr,
    globus_io_handle_t * handle );
*/

void globus_i_io_windows_close( globus_io_handle_t * handle );

void globus_i_io_windows_file_close( globus_io_handle_t * handle );

int globus_i_io_windows_get_last_error( void );

void globus_i_io_windows_set_errno( int winError );

#endif /* GLOBUS_I_IO_WINDOWS_H */
