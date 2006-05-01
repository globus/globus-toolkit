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
