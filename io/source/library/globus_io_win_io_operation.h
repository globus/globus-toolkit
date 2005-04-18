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
 * @file globus_io_win_io_operation.h Globus I/O toolset
 *
 *  This file defines an extension to the Windows overlapped
 *	structure for purposes of using I/O completion ports
 *
 * $Source: 
 * $Date: 
 * $Revision: 
 * $State: 
 * $Author: Michael Lebman
 */

#ifndef GLOBUS_IO_WIN_IO_OPERATION_H
#define GLOBUS_IO_WIN_IO_OPERATION_H

//#include <winsock2.h>

enum WinIoState { WinIoListening, WinIoConnecting, WinIoAccepting, 
 WinIoReading, WinIoWriting, WinIoClosing, WinIoWakeup, WinIoUnknown };

typedef struct win_io_operation
{
	OVERLAPPED overlapped;
	//char * buffer;
	//int currentBufferPosition;
	char state;
	char operationAttempted; // used to flag whether an actual I/O
							 // operation was attempted, or
							 // PostQueuedCompletionStatus() was called
							 // in order to invoke a callback
	int numberOfBytesProcessed;
	WSABUF wsaBuf;
	DWORD flags;
	SOCKET acceptedSocket; // used only to hack the Globus listen() functions
	char * addressInfo; // needed for sockets created by AcceptEx()
} WinIoOperation;

#endif // GLOBUS_IO_WIN_IO_OPERATION_H
