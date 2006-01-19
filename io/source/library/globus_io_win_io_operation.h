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
