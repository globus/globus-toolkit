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
