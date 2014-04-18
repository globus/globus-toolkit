/*
 * Copyright 1999-2014 University of Chicago
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

#ifdef _WIN32
#include "globus_i_xio_win32.h"

/* all taken from DDK */
#ifndef NT_SUCCESS
typedef LONG                            NTSTATUS;
#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)
#endif

typedef struct
{
    union
    {
        NTSTATUS                        Status;
        PVOID                           Pointer;
    };

    ULONG_PTR                           Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum
{
    FileModeInformation                 = 16
} FILE_INFORMATION_CLASS;

typedef struct
{
    ULONG                               Mode;
} FILE_MODE_INFORMATION;

typedef NTSTATUS
(__stdcall *globus_i_xio_win32_mode_nqif_t)(
    HANDLE                              FileHandle,
    PIO_STATUS_BLOCK                    IoStatusBlock,
    PVOID                               FileInformation,
    ULONG                               Length,
    FILE_INFORMATION_CLASS              FileInformationClass);

static HMODULE                          globus_i_xio_win32_mode_ntdll;
static globus_i_xio_win32_mode_nqif_t   globus_i_xio_win32_mode_query;

int
globus_i_xio_win32_mode_activate(void)
{
    if(globus_i_xio_win32_mode_ntdll == NULL)
    {
        globus_i_xio_win32_mode_ntdll = LoadLibrary("ntdll.dll");
        if(globus_i_xio_win32_mode_ntdll == NULL)
        {
            goto error_load;
        }
        
        globus_i_xio_win32_mode_query = (globus_i_xio_win32_mode_nqif_t)
            GetProcAddress(
                globus_i_xio_win32_mode_ntdll,
                "NtQueryInformationFile");
        if(globus_i_xio_win32_mode_query == NULL)
        {
            goto error_symbol;
        }
    }
    
    return GLOBUS_SUCCESS;

error_symbol:
    FreeLibrary(globus_i_xio_win32_mode_ntdll);
error_load:
    return GLOBUS_FAILURE;
}

globus_bool_t
globus_i_xio_win32_mode_is_overlapped(
    HANDLE                              handle)
{
    IO_STATUS_BLOCK                     iosb;
    FILE_MODE_INFORMATION               mode;
    
    if(NT_SUCCESS(globus_i_xio_win32_mode_query(
        handle, &iosb, &mode, sizeof(mode), FileModeInformation)) &&
        NT_SUCCESS(iosb.Status) &&
        (mode.Mode &
            (FILE_SYNCHRONOUS_IO_ALERT|FILE_SYNCHRONOUS_IO_NONALERT)) == 0)
    {
        return GLOBUS_TRUE;
    }
    else
    {
        return GLOBUS_FALSE;
    }
}
#endif /* TARGET_ARCH_WIN32 */
