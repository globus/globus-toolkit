/*
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */
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

enum
{
    FILE_SYNCHRONOUS_IO_ALERT           = 0x00000010,
    FILE_SYNCHRONOUS_IO_NONALERT        = 0x00000020
};

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
