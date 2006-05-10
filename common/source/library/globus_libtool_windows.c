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

/***************************************************************************
File:            globus_libtool_windows.c

Author:         R. Gaffaney

Description:    Simple Implementation of Libtool libltdl module for windows

Date:           11/06/2003
*****************************************************************************/

#include <windows.h>
#include "globus_libtool_windows.h"

// Definitions
#define MAX_FILE_NAME_Z         1024
#define MAX_FILE_NAME           MAX_FILE_NAME_Z - 1
#define MAX_SYMBOL_NAME         256

// Forward Declaration
typedef struct _DllModule *pDllModule;

// Module Data Struct
typedef struct _DllModule {
    pDllModule              pNext;
    HANDLE                  hDllHandle;
    char                    pcFileName[MAX_FILE_NAME_Z];
    int                     iRefCount;
    } DllModule, *pDllModule;
    

// Static Variables
CRITICAL_SECTION    csLibLock;
int                 iEntryCount = 0;
pDllModule          pModuleList = NULL;
int                 iLastError = 0;
static const char  *lt_dlerror_strings[] = {
    #define LT_ERROR(name, diagnostic)	(diagnostic),
    lt_dlerror_table
    #undef LT_ERROR
    0
    };


// Local Function Prototypes
pDllModule FindLoadedModuleByName(const char *filename);
pDllModule FindLoadedModuleByAddress(pDllModule pModule);
pDllModule OpenModule(const char *filename);
void NormalizeName(const char *filename,char *NormName);


#ifdef MAKE_WIN_DLL
// Empty (For Now) DllMain 
unsigned char __stdcall DllMain( HANDLE hModule, DWORD dwReason, LPVOID lpReserved )
{
unsigned char bReturnValue = TRUE;

    // Process according to reason
    switch (dwReason) {
        case DLL_PROCESS_ATTACH: {
            iEntryCount = 0;
            break;
            }

        case DLL_THREAD_ATTACH:
            break;

        case DLL_PROCESS_DETACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        default:
            bReturnValue = FALSE;
            break;
            };

    return bReturnValue;
}
#endif


// Initialize This Module
int lt_dlinit (void)
{
    if(++iEntryCount == 1) {
        InitializeCriticalSection(&csLibLock);
        }
    
    iLastError = 0;
    return 0;
}


// Exit This Module
int lt_dlexit (void)
{
    // ToDo: Spin Through Module List And Delete All Modules
   if(--iEntryCount == 0) {
        DeleteCriticalSection(&csLibLock);
        }
        
    iLastError = 0;
    return 0;
}


// Load A DLL
lt_dlhandle lt_dlopenext (const char *filename)
{
pDllModule pModule = NULL;

    // Check Argument
    if(!filename) {
        iLastError = LT_ERROR_DEPLIB_NOT_FOUND;
        return NULL;
        }

    // Grab The Lock
    EnterCriticalSection(&csLibLock);
    
    // Are We Initialized
    if(!iEntryCount) {
        // Release The Lock
        LeaveCriticalSection(&csLibLock);
        iLastError = LT_ERROR_SHUTDOWN;
        return NULL;
        }
        
    // Is This Module Already Open?
    pModule = FindLoadedModuleByName(filename);
    if(pModule) {
        // Bump The Reference Count
        pModule->iRefCount += 1;
        
        // Release The Lock
        LeaveCriticalSection(&csLibLock);
        
        // Return The Address Of The Data Struct As The Handle
        iLastError = 0;
        return (lt_dlhandle) pModule;
        }
    
    // Try To Find And Open The DLL
    // Note: For Performance Reasons It Might Be Better To Release The Critical
    //       Section Before Doing The Open, But That Would Require A Mechanism
    //       To Prevent A Second Request For The Same Module To Be Handled While
    //       A First One Is In Progress - This Is A "Later If Needed" Item
    pModule = OpenModule(filename);
    if(pModule) {
        // Bump The Reference Count
        pModule->iRefCount += 1;

        // Return The Module
        LeaveCriticalSection(&csLibLock);
        iLastError = 0;
        return (lt_dlhandle) pModule;
        }
    
    // Release The Lock
    LeaveCriticalSection(&csLibLock);
        
    // Not Found Or Opened
    iLastError = LT_ERROR_DEPLIB_NOT_FOUND;
    return (lt_dlhandle) pModule;
}


// Return A Pointer To A Function In The DLL
lt_ptr lt_dlsym (lt_dlhandle handle, const char *name)
{
pDllModule pModule;
FARPROC pFunction = NULL;

    // Check Arguments
    if(!handle || !name) {
        iLastError = LT_ERROR_DEPLIB_NOT_FOUND;
        return NULL;
        }
        
    // Cast The Pointer
    pModule = (pDllModule) handle;
    
    // Grab The Lock
    EnterCriticalSection(&csLibLock);

    // Make Sure The Record Is In The List
    if(FindLoadedModuleByAddress(pModule) == NULL) {
        iLastError = LT_ERROR_DEPLIB_NOT_FOUND;
        LeaveCriticalSection(&csLibLock);
        return NULL;
        }
        
    // Find The Function
    pFunction = GetProcAddress(pModule->hDllHandle,name);
    if(!pFunction) {
        iLastError = LT_ERROR_SYMBOL_NOT_FOUND;
        LeaveCriticalSection(&csLibLock);
        return NULL;
        }
    
    // Release Lock    
    LeaveCriticalSection(&csLibLock);
        
    // Return The Function Pointer
    iLastError = 0;
    return (lt_ptr) pFunction;
}


// Return The Last Reported Error
const char *lt_dlerror (void)
{
    return lt_dlerror_strings[iLastError];
}


// Close The Module
// ToDo: Appears From Callout Library That Caller Deallocates Memory
int lt_dlclose (lt_dlhandle handle)
{
pDllModule pModule = NULL;
pDllModule pTemp;

    // Check Argument
    if(!handle) {
        iLastError = LT_ERROR_DEPLIB_NOT_FOUND;
        return LT_ERROR_DEPLIB_NOT_FOUND;
        }

    // Make A Copy
    pTemp = (pDllModule) handle;

    // Grab The Lock
    EnterCriticalSection(&csLibLock);

    // Are We Initialized Or Is The List Empty
    if(!iEntryCount || !pModuleList) {
        // Release The Lock, Exit
        LeaveCriticalSection(&csLibLock);
        iLastError = LT_ERROR_UNKNOWN;
        return LT_ERROR_UNKNOWN;
        }
    
    // See If The Module Is The First Entry In The List
    if(pTemp == pModuleList) {
        // Decrement The Reference Count
        if(--pModuleList->iRefCount == 0) {
            // Free The Library
            FreeLibrary(pModuleList->hDllHandle);
            
            // Remove It From The List
            pModuleList = pModuleList->pNext;
            }
            
        // Release The Lock, Exit
        LeaveCriticalSection(&csLibLock);
        iLastError = 0;
        return 0;
        }

    // Search For The Entry
    pModule = pModuleList->pNext;
    while(pModule->pNext) {
        if(pModule->pNext == pTemp) {
            // Remove Only If Reference Count Hits Zero
            if(--pModule->pNext->iRefCount == 0) {
                // Remove The Entry
                pModule->pNext = pModule->pNext->pNext;
                }
                
            // Release The Lock, Exit
            LeaveCriticalSection(&csLibLock);
            iLastError = 0;
            return 0;
            }
        }
    
    // If We Got Here The Module Wasn't Found
    LeaveCriticalSection(&csLibLock);
    iLastError = LT_ERROR_DEPLIB_NOT_FOUND;
    return LT_ERROR_DEPLIB_NOT_FOUND;
}

/* This Is Called From common_extension.c */
extern	int	lt_dlmutex_register	LT_PARAMS((lt_dlmutex_lock *lock,
					    lt_dlmutex_unlock *unlock,
					    lt_dlmutex_seterror *seterror,
					    lt_dlmutex_geterror *geterror))
{
    return 0;
}                        

/*
**  Local Functions
*/

// Find A DLL In The Loaded Module List - By Address
//      Assumes That Caller Owns The Lock
pDllModule FindLoadedModuleByAddress(pDllModule pModule)
{
pDllModule pTemp;

    // Are We Initialized Or Is The List Empty
    if(!iEntryCount || !pModuleList) {
        return NULL;
        }
    
    // See If The Module Is The First Entry In The List
    if(pModule == pModuleList) {
        return pModule;
        }

    // Search For The Entry
    pTemp = pModuleList->pNext;
    while(pTemp->pNext) {
        if(pTemp->pNext == pModule) {
            return pModule;
            }
        }
    
    // Not Found
    return NULL;
}


// Find A DLL In The Loaded Module List - By Name
//      Assumes Caller Owns The Lock
pDllModule FindLoadedModuleByName(const char *filename)
{
pDllModule pModule = NULL;
char NormName[MAX_FILE_NAME_Z];

    // Check If No Entries
    if((pModule = pModuleList) == NULL) {
        return pModule;
        }
    
    // Normalize The Name 
    NormalizeName(filename,NormName);
    
    // Walk The List Looking For The Module
    do {
        if(!strnicmp(NormName,pModule->pcFileName,MAX_FILE_NAME)) {
            // Found It
            return pModule;
            }
            
        // Point To Next
        pModule = pModule->pNext;
        } while(pModule);

    // Not Found        
    return pModule;
}


// Open A DLL And Put It Into The Module List
//      Assumes That Caller Owns The Lock
pDllModule OpenModule(const char *filename)
{
pDllModule pModule = NULL;
pDllModule pTemp = NULL;
char NormName[MAX_FILE_NAME_Z];
HANDLE DllHandle;

    // Normalize The Name 
    NormalizeName(filename,NormName);

    // Fail If The Module Is Already Open
    pModule = FindLoadedModuleByName(filename);
    if(pModule) {
        return NULL;
        }
    
    // Try To Load The Library
    DllHandle = LoadLibrary(NormName);
    if(DllHandle == NULL) {
        return NULL;
        }    
        
    // Create A Module List Entry
    pModule = malloc(sizeof(DllModule));
    if(!pModule) {
        // Bail - Problems In River City
        return NULL;
        }
        
    // Fill It In
    memset(pModule,0,sizeof(DllModule));
    pModule->hDllHandle = DllHandle;
    strncpy(pModule->pcFileName,NormName,MAX_FILE_NAME);
    // Note: Leave The Reference Count At Zero - Caller Will Bump It
    
    // Add It To The Module List
    
    // The List Is Empty
    if((pTemp = pModuleList) == NULL) {
        pModuleList = pModule;
        return pModule;
        }
        
    // Find The End
    while(pTemp->pNext) {
        pTemp = pTemp->pNext;
        }

    // Add It
    pTemp->pNext = pModule;
    
    // Return The New Entry
    return pModule;
}


// Normalize The Name - Lower Case, Add ".dll" Extension If Necessary
void NormalizeName(const char *filename,char *NormName)
{
char *pcSubStr;

    // Copy The String
    strncpy(NormName,filename,MAX_FILE_NAME);
    
    // Convert To Lower Case
    _strlwr(NormName);
    
    // Look For Trailing ".dll"
    pcSubStr = strstr(NormName,".dll");
    if(!pcSubStr) {
        strcat(NormName,".dll");
        }
}
