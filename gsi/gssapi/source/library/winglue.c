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

/**********************************************************************
                             Include header files
**********************************************************************/


#include "winglue.h"
#include <winuser.h>
#include <stdio.h>
#include <bio.h>
#include <err.h>
#include <malloc.h>


/**********************************************************************
                               Type definitions
**********************************************************************/

#define IDC_STATIC       0xffff 
#define ID_READ_PASSPHRASE_DIALOG       3690
#define ID_READ_PASSPHRASE_PROMPT       3691
#define ID_READ_PASSPHRASE_PASSPHRASE   3692

typedef struct {
    char *prompt;
    char *return_pwd;
    int  *size_return;
} read_passphrase_params;

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

static HINSTANCE hinstance;
static char * saved_prompt;

/***********************************************************************
Function: ERR_print_errors_MessageBox()

Description:
	Print SSLeay errors to a message box.
************************************************************************/
int
ERR_print_errors_MessageBox(HWND hwnd, char * title)
{
	BIO * mbio;
	int len;
	char * buffer;

	if ((mbio = BIO_new(BIO_s_mem())) == NULL) {
		MessageBox(hwnd,"Unable to determine errors", title, MB_ICONEXCLAMATION);
		return 1; 
	}
	
	ERR_print_errors(mbio);
	len = BIO_pending(mbio);
	buffer = (char *) malloc(len+1);
	if (buffer) {
		BIO_read(mbio,buffer,len);
		buffer[len] = '\0';
		MessageBox(hwnd, buffer, title, MB_ICONEXCLAMATION);
	
		free(buffer);
	}
	BIO_free(mbio);
	return 0;
} 




//----------------------------------------------------------------------------- 
// Name:  CopyToWideChar 
//----------------------------------------------------------------------------- 
static VOID CopyToWideChar( WCHAR** pstrOut, LPTSTR strIn ) 
{ 
    DWORD  dwLen  = lstrlen( strIn ); 
    WCHAR* strOut = *pstrOut; 
 
#ifdef UNICODE // Copy Unicode to Unicode 
    _wcsncpy( strOut, strIn, dwLen ); 
    strOut[dwLen] = L'\0'; 
#else         // Copy Ansi to Unicode 
    dwLen = MultiByteToWideChar( CP_ACP, 0, strIn, dwLen, strOut, dwLen ); 
    strOut[dwLen++] = L'\0'; // Add the null terminator 
#endif 
    *pstrOut += dwLen; 
} 
 
//----------------------------------------------------------------------------- 
// Name: AddDialogControl() 
// Desc: Internal function to help build the user select dialog 
//----------------------------------------------------------------------------- 
static VOID AddDialogControl( WORD** pp, DWORD dwStyle, SHORT x, SHORT y, 
                              SHORT cx, SHORT cy, WORD id,  
                              WORD class, LPTSTR strClassName, LPTSTR strTitle ) 
{ 
    // DWORD align the current ptr 
    DLGITEMTEMPLATE* p = (DLGITEMTEMPLATE*)(((((ULONG)(*pp))+3)>>2)<<2); 
 
    p->style           = dwStyle | WS_CHILD | WS_VISIBLE; 
    p->dwExtendedStyle = 0L; 
    p->x               = x; 
    p->y               = y; 
    p->cx              = cx; 
    p->cy              = cy; 
    p->id              = id; 
 
    *pp = (WORD*)(++p); // Advance ptr 
    if (class) {
       *((*pp)++) = 0xffff;
       *((*pp)++) = class;
    } else {
        CopyToWideChar( (WCHAR**)pp, strClassName ); // Set Class name
    }
    CopyToWideChar( (WCHAR**)pp, strTitle );     // Set Title 
 
    (*pp)++;          // Skip Extra Stuff 
} 
#if 0

ID_READ_PASSPHRASE_DIALOG DIALOG 60, 72, 200, 84
STYLE DS_MODALFRAME | WS_POPUP | WS_VISIBLE | WS_CAPTION | WS_SYSMENU |
	DS_SETFONT
CAPTION "GSI Passphrase/Pin"
FONT 8, "Ariel"
{
  LTEXT "", ID_READ_PASSPHRASE_PROMPT, 10, 8, 180, 10
  EDITTEXT ID_READ_PASSPHRASE_PASSPHRASE, 10, 42, 180, 12, ES_AUTOHSCROLL | ES_PASSWORD |
	WS_BORDER | WS_TABSTOP
  DEFPUSHBUTTON "&OK", IDOK, 55, 61, 40, 14
  PUSHBUTTON "&Cancel", IDCANCEL, 107, 61, 40, 14
#endif 
//----------------------------------------------------------------------------- 
// Name: BuildDlgTemplate() 
// Desc: Internal function to build the user select dialog 
//----------------------------------------------------------------------------- 
static
DLGTEMPLATE* BuildDlgTemplate() 
{
    DLGTEMPLATE * pDlgTemplate = NULL;
    DLGTEMPLATE * pdt;
    WORD * pw;
    int size;
    int items = 4;

    size = sizeof(DLGTEMPLATE) + 2*4*256 + 8 + 
           items * (sizeof(DLGITEMTEMPLATE) + 2*4*256 + 2);

         
    pDlgTemplate = (DLGTEMPLATE *) malloc(size);
  
    if (!pDlgTemplate) { 
        return NULL;
    }
    ZeroMemory(pDlgTemplate, size); 
     
    // Fill in the DLGTEMPLATE info 
    pdt     = pDlgTemplate; 
    pdt->style           = DS_MODALFRAME | DS_NOIDLEMSG | DS_SETFOREGROUND | 
                           DS_3DLOOK | DS_CENTER | WS_POPUP | WS_VISIBLE | 
                           WS_CAPTION | WS_SYSMENU | DS_SETFONT; 
    pdt->dwExtendedStyle = 0L; 
    pdt->cdit            = items; 
    pdt->x               = 60; 
    pdt->y               = 52; 
    pdt->cx              = 200; 
    pdt->cy              = 64; 
 
    // Add menu array, class array, dlg title, font size and font name 
    pw = (WORD*)(++pdt); 
    *pw++ = L'\0';                               // Set Menu array to nothing 
    *pw++ = L'\0';                               // Set Class array to nothing 
    CopyToWideChar( (WCHAR**)&pw, TEXT( "GSI PassPhrase or PIN" ) ); // Dlg title 
    *pw++ = 8;                                   // Font Size 
    CopyToWideChar( (WCHAR**)&pw, TEXT("Arial") );         // Font Name

     // Add the passphrase
    AddDialogControl( &pw, ES_AUTOHSCROLL | ES_PASSWORD |WS_BORDER | WS_TABSTOP,
                       10, 22, 180, 12, ID_READ_PASSPHRASE_PASSPHRASE,        
                       0x0081,TEXT("EDIT"), TEXT("") );                       

    // Add the okay button 
    AddDialogControl( &pw, BS_PUSHBUTTON | WS_TABSTOP, 55, 41, 40, 14,  
                      IDOK, 0x0080, TEXT("BUTTON"), TEXT("OK") ); 
 
    // Add the cancel button 
    AddDialogControl( &pw, BS_PUSHBUTTON | WS_TABSTOP, 107, 41, 40, 14,  
                      IDCANCEL, 0x0080, TEXT("XXXBUTTON"), TEXT("Cancel") ); 
 
    // Add the prompt 
    AddDialogControl( &pw, 0,
                      10, 8, 180, 10, ID_READ_PASSPHRASE_PROMPT,
                      0x0082, TEXT("STATIC"), TEXT("") );
 

  
    return pDlgTemplate; 
} 


/***********************************************************************
Function: save_hinstance()

Description:
	save the instance.
************************************************************************/
void
save_instance(HINSTANCE hinst)
{
	hinstance = hinst;
}


/***********************************************************************
Function: read_passphrase_win32_proc()

Description:
	Read the pass-phrase of pin using
      a dialog box.
************************************************************************/
static int CALLBACK 
read_passphrase_win32_proc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    read_passphrase_params FAR *dp;
    
    switch(msg) {
    case WM_INITDIALOG:
	dp = (read_passphrase_params FAR *) lParam;
	SetWindowLong(hdlg, DWL_USER, lParam);
        SetDlgItemText(hdlg, ID_READ_PASSPHRASE_PROMPT, dp->prompt);
	SetDlgItemText(hdlg, ID_READ_PASSPHRASE_PASSPHRASE, "");
        /* center_dialog(hdlg);   */
	return TRUE;

    case WM_COMMAND:
	dp = (read_passphrase_params FAR *) GetWindowLong(hdlg, DWL_USER);
        switch (wParam) {
	case IDOK:
	    *(dp->size_return) =
		GetDlgItemText(hdlg, ID_READ_PASSPHRASE_PASSPHRASE, 
			       dp->return_pwd, *(dp->size_return));
	    EndDialog(hdlg, TRUE);
	    break;
	    
	case IDCANCEL:
	    memset(dp->return_pwd, 0 , *(dp->size_return));
	    *(dp->size_return) = 0;
	    EndDialog(hdlg, FALSE);
	    break;
        }
        return TRUE;
 
    default:
        return FALSE;
    }
}
/***********************************************************************
Function: read_passphrase_win32()

Description:
	Read the pass-phrase of pin using
      a dialog box.
************************************************************************/
int 
read_passphrase_win32(char *buf, int num, int w)
{
	int rc;
	DLGPROC dlgproc;
	DLGTEMPLATE * dlgtemplate = NULL;
	HINSTANCE hinst;
	read_passphrase_params dps;
	int size_return;

	dlgproc = read_passphrase_win32_proc;
	size_return = num;

	if (saved_prompt) {
		dps.prompt = saved_prompt;
	} else { 
		dps.prompt = "PassPhrase or PIN:";
	}
	dps.return_pwd = buf;
	dps.size_return = &size_return;

	dlgtemplate = BuildDlgTemplate(); 
	hinst = hinstance;
	rc = DialogBoxIndirectParam(hinst, dlgtemplate, 0,
                        dlgproc, (LPARAM) &dps);
 
        free(dlgtemplate);

        if (rc) {
          return size_return;
        }

        return 0;      
}

/***********************************************************************
Function: read_passphrase_win32()

Description:
	Read the pass-phrase of pin using
      a dialog box.
************************************************************************/
int 
read_passphrase_win32_prompt(char *prompt)
{
	if (saved_prompt) {
		free(saved_prompt);
	}
	saved_prompt = strdup(prompt);
	return 0;
} 
/***********************************************************************
Function: DLLMain()

Description:
	Save the HINSTANCE to be used in the read_passphrase
        dialog box.
	Only compiled if this is to be used in a DLL. 
************************************************************************/
#ifdef _WINDLL
BOOL WINAPI DllMain (HANDLE hModule, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
	    hinstance = (HINSTANCE) hModule;
	    break;

        case DLL_THREAD_ATTACH:
	    break;

        case DLL_THREAD_DETACH:
	    break;

        case DLL_PROCESS_DETACH:
	    break;

        default:
	    return FALSE;
    }
 
    return TRUE;   // successful DLL_PROCESS_ATTACH
}
#endif

