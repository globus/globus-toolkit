// bmed.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "bmed.h"
#include "bmedDlg.h"
#include "bookmark.h"
#include "util.h"

#include <Strn.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

extern "C" {
	extern int gNumBookmarks;
	extern BookmarkPtr gBookmarkTable;
	extern char gOurInstallationPath[260];
}

/////////////////////////////////////////////////////////////////////////////
// CBmedApp

BEGIN_MESSAGE_MAP(CBmedApp, CWinApp)
	//{{AFX_MSG_MAP(CBmedApp)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CBmedApp construction

CBmedApp::CBmedApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
	m_dirty = FALSE;
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CBmedApp object

CBmedApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CBmedApp initialization

BOOL CBmedApp::InitInstance()
{
	AfxEnableControlContainer();

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	//  of your final executable, you should remove from the following
	//  the specific initialization routines you do not need.

#ifdef _AFXDLL
	Enable3dControls();			// Call this when using MFC in a shared DLL
#else
	Enable3dControlsStatic();	// Call this when linking to MFC statically
#endif

	AfxGetApp()->m_pszAppName = "NcFTP Bookmarks";

	::InitUserInfo();
	::InitOurDirectory();

	if (::LoadBookmarkTable() < 0) {
		AfxMessageBox("Could not initialize bookmark table.");
		return FALSE;
	}

	CBmedDlg dlg;
	m_pMainWnd = &dlg;
	(void) dlg.DoModal();

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}	// InitInstance




void CBmedApp::SendSelectedBookmarkToNcFTP(void)
{
	HANDLE hMailSlot;
	char str[kNcFTPBookmarksMailslotMsgSize];
	DWORD dwWrote;
	DWORD err = 0;
	BOOL rc;
	const char *prog;
	char path[MAX_PATH];
	int winExecResult;

	hMailSlot = ::CreateFile(
         kNcFTPBookmarksMailslot,
         GENERIC_WRITE, 
         FILE_SHARE_READ,// share with other readers
         NULL,           // no security attributes
         OPEN_EXISTING,  // opens existing pipe 
         0,              // default attributes 
         NULL);          // no template file 

	if ((hMailSlot == INVALID_HANDLE_VALUE) || (hMailSlot == NULL)) {
		err = ::GetLastError();
	} else {
		// Prepare the bookmark name to send.
		//
		// Note that it is okay to send NcFTP an empty string,
		// since that would mean that no bookmark was selected.
		// We still have to do that since NcFTP is waiting for
		// a message!
		//
		strncpy(str, (LPCSTR) m_selectedBookmarkName, sizeof(str));
		str[sizeof(str) - 1] = '\0';

		dwWrote = 0;
		rc = ::WriteFile(
			hMailSlot,
			str,
			sizeof(str),
			&dwWrote,
			NULL
			);

		if (!rc) {
			// Perhaps NcFTP was terminated in between the time we opened
			// the mailslot and now?
			//
			err = ::GetLastError();
		}
		::CloseHandle(hMailSlot);
	}

	if ((err != 0) && (m_selectedBookmarkName.IsEmpty() == FALSE)) {
		// Odds are if we get here that we were run in stand-alone
		// mode.  Since the user chose a bookmark, we must now
		// launch NcFTP and specify a bookmark on the command-line.
		//
		prog = "ncftp.exe";
		if (gOurInstallationPath[0] == '\0') {
			AfxMessageBox("Could not find path to NcFTP.exe.  Please re-run Setup.");
		} else {
			OurInstallationPath(path, sizeof(path), prog);
			STRNCAT(path, " ");
			STRNCAT(path, str); 
			
			winExecResult = WinExec(path, SW_SHOWNORMAL);
			if (winExecResult <= 31) {
				AfxMessageBox("Could not launch NcFTP.exe.");
			}
		}
	}
}	// SendSelectedBookmarkToNcFTP




int CBmedApp::ExitInstance() 
{
	if (m_dirty) {
		SaveBookmarkTable();
		m_dirty = FALSE;
	}

	// It's important that we always send the message back to NcFTP,
	// since NcFTP waits for a message until we exit.
	//
	SendSelectedBookmarkToNcFTP();

	if (gBookmarkTable != NULL) {
		free(gBookmarkTable);
		gBookmarkTable = NULL;
	}
	return CWinApp::ExitInstance();
}	// ExitInstance
