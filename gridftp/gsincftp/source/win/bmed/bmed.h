// bmed.h : main header file for the BMED application
//

#if !defined(AFX_BMED_H__3C180D65_7355_11D3_9CCB_00400543CD04__INCLUDED_)
#define AFX_BMED_H__3C180D65_7355_11D3_9CCB_00400543CD04__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

#define kNcFTPBookmarksMailslot "\\\\.\\mailslot\\ncftpbm.slt"
#define kNcFTPBookmarksMailslotMsgSize 128

/////////////////////////////////////////////////////////////////////////////
// CBmedApp:
// See bmed.cpp for the implementation of this class
//

class CBmedApp : public CWinApp
{
public:
	CBmedApp();

protected:
	CString m_selectedBookmarkName;
	BOOL m_dirty;

public:
	void SetSelectedBookmark(LPCSTR s) { m_selectedBookmarkName = s; }
	void SetDirty(BOOL b = TRUE) { m_dirty = b; }

protected:
	void SendSelectedBookmarkToNcFTP(void);

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CBmedApp)
	public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CBmedApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

extern CBmedApp theApp;

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_BMED_H__3C180D65_7355_11D3_9CCB_00400543CD04__INCLUDED_)
