// wgpi.h : main header file for the WGPI application
//

#if !defined(AFX_WGPI_H__D90645E4_B151_11D2_8DBF_D1B78357C555__INCLUDED_)
#define AFX_WGPI_H__D90645E4_B151_11D2_8DBF_D1B78357C555__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CWgpiApp:
// See wgpi.cpp for the implementation of this class
//

class CWgpiApp : public CWinApp
{
public:
	CWgpiApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CWgpiApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CWgpiApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_WGPI_H__D90645E4_B151_11D2_8DBF_D1B78357C555__INCLUDED_)
