#if !defined(AFX_WGPIVIEW_H__2949C3E1_0EA1_11D3_8DC0_0080C7083D4D__INCLUDED_)
#define AFX_WGPIVIEW_H__2949C3E1_0EA1_11D3_8DC0_0080C7083D4D__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000
// WgpiView.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// WgpiView dialog

class WgpiView : public CDialog
{
// Construction
public:
	WgpiView(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(WgpiView)
	enum { IDD = IDD_DIALOG1 };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(WgpiView)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(WgpiView)
		// NOTE: the ClassWizard will add member functions here
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_WGPIVIEW_H__2949C3E1_0EA1_11D3_8DC0_0080C7083D4D__INCLUDED_)
