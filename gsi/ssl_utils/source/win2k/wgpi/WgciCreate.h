#if !defined(AFX_WGCICREATE_H__2E1B4740_BA2D_11D2_8DBF_0080C7083D4D__INCLUDED_)
#define AFX_WGCICREATE_H__2E1B4740_BA2D_11D2_8DBF_0080C7083D4D__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000
// WgciCreate.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// WgciCreate dialog

class WgciCreate : public CDialog
{
// Construction
public:
	WgciCreate(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(WgciCreate)
	enum { IDD = IDD_WGCI_CREATE };
	UINT	m_bits;
	UINT	m_hours;
	CString	m_subject;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(WgciCreate)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(WgciCreate)
		// NOTE: the ClassWizard will add member functions here
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_WGCICREATE_H__2E1B4740_BA2D_11D2_8DBF_0080C7083D4D__INCLUDED_)
