#if !defined(AFX_BOOKMARKPROPERTIES_H__B7BD0963_7419_11D3_9CCB_00400543CD04__INCLUDED_)
#define AFX_BOOKMARKPROPERTIES_H__B7BD0963_7419_11D3_9CCB_00400543CD04__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// BookmarkProperties.h : header file
//

#include "bookmark.h"

/////////////////////////////////////////////////////////////////////////////
// CBookmarkProperties dialog

class CBookmarkProperties : public CDialog
{
// Construction
public:
	CBookmarkProperties(BookmarkPtr bmp, CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CBookmarkProperties)
	enum { IDD = IDD_BOOKMARK_PROPERTIES };
	CEdit	m_passwordEdit;
	CString	m_account;
	CString	m_bookmarkName;
	CString	m_comment;
	CString	m_hostName;
	CString	m_localDir;
	CString	m_password;
	UINT	m_portNumber;
	CString	m_remoteDir;
	CString	m_user;
	int		m_typeBinary;
	//}}AFX_DATA

protected:
	BookmarkPtr m_bmp;
	BOOL m_passwordWarning;


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CBookmarkProperties)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	void EnablePasswordFieldAccordingToUserField(CString &user);

	// Generated message map functions
	//{{AFX_MSG(CBookmarkProperties)
	virtual void OnOK();
	afx_msg void OnChangeUser();
	virtual BOOL OnInitDialog();
	afx_msg void OnKillfocusPassword();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_BOOKMARKPROPERTIES_H__B7BD0963_7419_11D3_9CCB_00400543CD04__INCLUDED_)
