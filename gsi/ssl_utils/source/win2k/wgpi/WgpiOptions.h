#if !defined(AFX_WGPIOPTIONS_H__1588E8C0_B15B_11D2_8DBF_A73FC48C5A40__INCLUDED_)
#define AFX_WGPIOPTIONS_H__1588E8C0_B15B_11D2_8DBF_A73FC48C5A40__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000
// WgpiOptions.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// WgpiOptions dialog

class WgpiOptions : public CDialog
{
// Construction
public:
	WgpiOptions(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(WgpiOptions)
	enum { IDD = IDD_WGCI_OPT };
	CString	Wgpi_opt_cert;
	CString	Wgpi_opt_key;
	CString	Wgpi_opt_proxy;
	CString	Wgpi_opt_certdir;
	CString Wgpi_opt_pkcs11dll;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(WgpiOptions)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(WgpiOptions)
	afx_msg void OnWgciOptCertB();
	afx_msg void OnWgciOptCertdirB();
	afx_msg void OnWgciOptKeyB();
	afx_msg void OnWgciOptProxyB();
	afx_msg void OnWgciOptPkcs11dllB();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_WGPIOPTIONS_H__1588E8C0_B15B_11D2_8DBF_A73FC48C5A40__INCLUDED_)
