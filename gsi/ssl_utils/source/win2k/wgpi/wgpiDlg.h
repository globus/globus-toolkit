// wgpiDlg.h : header file
//

#if !defined(AFX_WGPIDLG_H__D90645E6_B151_11D2_8DBF_D1B78357C555__INCLUDED_)
#define AFX_WGPIDLG_H__D90645E6_B151_11D2_8DBF_D1B78357C555__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000

/////////////////////////////////////////////////////////////////////////////
// CWgpiDlg dialog

class CWgpiDlg : public CDialog
{
// Construction
public:
	CWgpiDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CWgpiDlg)
	enum { IDD = IDD_WGPI_DIALOG };
//???	CButton	Wgci_options;
	CString	Wgpi_subject;
	CString	Wgpi_before_time;
	CString	Wgpi_after_time;
	//}}AFX_DATA


	//MY DATA
	CString x509_user_cert;
	CString x509_user_key;
	CString x509_cert_dir;
	CString x509_user_proxy;
	CString x509_pkcs11dll;


	BOOL RefreshProxyInfo();
	BOOL RefreshFileNames();


	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CWgpiDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CWgpiDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnWgpiOptionButton();
	afx_msg void OnWgpiViewButton();
	afx_msg void OnWgciDestroyButton();
	afx_msg void OnWgpiCreateBotton();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_WGPIDLG_H__D90645E6_B151_11D2_8DBF_D1B78357C555__INCLUDED_)
