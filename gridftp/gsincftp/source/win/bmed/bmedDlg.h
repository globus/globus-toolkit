// bmedDlg.h : header file
//

#if !defined(AFX_BMEDDLG_H__3C180D67_7355_11D3_9CCB_00400543CD04__INCLUDED_)
#define AFX_BMEDDLG_H__3C180D67_7355_11D3_9CCB_00400543CD04__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CBmedDlg dialog

class CBmedDlg : public CDialog
{
// Construction
public:
	CBmedDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CBmedDlg)
	enum { IDD = IDD_BMED_DIALOG };
	CButton	m_buttDuplicate;
	CButton	m_buttNew;
	CButton	m_buttEdit;
	CButton	m_buttDelete;
	CButton	m_buttConnect;
	CButton	m_buttClose;
	CListCtrl	m_bookmarkListCtrl;
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CBmedDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	void LoadBookmarkCtrl(void);
	void EnableButtons(BOOL bEnable);

	// Generated message map functions
	//{{AFX_MSG(CBmedDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnClose();
	afx_msg void OnClickBookmarkList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnConnect();
	afx_msg void OnEdit();
	afx_msg void OnDelete();
	afx_msg void OnNew();
	afx_msg void OnDblclkBookmarkList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnDuplicate();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_BMEDDLG_H__3C180D67_7355_11D3_9CCB_00400543CD04__INCLUDED_)
