// BookmarkProperties.cpp : implementation file
//

#include "stdafx.h"
#include "bmed.h"
#include "BookmarkProperties.h"
#include <Strn.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CBookmarkProperties dialog


CBookmarkProperties::CBookmarkProperties(BookmarkPtr bmp, CWnd* pParent /*=NULL*/)
	: CDialog(CBookmarkProperties::IDD, pParent)
{
	m_bmp = bmp;

	//{{AFX_DATA_INIT(CBookmarkProperties)
	m_account = _T("");
	m_bookmarkName = _T("");
	m_comment = _T("");
	m_hostName = _T("");
	m_localDir = _T("");
	m_password = _T("");
	m_portNumber = 0;
	m_remoteDir = _T("");
	m_user = _T("");
	m_typeBinary = -1;
	//}}AFX_DATA_INIT

	ASSERT(bmp->deleted == 0);

	m_account = bmp->acct;
	m_bookmarkName = bmp->bookmarkName;
	m_comment = bmp->comment;
	m_hostName = bmp->name;
	m_localDir = bmp->ldir;
	m_password = bmp->pass;
	m_portNumber = (UINT) bmp->port;
	m_remoteDir = bmp->dir;
	m_user = bmp->user;

	if (m_portNumber == 0)
		m_portNumber = 21;

	// This looks odd, but what we pass to DDX is 0 for the first
	// radio button (binary), or 1 for the second button (ASCII).
	//
	m_typeBinary = (bmp->xferType == 'A') ? 1 : 0;

	m_passwordWarning = FALSE;
}


void CBookmarkProperties::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CBookmarkProperties)
	DDX_Control(pDX, IDC_PASSWORD, m_passwordEdit);
	DDX_Text(pDX, IDC_ACCOUNT, m_account);
	DDV_MaxChars(pDX, m_account, 63);
	DDX_Text(pDX, IDC_BOOKMARK_NAME, m_bookmarkName);
	DDV_MaxChars(pDX, m_bookmarkName, 15);
	DDX_Text(pDX, IDC_COMMENT, m_comment);
	DDV_MaxChars(pDX, m_comment, 127);
	DDX_Text(pDX, IDC_HOSTNAME, m_hostName);
	DDV_MaxChars(pDX, m_hostName, 63);
	DDX_Text(pDX, IDC_LOCAL_DIR, m_localDir);
	DDV_MaxChars(pDX, m_localDir, 159);
	DDX_Text(pDX, IDC_PASSWORD, m_password);
	DDV_MaxChars(pDX, m_password, 63);
	DDX_Text(pDX, IDC_PORT, m_portNumber);
	DDV_MinMaxUInt(pDX, m_portNumber, 1, 65535);
	DDX_Text(pDX, IDC_REMOTE_DIR, m_remoteDir);
	DDV_MaxChars(pDX, m_remoteDir, 159);
	DDX_Text(pDX, IDC_USER, m_user);
	DDV_MaxChars(pDX, m_user, 63);
	DDX_Radio(pDX, IDC_BINARY, m_typeBinary);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CBookmarkProperties, CDialog)
	//{{AFX_MSG_MAP(CBookmarkProperties)
	ON_EN_CHANGE(IDC_USER, OnChangeUser)
	ON_EN_KILLFOCUS(IDC_PASSWORD, OnKillfocusPassword)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CBookmarkProperties message handlers


void CBookmarkProperties::EnablePasswordFieldAccordingToUserField(CString &user)
{
	if ((user.IsEmpty() == FALSE) && (user != "anonymous") && (user != "ftp"))
		m_passwordEdit.EnableWindow(TRUE);
	else
		m_passwordEdit.EnableWindow(FALSE);
}	// EnablePasswordFieldAccordingToUserField




BOOL CBookmarkProperties::OnInitDialog() 
{
	CDialog::OnInitDialog();

	EnablePasswordFieldAccordingToUserField(m_user);
	
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}	// OnInitDialog




void CBookmarkProperties::OnChangeUser() 
{
	CString user;

	GetDlgItemText(IDC_USER, user);
	EnablePasswordFieldAccordingToUserField(user);
}	// OnChangeUser




void CBookmarkProperties::OnKillfocusPassword() 
{
	CString pass, user;
	
	if (m_passwordWarning == FALSE) {
		GetDlgItemText(IDC_USER, user);
		GetDlgItemText(IDC_PASSWORD, pass);
		
		if ((user.IsEmpty() == FALSE) && (user != "anonymous") && (user != "ftp") && (pass.IsEmpty() == FALSE)) {
			m_passwordWarning = TRUE;
			AfxMessageBox("Warning: You have entered a password for a non-anonymous user account.  This password will be stored in plain-text on disk -- leave the password field blank for better security.  NcFTP will prompt you when it needs a password, so there is no need to store your password.");
		}
	}
}	// OnKillfocusPassword




void CBookmarkProperties::OnOK() 
{
	CDialog::OnOK();

	BookmarkPtr bmp = m_bmp;

	if ((m_user == "anonymous") || (m_user == "ftp"))
		m_user.Empty();

	STRNCPY(bmp->acct, (LPCSTR) m_account);
	STRNCPY(bmp->bookmarkName, (LPCSTR) m_bookmarkName);
	STRNCPY(bmp->comment, (LPCSTR) m_comment);
	STRNCPY(bmp->name, (LPCSTR) m_hostName);
	STRNCPY(bmp->ldir, (LPCSTR) m_localDir);
	STRNCPY(bmp->pass, (LPCSTR) m_password);
	bmp->port = (unsigned short) m_portNumber;
	STRNCPY(bmp->dir, (LPCSTR) m_remoteDir);
	STRNCPY(bmp->user, (LPCSTR) m_user);
	bmp->xferType = (m_typeBinary == 1) ? 'A' : 'I';

	// Whenever the record could be changed, purge
	// the (pretty much worthless) last IP address
	// field, in case the hostname is different.
	//
	bmp->lastIP[0] = 0;

	if (m_portNumber == 21)
		bmp->port = 0;
}	// OnOK
