// WgpiOptions.cpp : implementation file
//

#include "stdafx.h"
#include "wgpi.h"
#include "WgpiOptions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// WgpiOptions dialog


WgpiOptions::WgpiOptions(CWnd* pParent /*=NULL*/)
	: CDialog(WgpiOptions::IDD, pParent)
{
	//{{AFX_DATA_INIT(WgpiOptions)
	Wgpi_opt_cert = _T("");
	Wgpi_opt_key = _T("");
	Wgpi_opt_proxy = _T("");
	Wgpi_opt_certdir = _T("");
	Wgpi_opt_pkcs11dll = _T(" ");
	//}}AFX_DATA_INIT
}


void WgpiOptions::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(WgpiOptions)
	DDX_Text(pDX, IDC_WGCI_OPT_CERT, Wgpi_opt_cert);
	DDX_Text(pDX, IDC_WGCI_OPT_KEY, Wgpi_opt_key);
	DDX_Text(pDX, IDC_WGCI_OPT_PROXY, Wgpi_opt_proxy);
	DDX_Text(pDX, IDC_WGCI_OPT_CERTDIR, Wgpi_opt_certdir);
	DDX_Text(pDX, IDC_WGCI_OPT_PKCS11DLL, Wgpi_opt_pkcs11dll);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(WgpiOptions, CDialog)
	//{{AFX_MSG_MAP(WgpiOptions)
	ON_BN_CLICKED(IDC_WGCI_OPT_CERT_B, OnWgciOptCertB)
	ON_BN_CLICKED(IDC_WGCI_OPT_CERTDIR_B, OnWgciOptCertdirB)
	ON_BN_CLICKED(IDC_WGCI_OPT_KEY_B, OnWgciOptKeyB)
	ON_BN_CLICKED(IDC_WGCI_OPT_PROXY_B, OnWgciOptProxyB)
	ON_BN_CLICKED(IDC_WGCI_OPT_PKCS11DLL_B, OnWgciOptPkcs11dllB)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// WgpiOptions message handlers

void WgpiOptions::OnWgciOptCertB() 
{
	// TODO: Add your control notification handler code here

	CFileDialog fdlg(TRUE,NULL,Wgpi_opt_cert,
			OFN_FILEMUSTEXIST | OFN_HIDEREADONLY,
			"Pem Files (*.pem)|*.pem|All Files (*.*)|*.*|");

	fdlg.m_ofn.lpstrTitle = "Certificate File";
	int nResult = fdlg.DoModal();

	if (nResult == IDOK) {
		Wgpi_opt_cert = fdlg.GetPathName();
		UpdateData(TRUE);
	}
}

void WgpiOptions::OnWgciOptCertdirB() 
{
	// TODO: Add your control notification handler code here
	CFileDialog fdlg(TRUE,NULL,Wgpi_opt_certdir,
			OFN_PATHMUSTEXIST | OFN_HIDEREADONLY,"Directories|*.*|");

	fdlg.m_ofn.lpstrTitle = "Trusted Certificate Direcrory";
	int nResult = fdlg.DoModal();

	if (nResult == IDOK) {
		Wgpi_opt_certdir = fdlg.GetPathName();
		UpdateData(TRUE);
	}
}

void WgpiOptions::OnWgciOptKeyB() 
{
	// TODO: Add your control notification handler code here
	CFileDialog fdlg(TRUE,NULL,Wgpi_opt_key,
			OFN_FILEMUSTEXIST | OFN_HIDEREADONLY,
			"Pem Files(*.pem)|*.pem|All Files (*.*)|*.*|");

	fdlg.m_ofn.lpstrTitle = "Private Key File";
	int nResult = fdlg.DoModal();

	if (nResult == IDOK) {
		Wgpi_opt_key = fdlg.GetPathName();
		UpdateData(TRUE);
	}
}

void WgpiOptions::OnWgciOptProxyB() 
{
	// TODO: Add your control notification handler code here
	
	CFileDialog fdlg(TRUE,NULL,Wgpi_opt_proxy,
			OFN_PATHMUSTEXIST | OFN_HIDEREADONLY,
			"Proxy Files (x509*.*)|x509*.*|All Files (*.*)|*.*|");

	fdlg.m_ofn.lpstrTitle = "Proxy File";
	int nResult = fdlg.DoModal();

	if (nResult == IDOK) {
		Wgpi_opt_proxy = fdlg.GetPathName();
		UpdateData(FALSE);
	}
}

void WgpiOptions::OnWgciOptPkcs11dllB() 
{
	// TODO: Add your control notification handler code here

	CFileDialog fdlg(TRUE,NULL,Wgpi_opt_pkcs11dll,
			OFN_PATHMUSTEXIST | OFN_HIDEREADONLY,
			"DLLs (.dll)|*.dll|All Files (*.*)|*.*|");

	fdlg.m_ofn.lpstrTitle = "PKCS#11 Security Module:";
	int nResult = fdlg.DoModal();

	if (nResult == IDOK) {
		Wgpi_opt_pkcs11dll = fdlg.GetPathName();
		UpdateData(FALSE);
	}
}
