// wgpiDlg.cpp : implementation file
//

#include "stdafx.h"
#include "wgpi.h"
#include "wgpiDlg.h"
#include  "WgpiOptions.h"
#include  "WgciCreate.h"

#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <time.h>

extern "C" {
#include "x509.h"
#include "pem.h"
#include "evp.h"
#include "asn1.h"
#include "buffer.h"
#include "crypto.h"
#include "rsa.h"
#include "sslutils.h"
#include "winglue.h"
}


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CWgpiDlg dialog

CWgpiDlg::CWgpiDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CWgpiDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CWgpiDlg)
	Wgpi_subject = _T("Starting");
	Wgpi_before_time = _T("Before");
	Wgpi_after_time = _T("After");
	//}}AFX_DATA_INIT


	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	//My Data	

	x509_user_cert = _T("Enter cert file name");
	x509_user_key = _T("Enter key filename");
	x509_user_proxy = _T("Enter Proxy file name i.e. c:\\windows\\x509up_user");
	x509_cert_dir = _T("Enter trusted cert dir");
	x509_pkcs11dll = _T("Enter PKCS#11 Security Modulr Name");

}

void CWgpiDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CWgpiDlg)
//???	DDX_Control(pDX, IDOPTIONS, Wgci_options);
	DDX_Text(pDX, ID_WGPI_SUBJECT, Wgpi_subject);
	DDX_Text(pDX, IDC_WGPI_BEFORE_TIME, Wgpi_before_time);
	DDX_Text(pDX, IDC_WGPI_AFTER_TIME, Wgpi_after_time);
	//}}AFX_DATA_MAP
}	

BEGIN_MESSAGE_MAP(CWgpiDlg, CDialog)
	//{{AFX_MSG_MAP(CWgpiDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ID_WGPI_OPTION_BUTTON, OnWgpiOptionButton)
	ON_BN_CLICKED(ID_WGPI_VIEW_BUTTON, OnWgpiViewButton)
	ON_BN_CLICKED(ID_WGCI_DESTROY_BUTTON, OnWgciDestroyButton)
	ON_BN_CLICKED(ID_WGPI_CREATE_BOTTON, OnWgpiCreateBotton)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CWgpiDlg message handlers

BOOL CWgpiDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

//DEE	CEdit *pEdit = GetDlgItem(ID_WGPI_SUBJECT);
	
	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	// TODO: Add extra initialization here

	RefreshProxyInfo();
	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CWgpiDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CWgpiDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CWgpiDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CWgpiDlg::OnWgpiOptionButton() 
{
	WgpiOptions dlg;
	// TODO: Add your control notification handler code here
	int nResponse = 0;

	dlg.Wgpi_opt_cert = x509_user_cert;
	dlg.Wgpi_opt_key  = x509_user_key;
	dlg.Wgpi_opt_proxy = x509_user_proxy;
	dlg.Wgpi_opt_certdir = x509_cert_dir;
	dlg.Wgpi_opt_pkcs11dll = x509_pkcs11dll;


	nResponse = dlg.DoModal();
	if (nResponse == IDOK)

	{
		HKEY hkDir = NULL;
		HKEY hkData = NULL;


		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
		// if userchaged any, add to registry
		// need checkst to say it is not changeable,
		// i.e. its in the enviornment
		//

		if (RegCreateKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir)
			== ERROR_SUCCESS) {
			
			if (x509_user_cert != dlg.Wgpi_opt_cert) {
				if (RegSetValueEx(hkDir,"x509_user_cert",0, REG_SZ,
						(const unsigned char *)(const char *)dlg.Wgpi_opt_cert,
						strlen(dlg.Wgpi_opt_cert)) == ERROR_SUCCESS) {
					x509_user_cert = dlg.Wgpi_opt_cert;
				}
			}

			if (x509_user_key  != dlg.Wgpi_opt_key) {
				if (RegSetValueEx(hkDir,"x509_user_key",0, REG_SZ,
						(const unsigned char *)(const char *)dlg.Wgpi_opt_key,
						strlen(dlg.Wgpi_opt_key)) == ERROR_SUCCESS) {
					x509_user_key = dlg.Wgpi_opt_key;
				}

			}
			if (x509_user_proxy != dlg.Wgpi_opt_proxy) {
				if (RegSetValueEx(hkDir,"x509_user_proxy",0,REG_SZ,
					 (const unsigned char*)(const char *)dlg.Wgpi_opt_proxy,
					 strlen(dlg.Wgpi_opt_proxy)) == ERROR_SUCCESS) {
					x509_user_proxy = dlg.Wgpi_opt_proxy;
				}


			}
			if (x509_cert_dir != dlg.Wgpi_opt_certdir) {
				if (RegSetValueEx(hkDir,"x509_cert_dir",0,REG_SZ,
						(const unsigned char *)(const char *)dlg.Wgpi_opt_certdir,
						strlen(dlg.Wgpi_opt_certdir)) == ERROR_SUCCESS) {
					x509_cert_dir = dlg.Wgpi_opt_certdir;
				}

			}
			if (x509_pkcs11dll != dlg.Wgpi_opt_pkcs11dll) {
				if (RegSetValueEx(hkDir,"PKCS11.DLL",0,REG_SZ,
						(const unsigned char *)(const char *)dlg.Wgpi_opt_pkcs11dll,
						strlen(dlg.Wgpi_opt_pkcs11dll)) == ERROR_SUCCESS) {
					x509_pkcs11dll = dlg.Wgpi_opt_pkcs11dll;
				}

			}

			RegCloseKey(hkDir);
		}
		RefreshProxyInfo();

	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}

}

void CWgpiDlg::OnWgpiViewButton() 
{
	// TODO: Add your control notification handler code here
	//MY DATA
	//for now ust show some variables

	::MessageBox(0,x509_user_cert,"x509_user_cert",IDOK);
	::MessageBox(0,x509_user_key, "x509_user_key",IDOK);
	::MessageBox(0,x509_user_proxy,"x509_user_proxy",IDOK);
	::MessageBox(0,x509_cert_dir, "x509_cert_dir", IDOK);
}

void CWgpiDlg::OnWgciDestroyButton() 
{
	// TODO: Add your control notification handler code here


	int f;
	int rec;
	int left;
	long size;
	char msg[65] = "Destroyed by globus_proxy_destroy\r\n";

	RefreshFileNames();


	f=open(x509_user_proxy,O_RDWR);
	if (f) {
		size = lseek(f,0L,SEEK_END);
		lseek(f,0L,SEEK_SET);
		if (size> 0) {
                       
			rec = size/64;
			left = size - rec*64;
			while (rec) {
				write(f,msg,64);
				rec--;
			}
			if (left) {
				write(f,msg,left);
			}
		}
		close(f);
	}

	remove(x509_user_proxy);
	RefreshProxyInfo();
}


void CWgpiDlg::OnWgpiCreateBotton() 
{
	WgciCreate dlg;
	int hours;
	int bits;
	char * s = NULL;
	char *cp, *pp;
	int nResponse = 0;
	proxy_cred_desc *pcd;
	HCURSOR cur_old;
	HCURSOR cur_wait;

	dlg.m_hours = 8;
	dlg.m_bits = 512;
	pcd = proxy_cred_desc_new();

	RefreshFileNames();	
	if (proxy_load_user_cert(pcd, x509_user_cert,NULL, NULL)) {
			ERR_print_errors_MessageBox(0,"Create - Load Cert");
			goto err;
	}

	s = X509_NAME_oneline(X509_get_subject_name(pcd->ucert),NULL,0);
	dlg.m_subject = _T("");	
	cp = s + 1;
	pp = s;
	while (*cp != '\0') {
		if (*cp == '/') {
			*cp = '\0';
			dlg.m_subject += pp;
			*cp = '/';
			dlg.m_subject += '\015';
			dlg.m_subject += '\012';
			pp = cp; 
		}
		cp++;
	}
	dlg.m_subject += pp;



//	dlg.UpdateData(TRUE);
	// TODO: Add your control notification handler code here
	nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
//		dlg->UpdateData(FALSE);
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
		hours = dlg.m_hours;
		bits = dlg.m_bits;
		// need check if 512, 1024, 2048 
		if (proxy_load_user_key(pcd, x509_user_key,	NULL, NULL)) {
			ERR_print_errors_MessageBox(0,"Create - Load Key");
		} else {
			cur_wait = LoadCursor(NULL, IDC_WAIT);
			cur_old = SetCursor(cur_wait);
			//Yield();  /* this may take awhile */
			if (proxy_create_local(pcd,
					x509_user_proxy,
					hours,
					bits,
					0,      /*limited_proxy */
					NULL, /*int (*kpcallback)()*/ 
					NULL,
					0 ) ){
			    SetCursor(cur_old);
				ERR_print_errors_MessageBox(0,"Create");
			}	
			SetCursor(cur_old);
		}	
		RefreshProxyInfo();

	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}
	
err:
	if (s) {
		free(s);
	}
	proxy_cred_desc_free(pcd);

}
BOOL CWgpiDlg::RefreshFileNames()
{
	HKEY hkDir = NULL;
	ULONG lval;
	DWORD type;
	char * user_cert = NULL;
	char * user_key = NULL;
	char * user_proxy = NULL;
	char * cert_dir = NULL;
	unsigned char val_pkcs11dll[1024] = "";

	if (proxy_get_filenames(0,NULL, &cert_dir, &user_proxy,
		&user_cert, &user_key)) {
		::MessageBox(0,"One or more of the files are not valid, use the Options button to correct.",
			"ReFreshFileNames", IDOK);
	}
	if (user_proxy) {
			x509_user_proxy = user_proxy;
			free(user_proxy);
	}
	if (user_cert) {
		x509_user_cert = user_cert;
		free(user_cert);
	}
	if (user_key) {
		x509_user_key = user_key;
		free(user_key);
	}
	if (cert_dir) {
		x509_cert_dir = cert_dir;
		free(cert_dir);
	}

	RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
	
	lval = sizeof(val_pkcs11dll)-1;
	if (hkDir && (RegQueryValueEx(hkDir,"PKCS11.DLL",0,&type,
		val_pkcs11dll,&lval) == ERROR_SUCCESS)) {
		x509_pkcs11dll = val_pkcs11dll;
	}

	if (hkDir) {
		RegCloseKey(hkDir);
	}

	return TRUE;

}

BOOL CWgpiDlg::RefreshProxyInfo()
{
	// open the proxy file, get subject and times
	// If failure, sst subject to NONE, or NOT FOUND
	X509 *ucert = NULL;
	FILE *fp = NULL;
	char *ss = NULL;
	char *cp, *pp;
	time_t xtime;
	struct tm *xtm;
	char beforet[26];
	char aftert[26];

		
//	::MessageBox(0,x509_user_proxy,"ReFreshProxyInfo - file:", IDOK);

	RefreshFileNames();

	fp = fopen (x509_user_proxy, "r");
	if (fp != NULL) {
//		::MessageBox(0,"File opened","ReFreshProxyInfo", IDOK);
		ucert = PEM_read_X509 (fp, NULL, OPENSSL_PEM_CB(NULL,NULL));
//		::MessageBox(0,"Cert read","ReFreshProxyInfo", IDOK);
		fclose (fp);
		if (ucert) {
			ss = X509_NAME_oneline(ucert->cert_info->subject,NULL,0);
			//			::MessageBox(0,ss,"ReFreshProxyInfo",IDOK);

			/*
			 * Want multiline to fint in window. Will replace
			 * the / with \n and start with second char 
			 */
			Wgpi_subject = _T(""); /* start with null */
			cp = ss + 1;
			pp = ss;
			while (*cp != '\0') {
				if (*cp == '/') {
					*cp = '\0';
					Wgpi_subject += pp;
					*cp = '/';
					Wgpi_subject += '\015';
					Wgpi_subject += '\012';
					pp = cp; 
				}
				cp++;
			}
			Wgpi_subject += pp;
			
			free(ss);


			xtime = ASN1_UTCTIME_mktime(X509_get_notBefore(ucert));
			xtm = localtime(&xtime);
			memcpy(beforet, asctime(xtm), 26);
			beforet[24] = '\0';
			Wgpi_before_time = beforet;
			

			xtime = ASN1_UTCTIME_mktime(X509_get_notAfter(ucert));
			if (xtime >= time(NULL)) {
				xtm = localtime(&xtime);
				memcpy(aftert, asctime(xtm), 26);
				aftert[24] = '\0';
			} else {
				strcpy(aftert,"   EXPIRED");
			}
			Wgpi_after_time = aftert;

			X509_free(ucert);
		} else {
//			::MessageBox(0,"UCert not read","ReFreshProxyInfo", IDOK);
			Wgpi_subject = _T("Unable to read");
			Wgpi_before_time = _T("");
			Wgpi_after_time = _T("");
		
		}
	} else {	
//		::MessageBox(0,"File not found","ReFreshProxyInfo", IDOK);
		Wgpi_subject = _T("Not found");
		Wgpi_before_time = _T("");
		Wgpi_after_time = _T("");

	}


	UpdateData(FALSE); /* Tell dialog the data has changed */


	return TRUE;
}


