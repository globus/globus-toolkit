// wgpi.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "wgpi.h"
#include "wgpiDlg.h"

//extern "C" {
#include "err.h"
#include "bio.h"
#include "ssl.h"
#include <malloc.h>
#include "sslutils.h"
#include "winglue.h"
//}

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CWgpiApp

BEGIN_MESSAGE_MAP(CWgpiApp, CWinApp)
	//{{AFX_MSG_MAP(CWgpiApp)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CWgpiApp construction

CWgpiApp::CWgpiApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CWgpiApp object

CWgpiApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CWgpiApp initialization

BOOL CWgpiApp::InitInstance()
{
	if (!AfxSocketInit())
	{
		AfxMessageBox(IDP_SOCKETS_INIT_FAILED);
		return FALSE;
	}

	AfxEnableControlContainer();

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	//  of your final executable, you should remove from the following
	//  the specific initialization routines you do not need.

#ifdef _AFXDLL
	Enable3dControls();			// Call this when using MFC in a shared DLL
#else
	Enable3dControlsStatic();	// Call this when linking to MFC statically
#endif


	CRYPTO_malloc_init();
	
	ERR_load_prxyerr_strings(0);
	
	SSLeay_add_ssl_algorithms();

//	save_instance(AfxGetInstanceHandle());

// ::MessageBox(0,"loaded strings","INIT",IDOK);

//	if ((bio_err=BIO_new(BIO_s_file())) != NULL) {
//        BIO_set_fp(bio_err,stderr,BIO_NOCLOSE);
//	}
	

	CWgpiDlg dlg;
	m_pMainWnd = &dlg;

	int nResponse = dlg.DoModal();
	if (nResponse == IDOK)

	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	//	Nothing to do.
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
		//Nothing to do, don't have a cancel button.
	}

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}
