// WgpiView.cpp : implementation file
//

#include "stdafx.h"
#include "wgpi.h"
#include "WgpiView.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// WgpiView dialog


WgpiView::WgpiView(CWnd* pParent /*=NULL*/)
	: CDialog(WgpiView::IDD, pParent)
{
	//{{AFX_DATA_INIT(WgpiView)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}


void WgpiView::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(WgpiView)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(WgpiView, CDialog)
	//{{AFX_MSG_MAP(WgpiView)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// WgpiView message handlers
