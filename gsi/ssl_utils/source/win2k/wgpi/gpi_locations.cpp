// gpi_locations.cpp : implementation file
//

#include "stdafx.h"
#include "wgpi.h"
#include "gpi_locations.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// gpi_locations dialog


gpi_locations::gpi_locations(CWnd* pParent /*=NULL*/)
	: CDialog(gpi_locations::IDD, pParent)
{
	//{{AFX_DATA_INIT(gpi_locations)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}


void gpi_locations::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(gpi_locations)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(gpi_locations, CDialog)
	//{{AFX_MSG_MAP(gpi_locations)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// gpi_locations message handlers
