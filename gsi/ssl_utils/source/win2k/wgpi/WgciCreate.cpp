// WgciCreate.cpp : implementation file
//

#include "stdafx.h"
#include "wgpi.h"
#include "WgciCreate.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// WgciCreate dialog


WgciCreate::WgciCreate(CWnd* pParent /*=NULL*/)
	: CDialog(WgciCreate::IDD, pParent)
{
	//{{AFX_DATA_INIT(WgciCreate)
	m_bits = 0;
	m_hours = 0;
	m_subject = _T("");
	//}}AFX_DATA_INIT
}


void WgciCreate::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(WgciCreate)
	DDX_Text(pDX, IDC_CREATE_BITS, m_bits);
	DDV_MinMaxUInt(pDX, m_bits, 512, 4096);
	DDX_Text(pDX, IDC_CREATE_HOURS, m_hours);
	DDV_MinMaxUInt(pDX, m_hours, 1, 9999999);
	DDX_Text(pDX, IDC_CREATE_SUBJECT, m_subject);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(WgciCreate, CDialog)
	//{{AFX_MSG_MAP(WgciCreate)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// WgciCreate message handlers
