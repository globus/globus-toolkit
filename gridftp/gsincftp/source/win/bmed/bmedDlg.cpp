// bmedDlg.cpp : implementation file
//

#include "stdafx.h"
#include "bmed.h"
#include "bmedDlg.h"
#include "BookmarkProperties.h"
#include <Strn.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CBmedDlg dialog

CBmedDlg::CBmedDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CBmedDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CBmedDlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CBmedDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CBmedDlg)
	DDX_Control(pDX, IDC_DUPLICATE, m_buttDuplicate);
	DDX_Control(pDX, IDC_NEW, m_buttNew);
	DDX_Control(pDX, IDC_EDIT, m_buttEdit);
	DDX_Control(pDX, IDC_DELETE, m_buttDelete);
	DDX_Control(pDX, IDC_CONNECT, m_buttConnect);
	DDX_Control(pDX, IDC_CLOSE, m_buttClose);
	DDX_Control(pDX, IDC_BOOKMARK_LIST, m_bookmarkListCtrl);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CBmedDlg, CDialog)
	//{{AFX_MSG_MAP(CBmedDlg)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_CLOSE, OnClose)
	ON_NOTIFY(NM_CLICK, IDC_BOOKMARK_LIST, OnClickBookmarkList)
	ON_BN_CLICKED(IDC_CONNECT, OnConnect)
	ON_BN_CLICKED(IDC_EDIT, OnEdit)
	ON_BN_CLICKED(IDC_DELETE, OnDelete)
	ON_BN_CLICKED(IDC_NEW, OnNew)
	ON_NOTIFY(NM_DBLCLK, IDC_BOOKMARK_LIST, OnDblclkBookmarkList)
	ON_BN_CLICKED(IDC_DUPLICATE, OnDuplicate)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

extern "C" {
	extern int gNumBookmarks;
	extern BookmarkPtr gBookmarkTable;
}

/////////////////////////////////////////////////////////////////////////////
// CBmedDlg message handlers

void CBmedDlg::LoadBookmarkCtrl(void)
{
	int i;
	BookmarkPtr bmp;
	char url[256];

	bmp = gBookmarkTable;
	for (i=0; i<gNumBookmarks; i++, bmp++) {
		if (gBookmarkTable[i].deleted == 0) {
			m_bookmarkListCtrl.InsertItem(i, bmp->bookmarkName);
			BookmarkToURL(bmp, url, sizeof(url));
			m_bookmarkListCtrl.SetItemText(i, 1, url);
			m_bookmarkListCtrl.SetItemData(i, i);
		}
	}
}	// LoadBookmarkCtrl




BOOL CBmedDlg::OnInitDialog()
{
	CRect r;
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	m_bookmarkListCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	m_bookmarkListCtrl.InsertColumn(0, "Abbreviation", LVCFMT_LEFT, 100);
	m_bookmarkListCtrl.GetClientRect(&r);
	m_bookmarkListCtrl.InsertColumn(1, "URL", LVCFMT_LEFT, r.Width() - 100);
	LoadBookmarkCtrl();

	m_bookmarkListCtrl.SetFocus();
	if (gNumBookmarks <= 0) {
		EnableButtons(FALSE);
	} else {
		EnableButtons(TRUE);
		m_bookmarkListCtrl.SetItemState(0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
	}

	return FALSE;  // return TRUE  unless you set the focus to a control
}	// OnInitDialog




// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CBmedDlg::OnPaint() 
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
}	// OnPaint




// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CBmedDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}	// OnQueryDragIcon




void CBmedDlg::EnableButtons(BOOL bEnable)
{
	if (bEnable) {
		m_buttConnect.EnableWindow(TRUE);
		m_buttEdit.EnableWindow(TRUE);
		m_buttDelete.EnableWindow(TRUE);
		m_buttDuplicate.EnableWindow(TRUE);
	} else {
		m_buttConnect.EnableWindow(FALSE);
		m_buttEdit.EnableWindow(FALSE);
		m_buttDelete.EnableWindow(FALSE);
		m_buttDuplicate.EnableWindow(FALSE);
	}
}	// EnableButtons





void CBmedDlg::OnConnect() 
{
	int i, li = m_bookmarkListCtrl.GetNextItem(-1, LVNI_ALL | LVNI_SELECTED);
	BookmarkPtr bmp;

	ASSERT(li >= 0);
	if (li < 0)
		return;

	i = (int) m_bookmarkListCtrl.GetItemData(li);
	ASSERT((i >= 0) && (i < gNumBookmarks));
	bmp = gBookmarkTable + i;
	theApp.SetSelectedBookmark(bmp->bookmarkName);

	CDialog::OnOK();
}	// OnConnect




void CBmedDlg::OnEdit() 
{
	int i, li = m_bookmarkListCtrl.GetNextItem(-1, LVNI_ALL | LVNI_SELECTED);
	BookmarkPtr bmp;
	char url[256];

	ASSERT(li >= 0);
	if (li < 0)
		return;

	i = (int) m_bookmarkListCtrl.GetItemData(li);
	ASSERT((i >= 0) && (i < gNumBookmarks));
	bmp = gBookmarkTable + i;
	
	CBookmarkProperties dlg(bmp);

	if (dlg.DoModal() == IDOK) {
		BookmarkToURL(bmp, url, sizeof(url));
		m_bookmarkListCtrl.SetItemText(li, 0, bmp->bookmarkName);
		m_bookmarkListCtrl.SetItemText(li, 1, url);
		theApp.SetDirty();
	}
}	// OnEdit




void CBmedDlg::OnDelete() 
{
	int i, li = m_bookmarkListCtrl.GetNextItem(-1, LVNI_ALL | LVNI_SELECTED);

	ASSERT(li >= 0);
	if (li < 0)
		return;

	i = (int) m_bookmarkListCtrl.GetItemData(li);
	ASSERT((i >= 0) && (i < gNumBookmarks));
	gBookmarkTable[i].deleted = 1;
	m_bookmarkListCtrl.DeleteItem(li);

	theApp.SetDirty();
}	// OnDelete




void CBmedDlg::OnNew() 
{
	int nb, i, li;
	BookmarkPtr bmp;

	// Insert a new item near the currently selected bookmark,
	// if possible.  It seems to be difficult to manage the
	// list control's scrolling behavior, so we don't want to
	// screw around with trying to scroll the listview to the
	// location of the new bookmark if possible.
	//
	nb = m_bookmarkListCtrl.GetItemCount();
	li = m_bookmarkListCtrl.GetNextItem(-1, LVNI_ALL | LVNI_SELECTED);
	if (li < 0)
		li = nb;

	i = AddNewItemToBookmarkTable();
	if (i >= 0) {
		bmp = &gBookmarkTable[i];
		SetBookmarkDefaults(bmp);
		strcpy(bmp->bookmarkName, "NewBookmark");
		m_bookmarkListCtrl.InsertItem(li, bmp->bookmarkName);
		m_bookmarkListCtrl.SetItemData(li, (DWORD) i);
		m_bookmarkListCtrl.SetItemState(li, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);

		theApp.SetDirty();

		OnEdit();
	}
}	// OnNew




void CBmedDlg::OnDuplicate() 
{
	int i, li = m_bookmarkListCtrl.GetNextItem(-1, LVNI_ALL | LVNI_SELECTED);
	BookmarkPtr bmpToDupe, bmp;
	char url[256];

	ASSERT(li >= 0);
	if (li < 0)
		return;

	i = (int) m_bookmarkListCtrl.GetItemData(li);
	ASSERT((i >= 0) && (i < gNumBookmarks));
	bmpToDupe = gBookmarkTable + i;
	
	i = AddNewItemToBookmarkTable();
	if (i >= 0) {
		bmp = &gBookmarkTable[i];
		memcpy(bmp, bmpToDupe, sizeof(Bookmark));
		STRNCPY(bmp->bookmarkName, bmpToDupe->bookmarkName);
		STRNCAT(bmp->bookmarkName, "Copy");
		m_bookmarkListCtrl.InsertItem(li, bmp->bookmarkName);
		BookmarkToURL(bmp, url, sizeof(url));
		m_bookmarkListCtrl.SetItemText(li, 1, url);
		m_bookmarkListCtrl.SetItemData(li, (DWORD) i);
		m_bookmarkListCtrl.SetItemState(li, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);

		theApp.SetDirty();
	}
}	// OnDuplicate




void CBmedDlg::OnClose() 
{
	CDialog::OnOK();
}	// OnClose




void CBmedDlg::OnDblclkBookmarkList(NMHDR* pNMHDR, LRESULT* pResult) 
{
	int i = m_bookmarkListCtrl.GetNextItem(-1, LVNI_ALL | LVNI_SELECTED);

	if (i >= 0)
		OnConnect();
	
	*pResult = 0;
}	// OnDblclkBookmarkList




void CBmedDlg::OnClickBookmarkList(NMHDR* pNMHDR, LRESULT* pResult) 
{
	int i = m_bookmarkListCtrl.GetNextItem(-1, LVNI_ALL | LVNI_SELECTED);
	if (i >= 0) {
		// At least one item is selected.
		//
		EnableButtons(TRUE);
	} else {
		// No item is selected.
		//
		EnableButtons(FALSE);
	}

	*pResult = 0;
}	// OnClickBookmarkList
