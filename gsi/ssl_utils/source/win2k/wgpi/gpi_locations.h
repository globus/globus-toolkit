#if !defined(AFX_GPI_LOCATIONS_H__D90645EE_B151_11D2_8DBF_D1B78357C555__INCLUDED_)
#define AFX_GPI_LOCATIONS_H__D90645EE_B151_11D2_8DBF_D1B78357C555__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000
// gpi_locations.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// gpi_locations dialog

class gpi_locations : public CDialog
{
// Construction
public:
	gpi_locations(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(gpi_locations)
	enum { IDD = _UNKNOWN_RESOURCE_ID_ };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(gpi_locations)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(gpi_locations)
		// NOTE: the ClassWizard will add member functions here
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_GPI_LOCATIONS_H__D90645EE_B151_11D2_8DBF_D1B78357C555__INCLUDED_)
