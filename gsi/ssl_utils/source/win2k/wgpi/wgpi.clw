; CLW file contains information for the MFC ClassWizard

[General Info]
Version=1
LastClass=WgciCreate
LastTemplate=CDialog
NewFileInclude1=#include "stdafx.h"
NewFileInclude2=#include "wgpi.h"

ClassCount=7
Class1=CWgpiApp
Class2=CWgpiDlg
Class3=CAboutDlg

ResourceCount=6
Resource1=IDD_WGCI_CREATE
Resource2=IDR_MAINFRAME
Class4=gpi_locations
Resource3=IDD_ABOUTBOX
Class5=WgpiOptions
Resource4=IDD_DIALOG1
Class6=WgciCreate
Resource5=IDD_WGCI_OPT
Class7=WgpiView
Resource6=IDD_WGPI_DIALOG

[CLS:CWgpiApp]
Type=0
HeaderFile=wgpi.h
ImplementationFile=wgpi.cpp
Filter=N
LastObject=CWgpiApp

[CLS:CWgpiDlg]
Type=0
HeaderFile=wgpiDlg.h
ImplementationFile=wgpiDlg.cpp
Filter=D
LastObject=CWgpiDlg
BaseClass=CDialog
VirtualFilter=dWC

[CLS:CAboutDlg]
Type=0
HeaderFile=wgpiDlg.h
ImplementationFile=wgpiDlg.cpp
Filter=D

[DLG:IDD_ABOUTBOX]
Type=1
Class=CAboutDlg
ControlCount=4
Control1=IDC_STATIC,static,1342177283
Control2=IDC_STATIC,static,1342308480
Control3=IDC_STATIC,static,1342308352
Control4=IDOK,button,1342373889

[DLG:IDD_WGPI_DIALOG]
Type=1
Class=CWgpiDlg
ControlCount=12
Control1=IDOK,button,1342242817
Control2=IDC_STATIC,static,1342308352
Control3=ID_WGPI_CREATE_BOTTON,button,1342242816
Control4=ID_WGCI_DESTROY_BUTTON,button,1342242816
Control5=ID_WGPI_VIEW_BUTTON,button,1342242816
Control6=ID_WGPI_SUBJECT,edit,1350633668
Control7=IDC_WGPI_BEFORE_TIME,edit,1350633600
Control8=IDC_WGPI_AFTER_TIME,edit,1350633600
Control9=IDC_STATIC,static,1342308352
Control10=IDC_STATIC,static,1342308352
Control11=ID_WGPI_OPTION_BUTTON,button,1342242816
Control12=IDB_GLOBUS2,static,1342177294

[CLS:gpi_locations]
Type=0
HeaderFile=gpi_locations.h
ImplementationFile=gpi_locations.cpp
BaseClass=CDialog
Filter=D
LastObject=gpi_locations

[CLS:WgpiOptions]
Type=0
HeaderFile=WgpiOptions.h
ImplementationFile=WgpiOptions.cpp
BaseClass=CDialog
Filter=D
LastObject=IDC_WGCI_OPT_CERT_B
VirtualFilter=dWC

[DLG:IDD_WGCI_OPT]
Type=1
Class=WgpiOptions
ControlCount=14
Control1=IDOK,button,1342242817
Control2=IDCANCEL,button,1342242816
Control3=IDC_WGCI_OPT_CERT,edit,1350631552
Control4=IDC_WGCI_OPT_CERT_B,button,1342242816
Control5=IDC_STATIC,static,1342308352
Control6=IDC_WGCI_OPT_KEY,edit,1350631552
Control7=IDC_WGCI_OPT_KEY_B,button,1342242816
Control8=IDC_STATIC,static,1342308352
Control9=IDC_WGCI_OPT_PROXY,edit,1350631552
Control10=IDC_WGCI_OPT_PROXY_B,button,1342242816
Control11=IDC_STATIC,static,1342308352
Control12=IDC_WGCI_OPT_CERTDIR,edit,1350631552
Control13=IDC_WGCI_OPT_CERTDIR_B,button,1342242816
Control14=IDC_STATIC,static,1342308352

[DLG:IDD_WGCI_CREATE]
Type=1
Class=WgciCreate
ControlCount=8
Control1=IDOK,button,1342242817
Control2=IDCANCEL,button,1342242816
Control3=IDC_STATIC,static,1342308352
Control4=IDC_STATIC,static,1342308352
Control5=IDC_CREATE_HOURS,edit,1350643842
Control6=IDC_CREATE_BITS,edit,1350643842
Control7=IDC_CREATE_SUBJECT,edit,1350633668
Control8=IDC_STATIC,static,1342308352

[CLS:WgciCreate]
Type=0
HeaderFile=WgciCreate.h
ImplementationFile=WgciCreate.cpp
BaseClass=CDialog
Filter=D
VirtualFilter=dWC
LastObject=IDC_CREATE_SUBJECT

[DLG:IDD_DIALOG1]
Type=1
Class=WgpiView
ControlCount=1
Control1=IDC_LIST1,listbox,1352728835

[CLS:WgpiView]
Type=0
HeaderFile=WgpiView.h
ImplementationFile=WgpiView.cpp
BaseClass=CDialog
Filter=D
LastObject=IDC_LIST1

