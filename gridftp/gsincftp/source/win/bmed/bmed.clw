; CLW file contains information for the MFC ClassWizard

[General Info]
Version=1
LastClass=CBmedDlg
LastTemplate=CDialog
NewFileInclude1=#include "stdafx.h"
NewFileInclude2=#include "bmed.h"

ClassCount=3
Class1=CBmedApp
Class2=CBmedDlg

ResourceCount=3
Resource2=IDD_BMED_DIALOG
Resource1=IDR_MAINFRAME
Class3=CBookmarkProperties
Resource3=IDD_BOOKMARK_PROPERTIES

[CLS:CBmedApp]
Type=0
HeaderFile=bmed.h
ImplementationFile=bmed.cpp
Filter=N
BaseClass=CWinApp
VirtualFilter=AC
LastObject=CBmedApp

[CLS:CBmedDlg]
Type=0
HeaderFile=bmedDlg.h
ImplementationFile=bmedDlg.cpp
Filter=D
BaseClass=CDialog
VirtualFilter=dWC
LastObject=IDC_NEW



[DLG:IDD_BMED_DIALOG]
Type=1
Class=CBmedDlg
ControlCount=7
Control1=IDC_BOOKMARK_LIST,SysListView32,1350666253
Control2=IDC_CONNECT,button,1342242817
Control3=IDC_EDIT,button,1342242816
Control4=IDC_DUPLICATE,button,1342242816
Control5=IDC_NEW,button,1342242816
Control6=IDC_CLOSE,button,1342242816
Control7=IDC_DELETE,button,1342242816

[DLG:IDD_BOOKMARK_PROPERTIES]
Type=1
Class=CBookmarkProperties
ControlCount=27
Control1=IDC_BOOKMARK_NAME,edit,1350631552
Control2=IDC_HOSTNAME,edit,1350631552
Control3=IDC_USER,edit,1350631552
Control4=IDC_PASSWORD,edit,1350631584
Control5=IDC_ACCOUNT,edit,1350631552
Control6=IDC_REMOTE_DIR,edit,1350631552
Control7=IDC_LOCAL_DIR,edit,1350631552
Control8=IDC_BINARY,button,1342308361
Control9=IDC_ASCII,button,1342177289
Control10=IDC_PORT,edit,1350639744
Control11=IDC_COMMENT,edit,1350631552
Control12=IDOK,button,1342242817
Control13=IDCANCEL,button,1342242816
Control14=IDC_STATIC,static,1342308352
Control15=IDC_STATIC,static,1342308352
Control16=IDC_STATIC,static,1342308352
Control17=IDC_STATIC,static,1342308352
Control18=IDC_STATIC,static,1342308352
Control19=IDC_STATIC,static,1342308352
Control20=IDC_STATIC,static,1342308352
Control21=IDC_STATIC,static,1342308352
Control22=IDC_STATIC,static,1342308352
Control23=IDC_STATIC,static,1342308352
Control24=IDC_STATIC,static,1342308352
Control25=IDC_STATIC,static,1342308352
Control26=IDC_STATIC,static,1342308352
Control27=IDC_STATIC,static,1342308352

[CLS:CBookmarkProperties]
Type=0
HeaderFile=BookmarkProperties.h
ImplementationFile=BookmarkProperties.cpp
BaseClass=CDialog
Filter=D
VirtualFilter=dWC
LastObject=IDC_PASSWORD

