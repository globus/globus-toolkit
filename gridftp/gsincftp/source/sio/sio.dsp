# Microsoft Developer Studio Project File - Name="sio" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=sio - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sio.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sio.mak" CFG="sio - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sio - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "sio - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "sio - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /W4 /GX /Ot /Oa /Og /Ob2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "sio - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "sio - Win32 Release"
# Name "sio - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\main.c
# End Source File
# Begin Source File

SOURCE=.\PRead.c
# End Source File
# Begin Source File

SOURCE=.\PWrite.c
# End Source File
# Begin Source File

SOURCE=.\SAcceptA.c
# End Source File
# Begin Source File

SOURCE=.\SAcceptS.c
# End Source File
# Begin Source File

SOURCE=.\SBind.c
# End Source File
# Begin Source File

SOURCE=.\SClose.c
# End Source File
# Begin Source File

SOURCE=.\SConnect.c
# End Source File
# Begin Source File

SOURCE=.\SConnectByName.c
# End Source File
# Begin Source File

SOURCE=.\SError.c
# End Source File
# Begin Source File

SOURCE=.\SNew.c
# End Source File
# Begin Source File

SOURCE=.\SocketUtil.c
# End Source File
# Begin Source File

SOURCE=.\SRead.c
# End Source File
# Begin Source File

SOURCE=.\SReadline.c
# End Source File
# Begin Source File

SOURCE=.\SRecv.c
# End Source File
# Begin Source File

SOURCE=.\SRecvfrom.c
# End Source File
# Begin Source File

SOURCE=.\SRecvmsg.c
# End Source File
# Begin Source File

SOURCE=.\SSelect.c
# End Source File
# Begin Source File

SOURCE=.\SSend.c
# End Source File
# Begin Source File

SOURCE=.\SSendto.c
# End Source File
# Begin Source File

SOURCE=.\SSendtoByName.c
# End Source File
# Begin Source File

SOURCE=.\StrAddr.c
# End Source File
# Begin Source File

SOURCE=.\SWait.c
# End Source File
# Begin Source File

SOURCE=.\SWrite.c
# End Source File
# Begin Source File

SOURCE=.\UAcceptA.c
# End Source File
# Begin Source File

SOURCE=.\UAcceptS.c
# End Source File
# Begin Source File

SOURCE=.\UBind.c
# End Source File
# Begin Source File

SOURCE=.\UConnect.c
# End Source File
# Begin Source File

SOURCE=.\UConnectByName.c
# End Source File
# Begin Source File

SOURCE=.\UNew.c
# End Source File
# Begin Source File

SOURCE=.\URecvfrom.c
# End Source File
# Begin Source File

SOURCE=.\USendto.c
# End Source File
# Begin Source File

SOURCE=.\USendtoByName.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\sio.h
# End Source File
# Begin Source File

SOURCE=.\syshdrs.h
# End Source File
# Begin Source File

SOURCE=.\wincfg.h
# End Source File
# End Group
# End Target
# End Project
