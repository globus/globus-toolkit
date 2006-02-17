@echo off
@ echo . 
@ echo . Set WinCVSBuildEnvironment
@ echo . 

::Must have GLOBUS_LOCATION
if "%GLOBUS_LOCATION%"=="" goto ErrorExit

set GlobusLocation=%GLOBUS_LOCATION%
set SSLLocation=%GlobusLocation%\core\source\win32\openssl
set ICULocation=%GlobusLocation%\core\source\win32\icu4c
set WinGlobusVersion=15.1

:: Display Variables
@ echo . Globus Location:    %GlobusLocation%
@ echo . SSL Location:       %SSLLocation%
@ echo . WinGlobus Version:  %WinGlobusVersion%
@ echo . 

:: Append ICU and OpenSSL bin, lib and include paths
if not "%WINGLOBUS_PATH%" == "%PATH%" (
	set PATH=%PATH%;%GlobusLocation%\bin;%ICULocation%\bin;%SSLLocation%\out32dll
	set WINGLOBUS_PATH=%PATH%
)

if not "%WINGLOBUS_LIB%" == "%LIB%" (
	set LIB=%LIB%;%ICULocation%\lib;%SSLLocation%\out32dll
	set WINGLOBUS_LIB=%LIB%
)

if not "%WINGLOBUS_INCLUDE%" == "%INCLUDE%" (
	set INCLUDE=%INCLUDE%;%GlobusLocation%\include;%ICULocation%\include;%SSLLocation%\inc32
	set WINGLOBUS_INCLUDE=%INCLUDE%
)

@ echo . PATH:    %PATH%
@ echo . LIB:     %LIB%
@ echo . INCLUDE: %INCLUDE%
@ echo . 

goto NormalExit

rem Error Exit
:ErrorExit
echo Error: GLOBUS_LOCATION must be set!
exit /b 1

rem Normal Exit
:NormalExit
exit /b 0
