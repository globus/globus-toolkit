@echo off
@ echo . 
@ echo . Set WinCVSBuildEnvironment
@ echo . 

rem Must have GLOBUS_LOCATION
if "%GLOBUS_LOCATION%"=="" goto ErrorExit

set GlobusLocation=%GLOBUS_LOCATION%
set SSLLocation=%GlobusLocation%\core\source\win32\openssl
set ICULocation=%GlobusLocation%\core\source\win32\icu4c
set WinGlobusVersion=15.1

rem Display Variables
@ echo . Globus Location:    %GlobusLocation%
@ echo . SSL Location:       %SSLLocation%
@ echo . WinGlobus Version:  %WinGlobusVersion%
@ echo . 

rem Append ICU and OpenSSL bin, lib and include paths
set GLOBUS_LOCATION=%GlobusLocation%
set PATH=%PATH%;%GlobusLocation%\bin;%ICULocation%\bin;%SSLLocation%\out32dll
set LIB=%LIB%;%ICULocation%\lib;%SSLLocation%\out32dll
set INCLUDE=%INCLUDE%;%GlobusLocation%\include;%ICULocation%\include;%SSLLocation%\inc32
goto NormalExit

rem Error Exit
:ErrorExit
echo Error: GLOBUS_LOCATION must be set!
exit /b 1

rem Normal Exit
:NormalExit
exit /b 0
