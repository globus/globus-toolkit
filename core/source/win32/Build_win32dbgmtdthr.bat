@echo off

echo .
echo . Set Environment
echo .
call Setenv.bat
if ERRORLEVEL 1 goto ErrorExit

echo .
echo . Create The Build Tree If Necessary
echo .
md %GLobusLocation%\lib
md %GLobusLocation%\include
md %GLobusLocation%\include\threaded
md %GLobusLocation%\include\nonthreaded
md %GLobusLocation%\bin

echo .
echo . Go To Script Home
echo .
cd %GLobusLocation%\core\source\win32

echo .
echo . Copy Core Windows Header Files (This Is Not Handled By The Script)
echo .
copy %GlobusLocation%\core\source\win32\threaded\globus_config.h %GlobusLocation%\include\threaded\*.*
copy %GlobusLocation%\core\source\win32\nonthreaded\globus_config.h %GlobusLocation%\include\nonthreaded\*.*

echo .
echo . Clear BuildResults.log And Put An Opening Stamp Into It
echo .
echo Starting Build On %DATE% At %TIME% > BuildResults.log

echo .
echo . Create And Execute Build For Static Debug Threaded Libraries (win32dbgmtdthr)
echo .
WinCVSBuild.pl %GlobusLocation% win32dbgmtdthr %WinGlobusVersion%
call WinCVSBuildLibs-win32dbgmtdthr
call WinCVSBuildExes-win32dbgmtdthr

echo .
echo . Put A Closing Time Stamp In BuildResults.log
echo .
echo Completed Build On %DATE% At %TIME% >> BuildResults.log

rem Normal Exit
echo .
echo . Done
echo .
exit /b 0

rem Error Exit
:ErrorExit
echo .
echo . The build was not run due to an Error
echo .
exit /b 1
