@echo off

echo .
echo . Set Environment
echo .
call Setenv.bat

echo .
echo . Create The Build Tree If Necessary
echo .
md %GLobusLocation%\lib
md %GLobusLocation%\include
md %GLobusLocation%\include\threaded
md %GLobusLocation%\include\nonthreaded
md %GLobusLocation%\include\openssl
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
echo . Copy OpenSSL Include Files (This Is Not Handled By The Script)
echo .
copy %SSLLocation%\inc32\openssl\*.* %GlobusLocation%\include\openssl\*.*

echo .
echo . Copy OpenSSL Binaries (This Is Not Handled By The Script)
echo .
copy %SSLLocation%\out32dll\libeay32.dll  %GlobusLocation%\bin\*.*
copy %SSLLocation%\out32dll\ssleay32.dll  %GlobusLocation%\bin\*.*
copy %SSLLocation%\out32dll\libeay32.lib  %GlobusLocation%\lib\*.*
copy %SSLLocation%\out32dll\ssleay32.lib  %GlobusLocation%\lib\*.*

echo .
echo . Clear BuildResults.log And Put An Opening Stamp Into It
echo .
echo Starting Build On %DATE% At %TIME% > BuildResults.log

echo .
echo . Create And Execute Build For Dynamic Release Threaded Libraries (win32relmdthr)
echo .
WinCVSBuild.pl %GlobusLocation% win32relmdthr 14.2
call WinCVSBuildLibs
call WinCVSBuildExes

echo .
echo . Put A Closing Time Stamp In BuildResults.log
echo .
echo Completed Build On %DATE% At %TIME% >> BuildResults.log

echo .
echo . Done
echo .
