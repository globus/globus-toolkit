@ECHO OFF

cd \src\win\ncftp
rmd \src\win\ncftp\Release
rmd \src\win\ncftp\Debug
cd ..

erase \temp\ncftp.zip
pkzip25.exe -add -204 -dir=current -excl=*.exe -excl=*.o -excl=*.obj -excl=*.lib -excl=*.pch -excl=*.ilk -excl=*.ncb -excl=*.opt -excl=*.pdb -excl=*.idb -excl=*.plg -excl=*.scc -excl=*.aps -excl=*.sbr -excl=*.bsc -excl=*.exp -excl=*.res -excl=*.zip \temp\ncftp.zip ncftp\*.*

cd \src\win\ncftp
dir \temp\ncftp.zip
