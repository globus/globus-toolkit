#serial 4

dnl By default, many hosts won't let programs access large files;
dnl one must use special compiler options to get large-file access to work.
dnl For more details about this brain damage please see:
dnl http://www.sas.com/standards/large.file/x_open.20Mar96.html

dnl Written by Paul Eggert <eggert@twinsun.com>.

AC_DEFUN(LAC_TRY_FORMAT,[
    AC_TRY_RUN([
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char ** argv)
{
    $1 foo = 1;
    char buf[256];
    if(sprintf(buf, "%$2", foo) == 1)
        return 0;
    return 1;
}], $1_FORMAT=$2, $1_FORMAT="unknown", $1_FORMAT="unknown")])
