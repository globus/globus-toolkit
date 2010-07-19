#serial 5

dnl By default, many hosts won't let programs access large files;
dnl one must use special compiler options to get large-file access to work.
dnl For more details about this brain damage please see:
dnl http://www.sas.com/standards/large.file/x_open.20Mar96.html

dnl Written by Paul Eggert <eggert@twinsun.com>.

dnl Internal subroutine of AC_SYS_LARGEFILE.
dnl AC_SYS_LARGEFILE_FLAGS(FLAGSNAME)
AC_DEFUN([AC_SYS_LARGEFILE_FLAGS],
  [AC_CACHE_CHECK([for $1 value to request large file support],
     ac_cv_sys_largefile_$1,
     [ac_cv_sys_largefile_$1=`($GETCONF LFS_$1) 2>/dev/null` || {
	ac_cv_sys_largefile_$1=no
      }])])

dnl Internal subroutine of AC_SYS_LARGEFILE.
dnl AC_SYS_LARGEFILE_SPACE_APPEND(VAR, VAL)
AC_DEFUN([AC_SYS_LARGEFILE_SPACE_APPEND],
  [case $2 in
   no) ;;
   ?*)
     case "[$]$1" in
     '') $1=$2 ;;
     *) $1=[$]$1' '$2 ;;
     esac ;;
   esac])

dnl Internal subroutine of AC_SYS_LARGEFILE.
dnl AC_SYS_LARGEFILE_MACRO_VALUE(C-MACRO, CACHE-VAR, COMMENT, CODE-TO-SET-DEFAULT)
AC_DEFUN([AC_SYS_LARGEFILE_MACRO_VALUE],
  [AC_CACHE_CHECK([for $1], $2,
     [$2=no
changequote(, )dnl
      $4
      for ac_flag in $ac_cv_sys_largefile_CFLAGS no; do
	case "$ac_flag" in
	-D$1)
	  $2=1 ;;
	-D$1=*)
	  $2=`expr " $ac_flag" : '[^=]*=\(.*\)'` ;;
	esac
      done
changequote([, ])dnl
      ])
   if test "[$]$2" != no; then
     AC_DEFINE_UNQUOTED([$1], [$]$2, [$3])
     GPT_SET_CFLAGS("-D[$1]=[$]$2")
   fi])

AC_DEFUN([AC_SYS_LARGEFILE],
  [AC_REQUIRE([AC_CANONICAL_HOST])
   AC_ARG_ENABLE(largefile,
     [  --disable-largefile     omit support for large files])
   if test "$enable_largefile" != no; then
     AC_CHECK_TOOL(GETCONF, getconf)
       if test "`($GETCONF _POSIX_V6_ILP32_OFFBIG) 2>/dev/null`" = "1"; then
         GETCONF="$GETCONF -v POSIX_V6_ILP32_OFFBIG"
       fi
     AC_SYS_LARGEFILE_FLAGS(CFLAGS)
     AC_SYS_LARGEFILE_FLAGS(LDFLAGS)
     AC_SYS_LARGEFILE_FLAGS(LIBS)
	
     for ac_flag in $ac_cv_sys_largefile_CFLAGS no; do
       case "$ac_flag" in
       no) ;;
       -D_FILE_OFFSET_BITS=*) ;;
       -D_LARGEFILE_SOURCE | -D_LARGEFILE_SOURCE=*) ;;
       -D_LARGE_FILES | -D_LARGE_FILES=*) ;;
       -D?* | -I?*)
	 AC_SYS_LARGEFILE_SPACE_APPEND(CPPFLAGS, "$ac_flag") ;;
       *)
dnl	 AC_SYS_LARGEFILE_SPACE_APPEND(CFLAGS, "$ac_flag") ;;
	 GPT_SET_CFLAGS("$ac_flag")
       esac
     done
        AC_SYS_LARGEFILE_SPACE_APPEND(LDFLAGS, "$ac_cv_sys_largefile_LDFLAGS")
        AC_SYS_LARGEFILE_SPACE_APPEND(LIBS, "$ac_cv_sys_largefile_LIBS")
     AC_SYS_LARGEFILE_MACRO_VALUE(_FILE_OFFSET_BITS,
       ac_cv_sys_file_offset_bits,
       [Number of bits in a file offset, on hosts where this is settable.],
       [case "$host_os" in
	# HP-UX 10.20 and later
	hpux10.[2-9][0-9]* | hpux1[1-9]* | hpux[2-9][0-9]*)
	  ac_cv_sys_file_offset_bits=64 ;;
	*linux*)
	  if test "X$ac_cv_sys_largefile_CFLAGS" = "X"; then
	    ac_cv_sys_file_offset_bits=64
	  fi ;;
	esac])
     AC_SYS_LARGEFILE_MACRO_VALUE(_LARGEFILE_SOURCE,
       ac_cv_sys_largefile_source,
       [Define to make fseeko etc. visible, on some hosts.],
       [case "$host_os" in
	# HP-UX 10.20 and later
	hpux10.[2-9][0-9]* | hpux1[1-9]* | hpux[2-9][0-9]*)
	  ac_cv_sys_largefile_source=1 ;;
	*linux*)
	  if test "X$ac_cv_sys_largefile_CFLAGS" = "X"; then
	    ac_cv_sys_largefile_source=1
	  fi ;;
	esac])
     AC_SYS_LARGEFILE_MACRO_VALUE(_LARGE_FILES,
       ac_cv_sys_large_files,
       [Define for large files, on AIX-style hosts.],
       [case "$host_os" in
	# AIX 4.2 and later
	aix4.[2-9]* | aix4.1[0-9]* | aix[5-9].* | aix[1-9][0-9]*)
	  ac_cv_sys_large_files=1 ;;
	esac])
   fi
  ])

AC_DEFUN([LAC_TRY_FORMAT],[
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

