
dnl
dnl Like AC_CHECK_SIZEOF, but allows extra headers to be included 
dnl before the check
dnl
AC_DEFUN(LAC_CHECK_SIZEOF,
[changequote(<<, >>)dnl
dnl The name to #define.
define(<<AC_TYPE_NAME>>, translit(sizeof_$1, [a-z *], [A-Z_P]))dnl
dnl The cache variable name.
define(<<AC_CV_NAME>>, translit(ac_cv_sizeof_$1, [ *], [_p]))dnl
changequote([, ])dnl
AC_MSG_CHECKING(size of $1)
AC_CACHE_VAL(AC_CV_NAME,
[AC_TRY_RUN([$3

#include <stdio.h>

main()
{
  FILE *f=fopen("conftestval", "w");
  if (!f) exit(1);
  fprintf(f, "%d\n", sizeof($1));
  exit(0);
}], AC_CV_NAME=`cat conftestval`, AC_CV_NAME=0, ifelse([$2], , , AC_CV_NAME=$2))])dnl
AC_MSG_RESULT($AC_CV_NAME)
AC_DEFINE_UNQUOTED(AC_TYPE_NAME, $AC_CV_NAME)
undefine([AC_TYPE_NAME])dnl
undefine([AC_CV_NAME])dnl
])


AC_DEFUN(CHECK_SIZES, [

LAC_CHECK_SIZEOF(off_t, 4, [#include <sys/types.h>])

AC_CHECK_SIZEOF(short, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long, 4)
AC_CHECK_SIZEOF(long long, 0)

AC_MSG_CHECKING(for type of off_t)
if test "$ac_cv_sizeof_off_t" = "$ac_cv_sizeof_short"; then
    GLOBUS_OFF_T="short"
elif test "$ac_cv_sizeof_off_t" = "$ac_cv_sizeof_int"; then
    GLOBUS_OFF_T="int"
elif test "$ac_cv_sizeof_off_t" = "$ac_cv_sizeof_long"; then
    GLOBUS_OFF_T="long"
elif test "$ac_cv_sizeof_off_t" = "$ac_cv_sizeof_long_long"; then
    GLOBUS_OFF_T="long long"
else
    AC_MSG_ERROR(Cannot determine an appropriate data type for globus_off_t)
fi
AC_MSG_RESULT($GLOBUS_OFF_T)
AC_DEFINE_UNQUOTED(GLOBUS_OFF_T, $GLOBUS_OFF_T)

AC_MSG_CHECKING(for format to use with off_t)
if test "$GLOBUS_OFF_T" = "short"; then
    GLOBUS_OFF_T_FORMAT="hd"
elif test "$GLOBUS_OFF_T" = "int"; then
    GLOBUS_OFF_T_FORMAT="d"
elif test "$GLOBUS_OFF_T" = "long"; then
    GLOBUS_OFF_T_FORMAT="ld"
elif test "$GLOBUS_OFF_T" = "long long"; then
    GLOBUS_OFF_T_FORMAT="unknown"

    if test "$GLOBUS_OFF_T_FORMAT" = "unknown" ; then
	LAC_TRY_FORMAT(GLOBUS_OFF_T, qd)
    fi
    if test "$GLOBUS_OFF_T_FORMAT" = "unknown" ; then
	LAC_TRY_FORMAT(GLOBUS_OFF_T, lld)
    fi
    if test "$GLOBUS_OFF_T_FORMAT" = "unknown" ; then
        AC_MSG_RESULT(unkown)
	AC_MSG_ERROR(Cannot determine an appropriate format for globus_off_t)
    fi
fi

AC_MSG_RESULT(%$GLOBUS_OFF_T_FORMAT)
AC_DEFINE_UNQUOTED(GLOBUS_OFF_T_FORMAT, "$GLOBUS_OFF_T_FORMAT")


])
