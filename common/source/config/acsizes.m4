AC_DEFUN(CHECK_SIZES, [

AC_CHECK_SIZEOF(off_t, 4)

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
