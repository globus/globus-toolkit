
dnl LAC_SUBSTITUTE_VAR

AC_DEFUN(LAC_SUBSTITUTE_VAR,
[
    if test -n "[$]lac_$1"; then
        $1=[$]lac_$1
        AC_SUBST($1)
    fi
])


dnl LAC_DEFINE_VAR

AC_DEFUN(LAC_DEFINE_VAR,
[
    if test -n "[$]lac_$1"; then
        $1=[$]lac_$1
        AC_DEFINE_UNQUOTED($1,[$]lac_$1)
    fi
])

dnl LAC_CHECK_DL_LIB
AC_DEFUN(LAC_CHECK_DL_LIB,
[
    AC_CHECK_LIB(dl,dlopen,
    [
        DL_LIB=-ldl
    ],
    [
        AC_CHECK_LIB(dld,dlopen,
        [
            DL_LIB=-ldld
        ],
        [
            AC_MSG_ERROR("Unable to find dynamic linking library")
        ])
    ])
])
