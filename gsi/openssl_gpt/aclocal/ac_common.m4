
dnl LAC_SUBSTITUTE_VAR

AC_DEFUN([LAC_SUBSTITUTE_VAR],
[
    if test -n "[$]lac_$1"; then
        $1=[$]lac_$1
        AC_SUBST($1)
    fi
])


dnl LAC_DEFINE_VAR

AC_DEFUN([LAC_DEFINE_VAR],
[
    if test -n "[$]lac_$1"; then
        $1=[$]lac_$1
        AC_DEFINE_UNQUOTED($1,[$]lac_$1)
    fi
])

dnl CHECK_NEED_LDL
AC_DEFUN([CHECK_NEED_LDL],
[
if test "x$GPT_LINKTYPE" != "xstatic"; then
    AC_CHECK_FUNC([dlopen],
    [],
    [
        AC_CHECK_LIB([dl],[dlopen],
        [
            EXTERNAL_LIBS="$EXTERNAL_LIBS -ldl"
        ],
        [
            AC_CHECK_LIB([dld],[dlopen],
            [
                EXTERNAL_LIBS="$EXTERNAL_LIBS -ldld"
            ],
            [
                AC_MSG_ERROR("Unable to find dynamic linking library")
            ])
        ])
    ])
fi
    AM_CONDITIONAL(STATIC_ONLY, test "x$GPT_LINKTYPE" = "xstatic")
])

# Figure out how to run the assembler.

# LAC_PROG_AS
AC_DEFUN([LAC_PROG_AS],
[# By default we simply use the C compiler to build assembly code.
AC_REQUIRE([AC_PROG_CC])
: ${AS="$CC"}
# Set ASFLAGS if not already set.
: ${ASFLAGS="$CFLAGS"}
AC_SUBST(AS)
AC_SUBST(ASFLAGS)])
