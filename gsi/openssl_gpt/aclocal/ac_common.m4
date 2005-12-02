
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
])

dnl CHECK_MINIMAL_SSL
AC_DEFUN([CHECK_MINIMAL_SSL],
    [AC_ARG_WITH(minimal-ssl,
            [ --with-minimal-ssl    Specify the build of minimal set of ciphers],
            [
            if test "x$withval" != "xno"; then
                minimal_ssl=yes
                AC_DEFINE(OPENSSL_NO_IDEA)
                AC_DEFINE(OPENSSL_NO_AES)
                AC_DEFINE(OPENSSL_NO_RC2)
                AC_DEFINE(OPENSSL_NO_RC4)
                AC_DEFINE(OPENSSL_NO_RC5)
                AC_DEFINE(OPENSSL_NO_MD2)
                AC_DEFINE(OPENSSL_NO_MD4)
                AC_DEFINE(OPENSSL_NO_RIPEMD)
                AC_DEFINE(OPENSSL_NO_DSA)
                AC_DEFINE(OPENSSL_NO_DH)
                AC_DEFINE(OPENSSL_NO_KRB5)
                AC_DEFINE(OPENSSL_NO_HW)
            fi])
        AM_CONDITIONAL([MINIMAL_SSL], [test "x$minimal_ssl" = "xyes"])
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
