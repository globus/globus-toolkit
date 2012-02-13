dnl

AC_DEFUN([GLOBUS_OPENSSL],
[
AC_ARG_WITH(openssl,
    AC_HELP_STRING(
        [--with-openssl=PATH],
        [Specify the root of the openssl installation]),
        [
            case $withval in
                no|yes)
                    ;;
                *)
                openssl="$withval"
                    ;;
            esac
        ])

if test "${openssl}" != ""; then
    PKG_CONFIG_PATH=${openssl}/lib/pkgconfig
    export PKG_CONFIG_PATH
fi

AC_MSG_CHECKING([OpenSSL CFLAGS])
if test "$OPENSSL_CFLAGS" = ""; then
    if pkg-config openssl --exists > /dev/null 2>&1 ; then
        OPENSSL_CFLAGS="`pkg-config openssl --cflags`"
    elif test -r "${openssl}/include/openssl/ssl.h" ; then
        OPENSSL_CFLAGS="-I ${openssl}/include"
    fi
fi
AC_MSG_RESULT([using '$OPENSSL_CFLAGS'])
CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"

AC_TRY_COMPILE([#include <openssl/ssl.h>],
               [SSL_library_init();],,
               [AC_MSG_ERROR([Unable to compile with SSL])])

AC_MSG_CHECKING([OpenSSL LIBS])
if test "$OPENSSL_LIBS" = ""; then
    if pkg-config openssl --exists > /dev/null 2>&1 ; then
        OPENSSL_PKGCONF_DEPENDENCIES="openssl"
        OPENSSL_LIBS="`pkg-config openssl --libs`"
    else
        OPENSSL_LIBS="-L${openssl}/lib -lssl -lcrypto"
    fi
fi
AC_MSG_RESULT([using '$OPENSSL_LIBS'])
LIBS="${LIBS} ${OPENSSL_LIBS}"

AC_TRY_LINK(
[#include <openssl/ssl.h>],
[SSL_library_init();], , [AC_MSG_ERROR([Unable to link with SSL])])

AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

if test "x$OPENSSL_PKGCONF_DEPENDENCIES" != "x"; then
    GPT_PKGCONFIG_DEPENDENCIES="$GPT_PKGCONFIG_DEPENDENCIES $OPENSSL_PKGCONF_DEPENDENCIES"
else
    GPT_EXTERNAL_INCLUDES="${GPT_EXTERNAL_INCLUDES} ${OPENSSL_CFLAGS}"
    GPT_EXTERNAL_LIBS="${GPT_EXTERNAL_LIBS} ${OPENSSL_LIBS}"
fi
])
