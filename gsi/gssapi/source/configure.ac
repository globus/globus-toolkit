AC_INIT([globus_gssapi_gsi],[10.10])

AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=6
AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

case "$host" in
*-*-linux* | *-*-gnu* | *-*-k*bsd*-gnu)
    use_symbol_labels="yes"
    ;;
*)
    use_symbol_labels="no"
    ;;
esac

PACKAGE_DEPS="globus-common >= 14 globus-openssl-module >= 3 globus-gsi-openssl-error >= 2 globus-gsi-cert-utils >= 8 globus-gsi-credential >= 5 globus-gsi-callback >= 4 globus-gsi-proxy-core >= 6 globus-gsi-sysconfig >= 5 openssl >= 0.9.8"
AC_SUBST(PACKAGE_DEPS)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])

AC_MSG_CHECKING([if we can link with internal OpenSSL APIs])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [#include <openssl/ssl.h>
        extern int ssl3_setup_buffers(SSL *s);],
        [ssl3_setup_buffers(NULL);])],
    [ac_cv_can_link_with_openssl_internal_api=yes],
    [ac_cv_can_link_with_openssl_internal_api=no])
AC_MSG_RESULT([$ac_cv_can_link_with_openssl_internal_api])

if test "$ac_cv_can_link_with_openssl_internal_api" = yes; then
    AC_DEFINE([LINK_WITH_INTERNAL_OPENSSL_API],[1],[Define to `1' to use ss3_setup_buffers to import and export gss_cred_id_t structures])
fi

AM_CONDITIONAL(USE_SYMBOL_LABELS, test x$use_symbol_labels = "xyes")

AC_CONFIG_FILES(
        globus-gssapi-gsi.pc
        globus-gssapi-gsi-uninstalled.pc
	Makefile
        version.h
        library/Doxyfile
        library/Makefile
)
AC_OUTPUT
