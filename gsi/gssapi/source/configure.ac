AC_PREREQ([2.60])

AC_INIT([globus_gssapi_gsi],[11.6],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [7])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-openssl-module >= 3, globus-gsi-openssl-error >= 2, globus-gsi-cert-utils >= 8, globus-gsi-credential >= 5, globus-gsi-callback >= 4, globus-gsi-proxy-core >= 6, globus-gsi-sysconfig >= 5, openssl >= 0.9.8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

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

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])

SAVE_LIBS="$LIBS"
LIBS="$LIBS $PACKAGE_DEP_LIBS"
AC_MSG_CHECKING([if we can link with internal OpenSSL APIs])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [#include <openssl/ssl.h>
        extern int ssl3_setup_buffers(SSL *s);],
        [ssl3_setup_buffers(NULL);])],
    [ac_cv_can_link_with_openssl_internal_api=yes],
    [ac_cv_can_link_with_openssl_internal_api=no])
AC_MSG_RESULT([$ac_cv_can_link_with_openssl_internal_api])
LIBS="$SAVE_LIBS"

if test "$ac_cv_can_link_with_openssl_internal_api" = yes; then
    AC_DEFINE([LINK_WITH_INTERNAL_OPENSSL_API],[1],[Define to `1' to use ss3_setup_buffers to import and export gss_cred_id_t structures])
fi

AM_CONDITIONAL(
    [EXPORT_SEC_CONTEXT_WORKS],
    [test "$ac_cv_can_link_with_openssl_internal_api" = yes])

AM_CONDITIONAL(USE_SYMBOL_LABELS, test x$use_symbol_labels = "xyes")

AC_CONFIG_FILES(
        globus-gssapi-gsi.pc
        globus-gssapi-gsi-uninstalled.pc
	Makefile
        version.h
        library/Doxyfile
        library/Makefile
        test/Makefile
)
AC_OUTPUT
