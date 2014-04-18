AC_PREREQ([2.60])

AC_INIT([globus_gsi_proxy_core],[7.4],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [7])
AC_SUBST([PACKAGE_DEPS], ["openssl >= 0.9.8, globus-common >= 14, globus-openssl-module >= 3, globus-gsi-openssl-error >= 2, globus-gsi-cert-utils >= 8, globus-gsi-sysconfig >= 5, globus-gsi-proxy-ssl >= 4, globus-gsi-credential >= 5"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], [$PACKAGE_DEPS])

AC_PATH_PROGS([DOXYGEN], doxygen)
AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != "no"])

AC_OUTPUT(
        globus-gsi-proxy-core.pc
        globus-gsi-proxy-core-uninstalled.pc
        Makefile
	library/Makefile
        library/Doxyfile
	version.h
)
