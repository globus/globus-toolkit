AC_INIT([globus_gsi_proxy_core],[6.2])
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=3

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="openssl >= 0.9.8 globus-common >= 14 globus-openssl-module >= 3 globus-gsi-openssl-error >= 2 globus-gsi-cert-utils >= 8 globus-gsi-sysconfig >= 5 globus-gsi-proxy-ssl >= 4 globus-gsi-credential >= 5"
AC_SUBST(PACKAGE_DEPS)
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
