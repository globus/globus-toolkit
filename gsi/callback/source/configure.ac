AC_INIT([globus_gsi_callback], [4.6])

AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL
AC_CONFIG_HEADERS(config.h)

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=4

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="globus-common >= 14 globus-openssl-module >= 3 globus-gsi-openssl-error >= 2 globus-gsi-cert-utils >= 8 globus-gsi-sysconfig >= 5 globus-gsi-proxy-ssl >= 4 openssl >= 0.9.8"
AC_SUBST(PACKAGE_DEPS)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != "no"])

AC_CHECK_HEADERS(sys/time.h unistd.h)

AC_OUTPUT(
        Makefile
	library/Makefile
	library/oldgaa/Makefile
	library/Doxyfile
        globus-gsi-callback.pc
        globus-gsi-callback-uninstalled.pc
	version.h
)
