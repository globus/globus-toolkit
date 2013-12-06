AC_PREREQ([2.60])
AC_INIT([globus_ftp_client],[7.6])
AM_INIT_AUTOMAKE([foreign 1.13])
AM_PROG_LIBTOOL

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=5

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="globus-common >= 14 globus-ftp-control >= 4 globus-gsi-callback >= 4 globus-gsi-credential >= 5 globus-gsi-sysconfig >= 5 globus-gssapi-gsi >= 10 globus-xio >= 3 globus-xio-popen-driver >= 2"
AC_SUBST(PACKAGE_DEPS)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])
AC_CONFIG_FILES(
        globus-ftp-client-uninstalled.pc
        globus-ftp-client.pc
        gridftp-ssh
        Makefile
        Doxyfile
        test/Makefile
	version.h)
AC_OUTPUT
