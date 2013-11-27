AC_PREREQ([2.60])
AC_INIT([globus_xio_gridftp_multicast],[0.1])
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=0

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="globus_xio >= 0 globus_ftp_client >= 2 globus_xio_gsi_driver >= 0"
AC_SUBST(PACKAGE_DEPS)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_CONFIG_FILES(
        globus-xio-gridftp-multicast-uninstalled.pc
        globus-xio-gridftp-multicast.pc
        Makefile
	version.h)
AC_OUTPUT
