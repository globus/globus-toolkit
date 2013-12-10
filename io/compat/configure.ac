AC_PREREQ([2.60])
AC_INIT([globus_io],[10.0],[http://jira.globus.org])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign parallel-tests 1.11])
LT_INIT([dlopen win32-dll])

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=7

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="globus-common >= 14 globus-xio >= 3 globus-gss-assist >= 8 globus-gssapi-gsi >= 10 globus-xio-gsi-driver >= 2 globus-gssapi-error >= 4"

AC_SUBST(PACKAGE_DEPS)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)
GLOBUS_XIO_GSI_DRIVER_LIBDIR=`pkg-config --variable=libdir globus-xio-gsi-driver`
AC_SUBST(GLOBUS_XIO_GSI_DRIVER_LIBDIR)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])

AC_CONFIG_FILES(
        globus-io.pc
        globus-io-uninstalled.pc
	Makefile
        test/Makefile
        Doxyfile
	version.h
)

AC_OUTPUT
