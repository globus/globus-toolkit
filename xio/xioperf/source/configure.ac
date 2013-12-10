AC_PREREQ([2.60])
AC_INIT([globus_xioperf], [4.0],[http://jira.globus.org])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign parallel-tests 1.11])
LT_INIT([dlopen win32-dll])

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=1

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include(dirt.sh)
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="globus-common >= 14 globus-xio >= 3"
PKG_CHECK_MODULES([PACKAGE_DEP],$PACKAGE_DEPS)

AC_SUBST(PACKAGE_DEPS)

AC_OUTPUT(
        globus-xioperf-uninstalled.pc
        globus-xioperf.pc
	Makefile
        version.h
)
