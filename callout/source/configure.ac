AC_INIT([globus_callout], [2.4])
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL

AC_CHECK_HEADERS([ltdl.h],[],[AC_MSG_ERROR([Missing required header ltdl.h])])
AC_SEARCH_LIBS([lt_dlopen], [ltdl], [], [AC_MSG_ERROR([Missing required library ltdl])])

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=2

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="globus-common >= 14"
AC_SUBST(PACKAGE_DEPS)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != "no"])

AC_OUTPUT(
        Makefile
        globus-callout.pc
        globus-callout-uninstalled.pc
	library/Makefile
	library/Doxyfile
	version.h
)
