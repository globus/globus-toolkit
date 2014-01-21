AC_PREREQ([2.60])

AC_INIT([globus_callout], [3.0], [http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [3])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign parallel-tests 1.11 tar-pax])
LT_INIT([dlopen win32-dll])

AC_CHECK_HEADERS([ltdl.h],[],[AC_MSG_ERROR([Missing required header ltdl.h])])
AC_SEARCH_LIBS([lt_dlopen], [ltdl], [], [AC_MSG_ERROR([Missing required library ltdl])])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != "no"])

AC_CONFIG_FILES(
        Makefile
        globus-callout.pc
        globus-callout-uninstalled.pc
	library/Makefile
	library/Doxyfile
        test/Makefile
	version.h
)
AC_OUTPUT
