AC_PREREQ([2.60])

AC_INIT([globus_xio_netlogger_driver],[2.0],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [1])
AC_SUBST([PACKAGE_DEPS], ["globus-xio >= 0, globus-ftp-client >= 3, globus-gass-copy >= 4 netlogger-c >= 4"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign parallel-tests 1.11 tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])
AC_CONFIG_FILES(
        globus-gsi-credential-uninstalled.pc
        globus-gsi-credential.pc
        Makefile
        library/Doxyfile
	library/Makefile
	version.h)
AC_OUTPUT

AC_REVISION($Revision$)
AC_INIT(Makefile.am)

GLOBUS_INIT

AM_PROG_LIBTOOL

dnl config header goes here

dnl Initialize the automake rules the last argument
AM_INIT_AUTOMAKE($GPT_NAME, $GPT_VERSION)

LAC_DOXYGEN("../", "", "$GLOBUS_LOCATION/sbin/globus-vararg-enums-doxygen-filter.pl")

GLOBUS_FINALIZE

AC_OUTPUT(
	Makefile
	pkgdata/Makefile
        doxygen/Makefile
        doxygen/Doxyfile 
        doxygen/Doxyfile-internal
	pkgdata/pkg_data_src.gpt
        version.h
)
