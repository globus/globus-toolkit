AC_INIT([globus_xio_test],[4.4])
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

PACKAGE_DEPS="globus-xio >= 3 globus-common >= 14"
AC_SUBST(PACKAGE_DEPS)

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
dnl

AC_REVISION($Revision$)
AC_INIT(Makefile.am)

GLOBUS_INIT

AM_PROG_LIBTOOL

dnl config header goes here

dnl Initialize the automake rules the last argument
AM_INIT_AUTOMAKE($GPT_NAME, $GPT_VERSION)

CFLAGS="$CFLAGS -DGLOBUS_BUILTIN"
GLOBUS_FINALIZE

AC_OUTPUT(
	Makefile
        http-get-test.pl
        http-header-test.pl
        http-pingpong-test.pl
        http-post-test.pl
        http-put-test.pl
        http-throughput-test.pl
        http-timeout-test.pl
	pkgdata/Makefile
	pkgdata/pkg_data_src.gpt
	drivers/Makefile
	version.h
)
