AC_PREREQ([2.60])

AC_INIT([globus_gram_client],[13.1],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [10])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-gram-protocol >= 11, globus-io >= 9, globus-rsl >= 9, globus-gss-assist >= 8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

TEST_PACKAGE_DEPS="globus-gass-server-ez"
PKG_CHECK_MODULES([TEST_PACKAGE_DEP], $TEST_PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])


AC_ARG_WITH([perlmoduledir],
AC_HELP_STRING([--with-perlmoduledir=DIR],
[perl module directory [[PREFIX/lib/perl]]]),
[
    if test x$withval = "xno" -o x$withval = "xyes" ; then
        AC_MSG_ERROR([--with-perlmoduledir requires an argument])
    fi
    perlmoduledir=$withval
],
[
    perlmoduledir='${libdir}/perl'
])
AC_SUBST(perlmoduledir)


AC_CONFIG_FILES(
        globus-gram-client-uninstalled.pc
        globus-gram-client.pc
        Makefile
        test/Makefile
        Doxyfile
	version.h)
AC_CONFIG_FILES(
        [test/register-ping-test.pl],
        [chmod a+x test/register-ping-test.pl])

AC_CONFIG_FILES(
        [test/run-tests.pl],
        [chmod a+x test/run-tests.pl])
AC_CONFIG_FILES(
        [test/failed-job-two-phase-commit.pl],
        [chmod a+x test/failed-job-two-phase-commit.pl])
AC_CONFIG_FILES(
        [test/two-phase-commit-test.pl],
        [chmod a+x test/two-phase-commit-test.pl])

AC_OUTPUT
