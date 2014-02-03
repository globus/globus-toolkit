AC_PREREQ([2.60])

AC_INIT([globus_gram_protocol],[12.2],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [9])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-io >= 8, globus-gssapi-gsi >= 10, globus-gss-assist >= 8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign parallel-tests 1.11 tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([PERL], perl perl5)

AC_ARG_WITH([perlmoduledir],
AC_HELP_STRING([--with-perlmoduledir=DIR],
[perl module directory [PREFIX/lib/perl]]),
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

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])
AC_CONFIG_FILES(
        globus-gram-protocol-uninstalled.pc
        globus-gram-protocol.pc
        Makefile
        scripts/Makefile
        test/Makefile
        Doxyfile
	version.h)

AC_OUTPUT
