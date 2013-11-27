AC_INIT([globus_gram_protocol],[11.3])
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=8

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="globus-common >= 14 globus-io >= 8 globus-gssapi-gsi >= 10 globus-gss-assist >= 8"
AC_SUBST(PACKAGE_DEPS)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([PERL], perl perl5)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])
AC_CONFIG_FILES(
        globus-gram-protocol-uninstalled.pc
        globus-gram-protocol.pc
        Makefile
        scripts/Makefile
        Doxyfile
	version.h)

AC_OUTPUT
