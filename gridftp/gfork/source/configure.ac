AC_INIT([globus_gfork], [3.2])
AM_INIT_AUTOMAKE()
AM_PROG_LIBTOOL

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=3

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="globus-common >= 14 globus-xio >= 3"
AC_SUBST(PACKAGE_DEPS)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

case $host in
    *mingw* | win* | cygwin*)
        GFORK_EXE=""
        ;;
    *)
        GFORK_EXE=gfork
        ;;
esac
AC_SUBST(GFORK_EXE)

AC_OUTPUT(
	Makefile
        version.h
        globus-gfork.pc
        globus-gfork-uninstalled.pc
)
