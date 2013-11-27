AC_INIT([globus_gsi_proxy_ssl], [4.1])
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=3

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)
PACKAGE_DEPS="openssl >= 0.9.8"
AC_SUBST(PACKAGE_DEPS)
PKG_CHECK_MODULES([PACKAGE_DEP], [$PACKAGE_DEPS])

AC_PATH_PROGS([DOXYGEN], doxygen)
AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != "no"])

AC_OUTPUT(
        Makefile
        globus-gsi-proxy-ssl.pc
        globus-gsi-proxy-ssl-uninstalled.pc
	library/Makefile
        library/Doxyfile
)
