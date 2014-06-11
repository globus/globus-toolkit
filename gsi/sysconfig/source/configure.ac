AC_PREREQ([2.60])

AC_INIT([globus_gsi_sysconfig], [6.6],[https://globus.atlassian.net/])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [5])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-openssl-module >= 3, globus-gsi-openssl-error >= 2, openssl >= 0.9.8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])
AC_CONFIG_HEADERS(globus_i_gsi_sysconfig_config.h)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != "no"])

AC_CHECK_HEADERS([unistd.h dirent.h])
AC_CHECK_FUNCS([geteuid])

AC_OUTPUT(
        Makefile
	library/Makefile
        library/Doxyfile
        globus-gsi-sysconfig.pc
        globus-gsi-sysconfig-uninstalled.pc
	version.h
)
