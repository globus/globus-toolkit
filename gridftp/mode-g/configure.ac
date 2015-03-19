AC_PREREQ([2.60])

AC_INIT([globus_xio_mode_g],[0.0],[https://globus.atlassian.net/])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [3])
AC_SUBST([PACKAGE_DEPS], ["globus-xio >= 3, globus-common >= 14"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])

AC_CONFIG_FILES(
        connection_driver/globus-xio-mode-g-connection-driver.pc
        connection_driver/Makefile
        transfer_driver/globus-xio-mode-g-transfer-driver.pc
        transfer_driver/Makefile
        globus-xio-mode-g-uninstalled.pc
	Makefile
        Doxyfile
        version.h
        test/Makefile
)
AC_OUTPUT
