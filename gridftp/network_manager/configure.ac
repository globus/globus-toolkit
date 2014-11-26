AC_PREREQ([2.60])

AC_INIT([globus_net_manager],[0.0],[https://globus.atlassian.net/])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [0])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-xio >= 3"])

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
        globus-net-manager-uninstalled.pc
        globus-net-manager.pc
        Makefile
        Doxyfile
        attr/Makefile
        context/Makefile
        exec/Makefile
        logging/Makefile
        python/Makefile
        test/Makefile
        xio_driver/Makefile
        xio_driver/globus-xio-net-manager-driver-uninstalled.pc
        xio_driver/globus-xio-net-manager-driver.pc
	version.h)
AC_OUTPUT
