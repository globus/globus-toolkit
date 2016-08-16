AC_PREREQ([2.60])

AC_INIT([globus_gsi_proxy_ssl], [5.9],[https://github.com/globus/globus-toolkit/issues])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [4])
AC_SUBST([PACKAGE_DEPS], ["openssl >= 0.9.8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

PKG_CHECK_MODULES([PACKAGE_DEP], [$PACKAGE_DEPS])

AC_PATH_PROGS([DOXYGEN], doxygen)
AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != "no"])

AC_CONFIG_FILES(
        Makefile
        globus-gsi-proxy-ssl.pc
        globus-gsi-proxy-ssl-uninstalled.pc
	library/Makefile
        library/Doxyfile
        test/Makefile
)
AC_OUTPUT
