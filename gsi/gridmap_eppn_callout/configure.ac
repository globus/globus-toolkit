AC_PREREQ([2.60])

AC_INIT([globus_gridmap_eppn_callout],[1.6],[https://globus.atlassian.net/])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [1])
AC_SUBST([PACKAGE_DEPS], ["globus-gsi-sysconfig >= 1, globus-gssapi-gsi >= 4, globus-gss-assist >= 3, globus-gridmap-callout-error >= 0, globus-gsi-credential >= 6, openssl >= 0.9.8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_CONFIG_FILES(
        globus-gridmap-eppn-callout-uninstalled.pc
        globus-gridmap-eppn-callout.pc
	gridmap_eppn_callout-gsi_authz.conf
        Makefile
	version.h)
AC_OUTPUT
