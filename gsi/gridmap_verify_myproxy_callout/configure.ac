AC_PREREQ([2.60])

AC_INIT([globus_gridmap_verify_myproxy_callout],[2.4],[https://globus.atlassian.net/])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [2])
AC_SUBST([PACKAGE_DEPS], ["globus-gsi-sysconfig >= 1, globus-gssapi-gsi >= 4, globus-gss-assist >= 3, globus-gridmap-callout-error >= 0, globus-gsi-credential >= 6"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_CONFIG_FILES(
        globus-gridmap-verify-myproxy-callout-uninstalled.pc
        globus-gridmap-verify-myproxy-callout.pc
        Makefile
	gridmap_verify_myproxy_callout-gsi_authz.conf
	version.h)
AC_OUTPUT
