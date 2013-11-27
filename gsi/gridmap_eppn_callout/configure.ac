AC_INIT([globus_gridmap_eppn_callout],[0.6])
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=0

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS="globus-gsi-sysconfig >= 1 globus-gssapi-gsi >= 4 globus-gss-assist >= 3 globus-gridmap-callout-error >= 0 globus-gsi-credential >= 6 openssl >= 0.9.8"
AC_SUBST(PACKAGE_DEPS)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_CONFIG_FILES(
        globus-gridmap-eppn-callout-uninstalled.pc
        globus-gridmap-eppn-callout.pc
	gridmap_eppn_callout-gsi_authz.conf
        Makefile
	version.h)
AC_OUTPUT
