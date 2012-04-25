AC_INIT(globus_repository, 0.0.3)
AM_INIT_AUTOMAKE([foreign])

AC_ARG_WITH(
	[toolkit-version],
	AC_HELP_STRING(
		[--with-toolkit-version=MAJOR.MINOR.MICRO],
		[Globus Toolkit Version]),
	globus_toolkit_version="$withval",
        if command -v globus-version > /dev/null 2>&1; then
            globus_toolkit_version=`globus-version`
        else
            dnl no idea
	    globus_toolkit_version="0.0.0"
        fi)

DEBIAN_DISTRO_NAME=$(lsb_release -si | tr '[[:upper:]]' '[[:lower:]]')
DEBIAN_VERSION_NAME=$(lsb_release -sc)
DEBIAN_VERSION=$(lsb_release -sr)
DEBIAN_ARCH=$(dpkg-architecture -qDEB_BUILD_ARCH)

if test "$DEBIAN_DISTRO_NAME" = "debian" ; then
    DEBIAN_VERSION="${DEBIAN_VERSION%%.*}"
fi

if test "$DEBIAN_ARCH" = "amd64"; then
    DEBIAN_ARCH="x86_64"
fi

case "$globus_toolkit_version" in
	*.*.*)
		TOOLKIT_VERSION="${globus_toolkit_version}"
		TOOLKIT_MAJOR_VERSION="${globus_toolkit_version%%.*}"
		TOOLKIT_MINOR_VERSION="${globus_toolkit_version%.*}"
		TOOLKIT_MINOR_VERSION="${TOOLKIT_MINOR_VERSION#*.}"
		TOOLKIT_MICRO_VERSION="${globus_toolkit_version##*.}"
		;;
	*)
		TOOLKIT_VERSION="0.0.0"
		TOOLKIT_MAJOR_VERSION="0"
		TOOLKIT_MINOR_VERSION="0"
		TOOLKIT_MICRO_VERSION="0"
		;;
esac


AC_SUBST(DEBIAN_DISTRO_NAME)
AC_SUBST(DEBIAN_VERSION_NAME)
AC_SUBST(DEBIAN_VERSION)
AC_SUBST(DEBIAN_ARCH)
AC_SUBST(TOOLKIT_VERSION)
AC_SUBST(TOOLKIT_MAJOR_VERSION)
AC_SUBST(TOOLKIT_MINOR_VERSION)
AC_SUBST(TOOLKIT_MICRO_VERSION)

AC_OUTPUT(
	Makefile
	globus.list
        globus-testing.list
        globus-stable.list
)
