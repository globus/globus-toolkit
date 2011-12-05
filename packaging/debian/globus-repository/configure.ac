AC_INIT(globus_repository, 0.0.2)
AM_INIT_AUTOMAKE([foreign])

AC_ARG_WITH(
	[bamboo-artifact-url],
	AC_HELP_STRING(
		[--with-bamboo-artifact-url=URL],
		[URL where Bamboo stores the artifacts for this build]),
	bamboo_artifact_url="$withval",
	bamboo_artifact_url="no")

AC_ARG_WITH(
	[toolkit-version],
	AC_HELP_STRING(
		[--with-toolkit-version=MAJOR.MINOR.MICRO],
		[Globus Toolkit Version]),
	globus_toolkit_version="$withval",
	globus_toolkit_version="no")

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

case "$bamboo_artifact_url" in
	yes|no)
		BAMBOO_ARTIFACT_URL=invalid
		;;
	*)
		BAMBOO_ARTIFACT_URL="$bamboo_artifact_url"
		;;
esac

case "$globus_toolkit_version" in
	*.*.*)
		TOOLKIT_VERSION="${globus_toolkit_version}"
		TOOLKIT_MAJOR_VERSION="${globus_toolkit_version%%.*}"
		TOOLKIT_MINOR_VERSION="${globus_toolkit_version%.*}"
		TOOLKIT_MINOR_VERSION="${TOOLKIT_MINOR_VERSION#*.}"
		TOOLKIT_MICRO_VERSION="${globus_toolkit_version##*.}"
		;;
	*)
		TOOLKIT_VERSION="invalid"
		;;
esac


AM_CONDITIONAL(
	[CREATE_BAMBOO_SOURCES_LIST],
	[test "$BAMBOO_ARTIFACT_URL" != "invalid"])

AM_CONDITIONAL(
	[CREATE_VERSIONED_SOURCES_LIST],
	[test "$TOOLKIT_VERSION" != "invalid"])

AC_SUBST(BAMBOO_ARTIFACT_URL)
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
	globus-bamboo.list
)
