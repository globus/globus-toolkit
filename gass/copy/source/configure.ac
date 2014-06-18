AC_PREREQ([2.60])

AC_INIT([globus_gass_copy],[9.10],[https://globus.atlassian.net/])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [7])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 15, globus-ftp-client >= 7, globus-ftp-control >= 4, globus-gsi-sysconfig >= 4, globus-gass-transfer >= 7, globus-io >= 8, globus-gssapi-gsi >= 9, globus-gssapi-error >= 4, openssl >= 0.9.8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

AC_CANONICAL_HOST
AM_CONDITIONAL([CYGPATH_W_DEFINED], [
    case $host in
        *mingw32*)
        test x"$CYGPATH_W" != x;
        ;;
        *)
        false
        ;;
    esac])

AM_CONDITIONAL([MINGW32], [
    case $host in 
        *mingw32*)
        true
        ;;
    *)
        false
        ;;
esac])
PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

PKG_CHECK_EXISTS([globus-xio-gsi-driver >= 2], [
    GSI_DRIVER_CFLAGS="$($PKG_CONFIG --cflags globus-xio-gsi-driver)"
    GSI_DRIVER_LIBS="$($PKG_CONFIG --variable=dlopen globus-xio-gsi-driver)"])
if test x"$GSI_DRIVER_LIBS" = x; then
    DLPREOPEN_FORCE="-dlpreopen force"
fi
PKG_CHECK_EXISTS([globus-xio-pipe-driver >= 2], [
    PIPE_DRIVER_LIBS="$($PKG_CONFIG --variable=dlopen globus-xio-pipe-driver)"])
if test x"$PIPE_DRIVER_LIBS" = x; then
    DLPREOPEN_FORCE="-dlpreopen force"
fi
AC_SUBST([GSI_DRIVER_CFLAGS])
AC_SUBST([GSI_DRIVER_LIBS])
AC_SUBST([PIPE_DRIVER_LIBS])
AC_SUBST([DLPREOPEN_FORCE])

PKG_CHECK_EXISTS([globus-gridftp-server], [
    GRIDFTP_SERVER_PATH="$($PKG_CONFIG --variable=path globus-gridftp-server)"])
AC_SUBST([GRIDFTP_SERVER_PATH])

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])

AC_MSG_CHECKING([Toolkit version])
if test "X$GLOBUS_TOOLKIT_ID" = "X"; then
    if test "X$GLOBUS_VERSION" = "X"; then
        if test -x ${GLOBUS_LOCATION-/usr}/bin/globus-version; then
            GLOBUS_TOOLKIT_ID="`${GLOBUS_LOCATION-/usr}/bin/globus-version -full`"
        else
            GLOBUS_TOOLKIT_ID="unknown"
        fi
    else
        GLOBUS_TOOLKIT_ID="Globus Toolkit $GLOBUS_VERSION"
    fi
fi
AC_MSG_RESULT($GLOBUS_TOOLKIT_ID)
AC_SUBST(GLOBUS_TOOLKIT_ID)

AC_PATH_PROG(XSLTPROC, "xsltproc")
AC_PATH_PROG(XMLLINT, "xmllint")
AC_MSG_CHECKING([docbook dtd])
DOCBOOK_DTD=http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd
docbook_dtd_available=no

if test "$XMLLINT" != no; then
    cat <<EOF | $XMLLINT --nonet --dtdvalid $DOCBOOK_DTD - > /dev/null 2>&1
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE jobtitle PUBLIC "-//OASIS//DTD DocBook XML V4.4//EN" "http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd">
<jobtitle/>
EOF
    if test $? = 0; then
        docbook_dtd_available=yes
    fi
fi
AC_MSG_RESULT($docbook_dtd_available)
AC_SUBST(DOCBOOK_DTD)

AC_MSG_CHECKING([docbook xsl])
MAN_XSL=http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl
docbook_xsl_available=no

if test "$XSLTPROC" != no; then
    cat <<EOF | $XSLTPROC --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl  - > /dev/null 2>&1
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE jobtitle PUBLIC "-//OASIS//DTD DocBook XML V4.4//EN" "http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd">
<jobtitle/>
EOF
    if test $? = 0; then
        docbook_xsl_available=yes
    fi
fi
AC_MSG_RESULT($docbook_xsl_available)
AC_SUBST(MAN_XSL)

AM_CONDITIONAL(BUILD_MANPAGES, [
                test "$docbook_xsl_available" != "no" && \
                test "$docbook_dtd_available" != "no" && \
                test "$XSLTPROC" != "no" && \
                test "$XMLLINT" != "no"])

AC_CONFIG_FILES(
        Doxyfile
        globus-gass-copy-uninstalled.pc
        globus-gass-copy.pc
        Makefile
	version.h
        test/Makefile
        test/openssl.cnf)
AC_OUTPUT
