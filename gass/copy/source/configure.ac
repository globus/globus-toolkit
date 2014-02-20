AC_PREREQ([2.60])

AC_INIT([globus_gass_copy],[9.3],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [7])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-ftp-client >= 7, globus-ftp-control >= 4, globus-gsi-sysconfig >= 4, globus-gass-transfer >= 7, globus-io >= 8, globus-gssapi-gsi >= 9, globus-gssapi-error >= 4, openssl >= 0.9.8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

GSI_DRIVER_LIBDIR=`pkg-config --variable=libdir globus-xio-gsi-driver`
GSI_DRIVER=""
for ext in .la .so .dylib .a; do
    if test -r $GSI_DRIVER_LIBDIR/libglobus_xio_gsi_driver${ext}; then
        GSI_DRIVER=$GSI_DRIVER_LIBDIR/libglobus_xio_gsi_driver${ext} 
        break
    fi
done

AC_SUBST(GLOBUS_XIO_GSI_DRIVER, $GSI_DRIVER)

PIPE_DRIVER_LIBDIR=`pkg-config --variable=libdir globus-xio-pipe-driver`
PIPE_DRIVER=""
for ext in .la .so .dylib .a; do
    if test -r $PIPE_DRIVER_LIBDIR/libglobus_xio_pipe_driver${ext}; then
        PIPE_DRIVER=$PIPE_DRIVER_LIBDIR/libglobus_xio_pipe_driver${ext} 
        break
    fi
done

AC_SUBST(GLOBUS_XIO_PIPE_DRIVER, $PIPE_DRIVER)

GRIDFTP_SBINDIR=`pkg-config --variable=sbindir globus-gridftp-server`
AC_SUBST(GRIDFTP_SBINDIR, $GRIDFTP_SBINDIR)
AM_CONDITIONAL([GRIDFTP_TESTS],
  [ test "$GSI_DRIVER" != "" && \
    test "$PIPE_DRIVER" != "" && \
    test -d "$GRIDFTP_SBINDIR"])

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])

GLOBUS_TOOLKIT_ID=unknown
if test -x ${GLOBUS_LOCATION-/usr}/bin/globus-version ; then
    GLOBUS_TOOLKIT_ID="`${GLOBUS_LOCATION-/usr}/bin/globus-version -full`"
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
        test/Makefile)
AC_OUTPUT
