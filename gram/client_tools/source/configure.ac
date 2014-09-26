AC_PREREQ([2.60])

AC_INIT([globus_gram_client_tools],[11.6],[https://globus.atlassian.net/])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [1])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-gram-client >= 12, globus-gram-protocol >= 11, globus-gass-transfer >= 7, globus-gass-server-ez >= 4, globus-rsl >= 9, globus-gss-assist >= 8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

PKG_CHECK_EXISTS([globus-xio-gsi-driver >= 2], [
    GLOBUS_XIO_GSI_DRIVER_DLOPEN="$($PKG_CONFIG --variable=dlopen globus-xio-gsi-driver)"])
AC_SUBST([GLOBUS_XIO_GSI_DRIVER_DLOPEN])

if test -z "$GLOBUS_XIO_GSI_DRIVER_DLOPEN"; then
    PREOPEN_FORCE="-dlpreopen force"
fi
AC_SUBST([PREOPEN_FORCE])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

case $build:$host in 
    *cygwin*:*mingw*)
        use_cygpath_w=true
        ;;
    *)
        use_cygpath_w=false
        ;;
esac

AM_CONDITIONAL([USE_CYGPATH_W], [test "$use_cygpath_w" = "true"])
    

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

AC_PATH_PROG(A2X, [a2x.py], [no])
AM_CONDITIONAL([HAVE_A2X], [test "$A2X" != "no"])

AC_CONFIG_FILES(
        [globus-gram-client-tools-uninstalled.pc
        globus-gram-client-tools.pc
        Makefile
	version.h])
AC_CONFIG_FILES(
        [globus-job-cancel:globus-job-clean.in],
        [chmod a+x globus-job-cancel])
AC_CONFIG_FILES(
        [globus-job-clean], [chmod a+x globus-job-clean])
AC_CONFIG_FILES(
        [globus-job-submit:globus-job-run.in], [chmod a+x globus-job-submit])
AC_CONFIG_FILES(
        [globus-job-run], [chmod a+x globus-job-run])
AC_CONFIG_FILES(
        [globus-job-status], [chmod a+x globus-job-status])
AC_CONFIG_FILES(
        [globus-job-get-output], [chmod a+x globus-job-get-output])
AC_OUTPUT
