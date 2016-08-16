AC_PREREQ([2.60])

AC_INIT([globus_gsi_cert_utils], [9.14], [https://github.com/globus/globus-toolkit/issues])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [9])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-openssl-module >= 3, globus-gsi-openssl-error >= 2, openssl >= 0.9.8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], [$PACKAGE_DEPS])

AC_CONFIG_HEADERS(globus_i_gsi_cert_utils_config.h)

AC_MSG_CHECKING(checking for time_t timezone in <time.h>)
AC_TRY_COMPILE(
        [
        #include <time.h>
        ],
        [
        struct tm y;
        time_t offset = 3;
        time_t x = mktime(&y) + offset*60*60 - timezone;
        ],
        [answer=yes],
        [answer=no]
)
if test "X$answer" = "Xyes" ; then
   AC_MSG_RESULT(yes)
   AC_DEFINE(HAVE_TIME_T_TIMEZONE, [1], [if time_t timezone is in <time.h>])
else
   dnl
   dnl only place this should occur is on CYGWIN B20, which has an
   dnl integer _timezone defined instead
   dnl
   AC_MSG_CHECKING(checking for time_t _timezone in <time.h>)
   AC_TRY_COMPILE(
        [
        #include <time.h>
        ],
        [
        struct tm y;
        time_t offset = 3;
        time_t x = mktime(&y) + offset*60*60 - _timezone;
        ],
        [answer=yes]
        [answer=no]
   )
   if test "X$answer" = "Xyes" ; then   
       AC_MSG_RESULT(yes)
       AC_DEFINE(HAVE_TIME_T__TIMEZONE, [1], [existence of time_t _timezone])
   else
       AC_MSG_RESULT(no)
   fi
fi
AC_CHECK_FUNCS(timegm)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != "no"])

if test "X$GLOBUS_VERSION" = "X"; then
    if test -x ${GLOBUS_LOCATION-/usr}/bin/globus-version; then
        GLOBUS_VERSION="`${GLOBUS_LOCATION-/usr}/bin/globus-version`"
    else
        GLOBUS_VERSION="unknown"
    fi
fi
AC_SUBST(GLOBUS_VERSION)

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

AC_CONFIG_FILES([
        Makefile
        globus-gsi-cert-utils.pc
        globus-gsi-cert-utils-uninstalled.pc
	library/Makefile
	library/Doxyfile
        programs/Makefile
        test/Makefile
	version.h])
AC_CONFIG_FILES(
    [programs/grid-cert-info],
    [chmod a+x programs/grid-cert-info])
AC_CONFIG_FILES(
    [programs/grid-change-pass-phrase],
    [chmod a+x programs/grid-change-pass-phrase])
AC_CONFIG_FILES(
    [programs/grid-cert-request],
    [chmod a+x programs/grid-cert-request])
AC_CONFIG_FILES(
    [programs/grid-default-ca],
    [chmod a+x programs/grid-default-ca])
AC_CONFIG_FILES(
    [programs/globus-update-certificate-dir],
    [chmod a+x programs/globus-update-certificate-dir])

AC_OUTPUT
