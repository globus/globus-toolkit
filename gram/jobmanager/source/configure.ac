AC_PREREQ([2.60])

AC_INIT([globus_gram_job_manager],[14.0],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [1])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-gsi-credential >= 5, globus-gass-cache >= 8, globus-gass-transfer >= 7, globus-gram-protocol >= 11, globus-gssapi-gsi >= 10, globus-gss-assist >= 8, globus-gsi-sysconfig >= 5, globus-callout >= 2, globus-xio >= 3, globus-xio-popen-driver >= 2, globus-rsl >= 9, globus-gram-job-manager-callout-error >= 2, globus-scheduler-event-generator >= 4, globus-usage >= 3"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign parallel-tests 1.11 tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)


PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])

GLOBUS_TOOLKIT_VERSION="`globus-version`"
if test "x$GLOBUS_TOOLKIT_VERSION" = "x"; then
    GLOBUS_TOOLKIT_VERSION="UNKNOWN"
fi
AC_SUBST(GLOBUS_TOOLKIT_VERSION)

AM_PATH_XML2
if test "$ac_cv_have_libxml2" = "yes"; then
    AC_DEFINE(HAVE_LIBXML2)
fi

dnl Some preprocessor tricks to get CMSG_SPACE and co. defined in <sys/socket.h>
case $host in
       *solaris*)
           AC_DEFINE(__EXTENSIONS__)
           AC_DEFINE(_XOPEN_SOURCE)
           AC_DEFINE(_XOPEN_SOURCE_EXTENDED)
       ;;
esac

eval "LOGDIR=$localstatedir/log/globus"
AC_SUBST(LOGDIR)

eval AUDITDIR="$localstatedir/lib/globus/gram-audit"
AC_SUBST(AUDITDIR)

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
AC_PROG_LEX
AC_PROG_YACC

AM_CONDITIONAL(BUILD_MANPAGES, [
                test "$docbook_xsl_available" != "no" && \
                test "$docbook_dtd_available" != "no" && \
                test "$XSLTPROC" != "no" && \
                test "$XMLLINT" != "no"])
AC_OUTPUT(
	globus-gram-job-manager-uninstalled.pc
	globus-gram-job-manager.pc
	scripts/Makefile
        seg/Makefile
        rvf/Makefile
        globus-personal-gatekeeper
        globus-gram-job-manager.conf
        gram.logrotate
        Makefile
        version.h
)
AC_OUTPUT
