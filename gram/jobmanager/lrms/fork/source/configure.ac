AC_PREREQ([2.60])

AC_INIT([globus_gram_job_manager_fork],[2.1],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [1])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-xio >= 3, globus-scheduler-event-generator >= 4, globus-gram-protocol >= 11"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])
AM_PROG_CC_C_O

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROG(MPIEXEC, mpiexec, no)
if test "$MPIEXEC" = "no" ; then
    AC_MSG_WARN([Cannot locate mpiexec])
fi

AC_PATH_PROG(MPIRUN, mpirun, no)
if test "$MPIRUN" = "no" ; then
    AC_MSG_WARN([Cannot locate mpirun])
fi

# SoftEnv installation directory
AC_ARG_WITH(softenv-dir,
   AC_HELP_STRING([--with-softenv-dir], [softenv_install_dir]),
   [SOFTENV_DIR=$withval],
   [SOFTENV_DIR=''])

AC_SUBST(SOFTENV_DIR)

AC_ARG_WITH(globus-state-dir,
	AC_HELP_STRING(
		[--with-globus-state-dir=PATH],
		[Path to Globus state files]),
	globusstatedir="$withval",
	globusstatedir=$localstatedir)

# GRAM-333: SEG config in installer has variables that aren't resolved at
# runtime
globusstatedir="`eval echo $globusstatedir`"
AC_SUBST(globusstatedir)

AC_ARG_WITH(seg,
	AC_HELP_STRING(
		[--with-seg=yes|no],
		[Enable GRAM configuration with the SEG module]),
	SEG_ENABLED="$withval",
	SEG_ENABLED="no")
case "$SEG_ENABLED" in
	yes)
	    SEG_CLAUSE="-seg-module fork"
	    ;;
	no)
	    SEG_CLAUSE=""
	    ;;
	*)
	    AC_MSG_ERROR([Invalid argument to --with-seg])
	    ;;
esac

AC_SUBST(SEG_CLAUSE)
AM_CONDITIONAL(SEG_ENABLED_COND, [test "$SEG_ENABLED" = "yes"])

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

AC_ARG_WITH([perlmoduledir],
AC_HELP_STRING([--with-perlmoduledir=DIR],
[perl module directory [[PREFIX/lib/perl]]]),
[
    if test x$withval = "xno" -o x$withval = "xyes" ; then
        AC_MSG_ERROR([--with-perlmoduledir requires an argument])
    fi
    perlmoduledir=$withval
],
[
    perlmoduledir='${libdir}/perl'
])
AC_SUBST(perlmoduledir)
AC_CONFIG_FILES(
        globus-gram-job-manager-fork-uninstalled.pc
        globus-gram-job-manager-fork.pc
	Makefile
	globus-fork.conf
	starter/Makefile
	seg/Makefile
	version.h)
AC_OUTPUT
