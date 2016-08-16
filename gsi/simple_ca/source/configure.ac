AC_PREREQ([2.60])

AC_INIT([globus_simple_ca],[4.23],[https://github.com/globus/globus-toolkit/issues])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [1])
AC_SUBST([PACKAGE_DEPS], [""])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

AC_CANONICAL_HOST

grid_security_conf_tmpl="$srcdir/grid-security.conf.tmpl"
AC_SUBST_FILE(grid_security_conf_tmpl)
ca_signing_policy_tmpl="$srcdir/ca-signing-policy.tmpl"
AC_SUBST_FILE(ca_signing_policy_tmpl)
grid_ca_ssl_conf_tmpl="$srcdir/grid-ca-ssl.conf.tmpl"
AC_SUBST_FILE(grid_ca_ssl_conf_tmpl)

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
GLOBUS_COMMON_PATH=
PKG_CHECK_EXISTS([globus-common], [
    GLOBUS_COMMON_PATH="$($PKG_CONFIG --variable=path globus-common)"])
AC_SUBST([GLOBUS_COMMON_PATH])
AM_CONDITIONAL([CYGPATH_W_DEFINED], [
    case $host in
        *mingw32*)
        test x"$CYGPATH_W" != x;
        ;;
        *)
        false
        ;;
    esac])

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
        [globus-simple-ca-undefined.pc
        globus-simple-ca.pc
        Makefile
        test/Makefile])

AC_CONFIG_FILES([grid-ca-create], [chmod a+x grid-ca-create])
AC_CONFIG_FILES([grid-ca-package], [chmod a+x grid-ca-package])
AC_CONFIG_FILES([grid-ca-sign], [chmod a+x grid-ca-sign])

AC_OUTPUT
