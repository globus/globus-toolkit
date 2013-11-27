AC_INIT([globus_gram_audit],[3.2])
AM_INIT_AUTOMAKE

MAJOR_VERSION=${PACKAGE_VERSION%%.*}
MINOR_VERSION=${PACKAGE_VERSION##*.}
AGE_VERSION=0

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(AGE_VERSION)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PACKAGE_DEPS=""

AC_SUBST(PACKAGE_DEPS)

AC_ARG_WITH(
    [driver],
    AC_HELP_STRING([--with-driver=DRIVER], [Set name of DBI Driver to use]),
    [AUDIT_DRIVER="$withval"],
    [AUDIT_DRIVER="SQLite"])

AC_SUBST(AUDIT_DRIVER)

AC_ARG_WITH(
    [database],
    AC_HELP_STRING([--with-database=DBNAME], [Set contact string for the database to use]),
    [AUDIT_DATABASE="$withval"],
    [AUDIT_DATABASE=dbname=${localstatedir}/lib/globus/gram-audit-database])
AC_SUBST(AUDIT_DATABASE)

AC_ARG_WITH(
    [username],
    AC_HELP_STRING([--with-username=USERNAME], [Set database username]),
    [AUDIT_USERNAME="$withval"],
    [AUDIT_USERNAME=""])
AC_SUBST(AUDIT_USERNAME)

AC_ARG_WITH(
    [password],
    AC_HELP_STRING([--with-password=PASSWORD], [Set database password]),
    [AUDIT_PASSWORD="$withval"],
    [AUDIT_PASSWORD=""])
AC_SUBST(AUDIT_PASSWORD)

AC_ARG_WITH(
    [schema-version],
    AC_HELP_STRING([--with-schema-version=1|1TG],
        [Choose database schema version]),
    [AUDIT_VERSION="$withval"],
    [AUDIT_VERSION="1TG"])
AC_SUBST(AUDIT_VERSION)

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
        globus-gram-audit-uninstalled.pc
        globus-gram-audit.pc
        Makefile
        globus-gram-audit
        globus-gram-audit.cron
        gram-audit.conf
        schemas/Makefile)
AC_OUTPUT
