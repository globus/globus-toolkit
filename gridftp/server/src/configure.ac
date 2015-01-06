AC_PREREQ([2.60])

AC_INIT([globus_gridftp_server],[7.20],[https://globus.atlassian.net/])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [1])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 15, globus-xio >= 5, globus-xio-gsi-driver >= 2, globus-gfork >= 3, globus-gridftp-server-control >= 2, globus-ftp-control >= 6, globus-authz >= 2, globus-usage >= 3, globus-gssapi-gsi >= 10, globus-gss-assist >= 9, globus-gsi-credential >= 6, globus-gsi-sysconfig >= 5, globus-io >= 9, openssl >= 0.9.8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])
AC_PROG_CC

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_ARG_WITH([preloaded-modules],
    AS_HELP_STRING([--with-preloaded-modules=MODULE,...],
        [Use libtool to preload MODULES when built statically]),
    [if test x"$withval" != x; then
        preload_modules="$withval"
    fi])

if test x"$preload_modules" != x; then
    preload_modules="$(echo $preload_modules | tr , ' ')"
    for module in $preload_modules; do
        module_found=no
        AC_MSG_CHECKING([for $module mode])
        PKG_CHECK_EXISTS([$module], [
            preload_links="$preload_links $($PKG_CONFIG --variable=dlopen $module)"
            module_found=yes],
            [module_found=no])
        AC_MSG_RESULT([$module_found])
        if test x"$module" = x"globus-xio-udt-driver"; then
            link_with_cxx=1
        fi
    done
fi

AC_PROG_CXX

if test x"$preload_links" = x; then
    preload_links="-dlpreopen force"
    link_with_cxx=0
fi
if test "x$link_with_cxx" = x1; then
    AC_MSG_NOTICE([Linking with C++])
fi
AM_CONDITIONAL([LINK_WITH_CXX], [test x"$link_with_cxx" = x1])
AC_SUBST([preload_links])

AC_MSG_CHECKING([builtin modules])
m4_define([gridftp_modules], m4_normalize(
    m4_esyscmd([ls modules/*/Makefile.am | cut -d/ -f2])))
m4_define([modules_dirs], m4_normalize(m4_foreach(modn, m4_split(gridftp_modules),
    [modules/]modn[ ])))
m4_define([modules_makefiles], 
    m4_normalize(m4_foreach(modd, m4_split(modules_dirs),
        [modd[/Makefile ]])))
m4_define([modules_libs], m4_normalize(
    m4_foreach(modl, m4_split(gridftp_modules),
    [[modules/]modl[/libglobus_gridftp_server_]modl[.la ]])))
m4_define([builtin_extensions_dec], m4_foreach(modl, m4_split(gridftp_modules),
    [[GlobusExtensionDeclareModule(globus_gridftp_server_]modl[);]]))
m4_define([builtin_extensions_def],
    m4_foreach(modl, m4_split(gridftp_modules),
    [[{\"globus_gridftp_server_]modl[\", GlobusExtensionMyModule(globus_gridftp_server_]modl[)},]]))
MODULE_DIRS="gridftp_modules"
MODULE_LIBS="modules_libs"
MODULE_MAKEFILES="modules_makefiles"
BUILTIN_EXTENSIONS_DEC="builtin_extensions_dec"
BUILTIN_EXTENSIONS_DEF="builtin_extensions_def"
AC_MSG_RESULT(gridftp_modules)

if test "X$GRIDMAP" != "X" ; then
    GRIDMAP_CONF="-df $GRIDMAP"
else
    if test -f $HOME/.gridmap ; then
        GRIDMAP_CONF="-df $HOME/.gridmap"
    else
        if test -f /etc/grid-security/grid-mapfile ; then
            GRIDMAP_CONF="-df /etc/grid-security/grid-mapfile"
        else
            GRIDMAP_CONF=""
        fi
    fi
fi

AC_SUBST(GRIDMAP_CONF)
AC_SUBST(GLOBUS_LOCATION)
AC_SUBST(MODULE_DIRS)
AC_SUBST(MODULE_LIBS)
AC_SUBST(BUILTIN_EXTENSIONS_DEC)
AC_SUBST(BUILTIN_EXTENSIONS_DEF)

AC_CHECK_FUNCS(fgetpwent)
AC_C_BIGENDIAN

AC_PATH_PROGS(PERL, perl perl5)

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

reset_exec_prefix_to_none=0
if test x"${exec_prefix}" = xNONE; then
    reset_exec_prefix_to_none=1
    exec_prefix="${prefix}"
fi
eval "conf_sbindir=\"$sbindir\""
eval "conf_bindir=\"$bindir\""
eval "conf_libdir=\"$libdir\""
eval "conf_sysconfdir=\"$sysconfdir\""
eval "conf_localstatedir=\"$localstatedir\""

if test "$reset_exec_prefix_to_none" = 1 ; then
    exec_prefix="NONE"
fi

case "$conf_libdir" in
    /usr/lib|/usr/lib64)
        libdir_line=""
        ;;
    *)
        libdir_line="env += LD_LIBRARY_PATH=${conf_libdir}"
        ;;
esac

AC_SUBST(libdir_line)
AC_SUBST(conf_sbindir)
AC_SUBST(conf_bindir)
AC_SUBST(conf_libdir) 
AC_SUBST(conf_sysconfdir) 
AC_SUBST(conf_localstatedir)

AC_ARG_WITH(default-runlevels,
        AC_HELP_STRING(
            [--with-default-runlevels=RUNLEVELS],
            [Choose which System-V style runlevels the gatekeeper service will
             be started on.]),
            [ case "$withval" in
                yes)
                  AC_MSG_WARN([Invalid parameter to --with-default-runlevels])
                  ;;
                no)
                  CHKCONFIG_DEFAULT="-"
                  DEFAULT_START=""
                  DEFAULT_STOP=""
                  ;;
                *)
                  CHKCONFIG_DEFAULT="$withval"
                  for r in 0 1 2 3 4 5 6; do
                      if expr $withval : ".*$r.*" > /dev/null; then
                          DEFAULT_START="${DEFAULT_START:+$DEFAULT_START }$r"
                      else
                          DEFAULT_STOP="${DEFAULT_STOP:+$DEFAULT_STOP }$r"
                      fi
                  done
              esac],
            [
                CHKCONFIG_DEFAULT="-"
                DEFAULT_START=""
                DEFAULT_STOP=""
            ])

if test "$DEFAULT_START" = ""; then
    DEFAULT_START_LINE="#"
else
    DEFAULT_START_LINE="# Default-Start:     $DEFAULT_START"
fi
if test "$DEFAULT_STOP" = ""; then
    DEFAULT_STOP_LINE="#"
else
    DEFAULT_STOP_LINE="# Default-Stop:      $DEFAULT_STOP"
fi

AC_SUBST(CHKCONFIG_DEFAULT)
AC_SUBST(DEFAULT_START_LINE)
AC_SUBST(DEFAULT_STOP_LINE)

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

AC_CONFIG_HEADERS(globus_i_gridftp_server_config.h)

AC_CONFIG_FILES(
    globus-gridftp-server.pc
    globus-gridftp-server-uninstalled.pc
    globus-gridftp-password
    globus-gridftp-server-enable-sshftp
    Makefile
    modules_makefiles
    modules/Makefile
    init/Makefile
    init/globus-gridftp-server
    init/globus-gridftp-sshftp
    gridftp.conf.default
    gridftp.xinetd.default
    gridftp.gfork.default
    version.h
    extensions.h)

AC_OUTPUT
