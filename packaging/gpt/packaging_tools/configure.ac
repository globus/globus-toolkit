AC_REVISION($Revision$)
AC_INIT(gpt, 3.6.2)
AC_CONFIG_SRCDIR(Makefile.am)
AM_INIT_AUTOMAKE([foreign])
 
AC_ARG_WITH([perl],
    AC_HELP_STRING([--with-perl=PATH],
            [Specify path to perl binary]),
[
	case $withval in
	no|yes)
		AC_MSG_ERROR([--with-perl requires an argument])
		;;
	*)
                PERL=$withval
                AC_SUBST(PERL) 
		;;
	esac
],
[
        AC_PATH_PROG(PERL,perl)
]
)

AC_PATH_PROG(POD2MAN, pod2man)
AM_CONDITIONAL(INSTALL_MANS, test "x$POD2MAN" != "x")

AC_ARG_WITH([perlmoduledir],
    AC_HELP_STRING([--with-perlmoduledir=PATH],
            [Install GPT perl modules in PATH]),
[
        case "$withval" in
            no|yes)
                AC_MSG_ERROR([--with-perlmoduledir requires an argument])
                ;;
            *)
                perlmoduledir="$withval"
                ;;
        esac
],
        perlmoduledir='${libdir}/perl'
)

AC_SUBST(perlmoduledir)


AC_SUBST(POD2MAN)

# checking for the GPT_LOCATION

AC_PREFIX_DEFAULT(${GPT_LOCATION:-/usr/local})

AC_PATH_PROGS(GTAR, gtar tar)
AC_PATH_PROGS(GUNZIP, gunzip)
AC_PATH_PROGS(GZIP, gzip)
AC_PROG_LN_S

AC_SUBST(GPT_LOCATION)

initializer_prefix="$prefix"
test "$initializer_prefix" = "NONE" && initializer_prefix="$ac_default_prefix"
initializer_exec_prefix="$exec_prefix"
test "$initializer_exec_prefix" = "NONE" && initializer_exec_prefix='${prefix}'
test "$datarootdir" = "" && datarootdir='${prefix}/share'
gptdatadir='${datadir}/globus/gpt'
gptexecsharedir='${datadir}/globus/gpt'
amdir='${datadir}/globus/amdir'
pkg_confdir='${datadir}/globus/gpt'
aclocaldir='${datadir}/globus/aclocal'

AC_SUBST(gptdatadir)
AC_SUBST(gptexecsharedir)
AC_SUBST(amdir)
AC_SUBST(pkg_confdir)
AC_SUBST(aclocaldir)

cat > gpt-perl-initializer << EOF
my (\$prefix, \$globus_prefix, \$exec_prefix, \$bindir, \$sbindir, \$libdir);
my (\$datarootdir, \$datadir, \$perlmoduledir, \$gptdatadir);
my (\$gptexecsharedir, \$amdir, \$pkg_confdir, \$aclocaldir);

if (exists \$ENV{GPT_LOCATION})
{
    \$prefix = \$ENV{GPT_LOCATION};
}
else
{
    \$prefix = "$initializer_prefix";
}

if (exists \$ENV{GLOBUS_LOCATION})
{
    \$globus_prefix = \$ENV{GLOBUS_LOCATION};
}
else
{
    \$globus_prefix = "$initializer_prefix";
}

\$exec_prefix = "$initializer_exec_prefix";
\$bindir = "$bindir";
\$sbindir = "$sbindir";
\$libdir = "$libdir";
\$datarootdir = "$datarootdir";
\$datadir = "$datadir";
\$perlmoduledir = "$perlmoduledir";
\$gptdatadir = "$gptdatadir";
\$gptexecsharedir = "$gptexecsharedir";
\$amdir = "$amdir";
\$pkg_confdir = "$pkg_confdir";
\$aclocaldir = "$aclocaldir";

unshift(@INC, "\${perlmoduledir}");
EOF

GPT_PERL_INITIALIZER=gpt-perl-initializer
AC_SUBST_FILE(GPT_PERL_INITIALIZER)

dnl Things that used to be in Localize.pm
if test "x$GTAR" = "x"; then
    AC_MSG_ERROR([Unable to find tar. Set GTAR to the path to a tar command that accepts -z])
fi
AC_MSG_CHECKING([if tar accepts -z])
"$GTAR" zcf empty.tar.gz /dev/null 2> /dev/null
tar_result=$?
rm -f empty.tar.gz
if test "$tar_result" != 0; then
    AC_MSG_ERROR([no, set GTAR to the path to a tar command that accepts -z])
else
    AC_MSG_RESULT(yes)
fi

AC_PATH_PROGS(MAKE, gmake gnumake make)
if test "x$MAKE" = "x"; then
    AC_MSG_ERROR([Unable to find GNU Make.])
fi
AC_MSG_CHECKING([if $MAKE is GNU])
$MAKE --version | grep -q GNU
gmake_check_result="$?"

if test "$gmake_check_result" != 0; then
    AC_MSG_ERROR([no, set MAKE to the path to GNU Make])
else
    AC_MSG_RESULT(yes)
fi

AC_PATH_PROGS(RPM, rpm, rpm)
AC_PATH_PROGS(RPMBUILD, rpmbuild)

AC_CONFIG_FILES(
        Makefile 
        etc/Makefile
        amdir/Makefile
        perl/Makefile
        perl/scripts/Makefile
        perl/GPT/Makefile
        perl/GPT/PackageFilelist/FileIO/Makefile
        perl/GPT/PackageFilelist/flat1/Makefile
        perl/GPT/PackageFilelist/Makefile
        perl/GPT/PackageFilelist/xml1/Makefile
        perl/GPT/PkgMngmt/Makefile
        perl/GPT/V1/Makefile
        perl/scripts/gpt-build
        perl/scripts/gpt_build_config
        perl/scripts/gpt-bundle
        perl/scripts/gpt_create_automake_rules
        perl/scripts/gpt_extract_data
        perl/scripts/gpt_generate_bin_pkg_data
        perl/scripts/gpt_get_lib_names
        perl/scripts/gpt-install
        perl/scripts/gpt-pkg
        perl/scripts/gpt-postinstall
        perl/scripts/gpt-query
        perl/scripts/gpt_save_flavor
        perl/scripts/gpt_sort_filelist
        perl/scripts/gpt-uninstall
        perl/scripts/gpt-verify
        perl/scripts/gpt_version
        perl/GPT/GPTIdentity.pm
	perl/GPT/Locations.pm
	perl/GPT/LocalEnv.pm
        perl/GPT/PkgMngmt/SetupBuildFlavors.pm
        )
AC_OUTPUT()
