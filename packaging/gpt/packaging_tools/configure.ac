AC_REVISION($Revision$)
AC_INIT(gpt, 3.2)
AC_CONFIG_SRCDIR(Makefile.am)
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([ no-installman ])

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

AC_PATH_PROGS(TAR, gtar tar)
AC_PATH_PROGS(GUNZIP, gunzip)
AC_PATH_PROGS(GZIP, gzip)
AC_PROG_LN_S

AC_SUBST(GPT_LOCATION)

initializer_prefix="$prefix"
test "$initializer_prefix" = "NONE" && initializer_prefix="$ac_default_prefix"
test "$initializer_exec_prefix" = "" && initializer_exec_prefix='${prefix}'
gptdatadir='${datadir}/globus/gpt'
gptexecsharedir='${datadir}/globus/gpt'
amdir='${datadir}/globus/amdir'
pkg_confdir='${datadir}/globus/gpt'
dtddir='${datadir}/globus/dtd'
aclocaldir='${datadir}/globus/aclocal'

AC_SUBST(gptdatadir)
AC_SUBST(gptexecsharedir)
AC_SUBST(amdir)
AC_SUBST(pkg_confdir)
AC_SUBST(dtddir)
AC_SUBST(aclocaldir)

GPT_PERL_INITIALIZER="
my (\$prefix, \$globus_prefix, \$exec_prefix, \$bindir, \$sbindir, \$libdir, \$perlmoduledir);
my (\$datadir, \$datarootdir, \$gptdatadir, \$gptexecsharedir, \$amdir);
my (\$pkg_confdir, \$dtddir, \$aclocaldir);

sub eval_path
{
    my \$path = shift;
    my \$last = \$path;

    #{
    while (\$path =~ m/\\\${([[^}]]*)}/)
    {
        my \$varname = \${1};
        my \$evaluated;
        eval \"\\\$evaluated = \\\${\$varname}\";

        \$path =~ s/\\\${\$varname}/\$evaluated/g;
        if (\$path eq \$last)
        {
            die \"Error evaluating \$last\n\";
        }
        \$last = \$path;
    }
    return \$path;
}

if (exists \$ENV{GPT_LOCATION})
{
    \$prefix = \$ENV{GPT_LOCATION};
}
else
{
    \$prefix = '$initializer_prefix';
}

if (exists \$ENV{GLOBUS_LOCATION})
{
    \$globus_prefix = \$ENV{GLOBUS_LOCATION};
}
else
{
    \$globus_prefix = '$initializer_prefix';
}

\$exec_prefix = eval_path('$initializer_exec_prefix');
\$bindir = eval_path('$bindir');
\$sbindir = eval_path('$sbindir');
\$libdir = eval_path('$libdir');
\$perlmoduledir = eval_path('$perlmoduledir');
\$datarootdir = eval_path('$datarootdir');
\$datadir = eval_path('$datadir');
\$gptdatadir = eval_path('$gptdatadir');
\$gptexecsharedir = eval_path('$gptexecsharedir');
\$amdir = eval_path('$amdir');
\$pkg_confdir = eval_path('$pkg_confdir');
\$dtddir = eval_path('$dtddir');
\$aclocaldir = eval_path('$aclocaldir');

push(@INC, \"\${perlmoduledir}\");
my \$datadir = eval_path(\"${datadir}\");
"
AC_SUBST(GPT_PERL_INITIALIZER)
_AM_SUBST_NOTMAKE(GPT_PERL_INITIALIZER)


AC_CONFIG_FILES(Makefile 
        perl/scripts/gpt-build
        perl/scripts/gpt_build_config
        perl/scripts/gpt-bundle
        perl/scripts/gpt-config
        perl/scripts/gpt_create_automake_rules
        perl/scripts/gpt_extract_data
        perl/scripts/gpt_generate_bin_pkg_data
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
        perl/GPT/PkgMngmt/SetupBuildFlavors.pm
        )
AC_OUTPUT()
