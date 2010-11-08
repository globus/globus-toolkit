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
                perldir="`echo $PERL | sed -e 's|/[^/]*\$||'`"
                POD2MAN="$perldir/pod2man"
                if ! test -f $POD2MAN; then
                 POD2MAN=
                fi 
		;;
	esac
],
[
        AC_PATH_PROG(PERL,perl)
        AC_PATH_PROG(POD2MAN,pod2man)
]
)

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

AC_SUBST(gptdatadir)
AC_SUBST(gptexecsharedir)
AC_SUBST(amdir)

GPT_PERL_INITIALIZER="
my (\$prefix, \$exec_prefix, \$bindir, \$sbindir, \$libdir, \$perlmoduledir);
my (\$gptdatadir, \$gptexecsharedir, \$amdir);

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

\$exec_prefix = eval_path('$initializer_exec_prefix');
\$bindir = eval_path('$bindir');
\$sbindir = eval_path('$sbindir');
\$libdir = eval_path('$libdir');
\$perlmoduledir = eval_path('$perlmoduledir');
\$gptdatadir = eval_path('$gptdatadir');
\$gptexecsharedir = eval_path('$gptexecsharedir');
\$amdir = eval_path('$amdir');

push(@INC, \"\${perlmoduledir}\");
my \$datadir = eval_path(\"${datadir}\");
"
AC_SUBST(GPT_PERL_INITIALIZER)
_AM_SUBST_NOTMAKE(GPT_PERL_INITIALIZER)


AC_CONFIG_FILES(Makefile 
        perl/scripts/gpt-build
        perl/scripts/gpt-config
        perl/scripts/gpt_version
        perl/GPT/GPTIdentity.pm
        )
AC_OUTPUT()
