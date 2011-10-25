AC_DEFUN([GLOBUS_INITIALIZERS], [
initializer_prefix="${prefix}"
test "$initializer_prefix" = "NONE" && initializer_prefix="$ac_default_prefix"
initializer_exec_prefix="${exec_prefix}"
test "$initializer_exec_prefix" = "NONE" && initializer_exec_prefix='${prefix}'
test "$datarootdir" = "" && datarootdir='${prefix}/share'
AC_SUBST(datarootdir)

if test "$guess_libdir" = ""; then
AC_ARG_WITH(
    [initializer-libdir-based-on-machine-type],
    AC_HELP_STRING([--with-initializer-libdir-based-on-machine-type],
        [Guess that the libdir might be lib or lib64 depending on the machine type]),
    [case $withval in
        yes)
            guess_libdir=1
            ;;
        *)
            guess_libdir=0
            ;;
    esac],
    [guess_libdir=0])
    AC_SUBST(guess_libdir)
fi


case $guess_libdir:${host}:${libdir} in
    1:*linux*:*lib64)
        libdir32="${libdir%%64}"
        libdir64="${libdir}"

        libdir_choice="
        case \`uname -m\` in
            x86_64)
                libdir=\"\`eval_path $libdir64\`\"
                ;;
            *)
                libdir=\"\`eval_path $libdir32\`\"
                ;;
        esac
"
        perl_libdir_choice="
        if (\`uname -m\` eq \"x86_64\\n\") {
            \$libdir = eval_path('$libdir64');
        } else {
            \$libdir = eval_path('$libdir32');
        }
"

        ;;
    1:*linux*:*lib)
        libdir32="${libdir}"
        libdir64="${libdir}64"

        libdir_choice="
        case \`uname -m\` in
            x86_64)
                libdir=\"\`eval_path $libdir64\`\"
                ;;
            *)
                libdir=\"\`eval_path $libdir32\`\"
                ;;
        esac
"
        perl_libdir_choice="
        if (\`uname -m\` eq \"x86_64\\n\") {
            \$libdir = eval_path('$libdir64');
        } else {
            \$libdir = eval_path('$libdir32');
        }
"
        ;;
    *)
        libdir_choice="libdir=\"\`eval_path $libdir\`\""
        perl_libdir_choice="\$libdir = eval_path('$libdir')";
        ;;
esac

echo "$libdir_choice" > libdir-choice
GLOBUS_LIBDIR_CHOICE="libdir-choice"

AC_SUBST_FILE(GLOBUS_LIBDIR_CHOICE)

cat > globus-script-initializer << EOF
eval_path()
{
    _pathval="\[$]1"
    _old_pathval=""

    while test "\$_pathval" != "\$_old_pathval"; do
        _old_pathval="\$_pathval"
        eval _pathval="\$_pathval"
    done
    echo "\$_pathval"
}

if test -n "\${GLOBUS_LOCATION}" ; then
    prefix="\${GLOBUS_LOCATION}"
else
    prefix='$initializer_prefix'
fi

exec_prefix="\`eval_path $initializer_exec_prefix\`"
sbindir="\`eval_path $sbindir\`"
bindir="\`eval_path $bindir\`"
$libdir_choice
includedir="\`eval_path $includedir\`"
datarootdir="\`eval_path $datarootdir\`"
datadir="\`eval_path $datadir\`"
libexecdir="\`eval_path $libexecdir\`"
sysconfdir="\`eval_path $sysconfdir\`"
sharedstatedir="\`eval_path $sharedstatedir\`"
localstatedir="\`eval_path $localstatedir\`"
aclocaldir="\`eval_path $aclocaldir\`"
EOF

GLOBUS_SCRIPT_INITIALIZER=globus-script-initializer
AC_SUBST_FILE(GLOBUS_SCRIPT_INITIALIZER)

cat > globus-perl-initializer << EOF
my (\$prefix, \$exec_prefix, \$libdir, \$perlmoduledir);
my (\$sbindir, \$bindir, \$includedir, \$datarootdir,
    \$datadir, \$libexecdir, \$sysconfdir, \$sharedstatedir,
    \$localstatedir, \$aclocaldir);
BEGIN
{
    sub eval_path
    {
        my \$path = shift;
        my \$last = \$path;

        while (\$path =~ m/\\\${([[^}]]*)}/)
        {
            my \$varname = \${1};
            my \$evaluated;
            eval "\\\$evaluated = \\\${\$varname}";

            \$path =~ s/\\\${\$varname}/\$evaluated/g;
            if (\$path eq \$last)
            {
                die "Error evaluating \$last\n";
            }
            \$last = \$path;
        }
        return \$path;
    }

    if (exists \$ENV{GLOBUS_LOCATION})
    {
        \$prefix = \$ENV{GLOBUS_LOCATION};
    }
    else
    {
        \$prefix = '$initializer_prefix';
    }

    \$exec_prefix = eval_path('$initializer_exec_prefix');
    $perl_libdir_choice
    \$sbindir = eval_path('$sbindir');
    \$bindir = eval_path('$bindir');
    \$includedir = eval_path('$includedir');
    \$datarootdir = eval_path('$datarootdir');
    \$datadir = eval_path('$datadir');
    \$perlmoduledir = eval_path('$perlmoduledir');
    \$libexecdir = eval_path('$libexecdir');
    \$sysconfdir = eval_path('$sysconfdir');
    \$sharedstatedir = eval_path('$sharedstatedir');
    \$localstatedir = eval_path('$localstatedir');
    \$aclocaldir = eval_path('$aclocaldir');

    push(@INC, "\${perlmoduledir}");

    if (exists \$ENV{GPT_LOCATION})
    {
        push(@INC, "\$ENV{GPT_LOCATION}/lib/perl");
    }
}
EOF

GLOBUS_PERL_INITIALIZER=globus-perl-initializer
AC_SUBST_FILE(GLOBUS_PERL_INITIALIZER)

])
