AC_DEFUN([GLOBUS_INITIALIZERS], [
initializer_prefix="${prefix}"
test "$initializer_prefix" = "NONE" && initializer_prefix="$ac_default_prefix"
initializer_exec_prefix="${exec_prefix}"
test "$initializer_exec_prefix" = "NONE" && initializer_exec_prefix='${prefix}'
test "$datarootdir" = "" && datarootdir='${prefix}/share'
AC_SUBST(datarootdir)

case $guess_libdir:${host}:${libdir} in
    1:*linux*:*lib64)
        libdir32="${libdir%%64}"
        libdir64="${libdir}"

        libdir_choice="
case \`uname -m\` in
    aarch64|ppc64|s390x|sparc64|x86_64)
        libdir=\"$libdir64\"
        ;;
    *)
        libdir=\"$libdir32\"
        ;;
esac
"
        perl_libdir_choice="
    if (\`uname -m\` =~ /^(aarch64|ppc64|s390x|sparc64|x86_64)\$/) {
        \$libdir = \"$libdir64\";
    } else {
        \$libdir = \"$libdir32\";
    }
"
        ;;
    1:*linux*:*lib)
        libdir32="${libdir}"
        libdir64="${libdir}64"

        libdir_choice="
case \`uname -m\` in
    aarch64|ppc64|s390x|sparc64|x86_64)
        libdir=\"$libdir64\"
        ;;
    *)
        libdir=\"$libdir32\"
        ;;
esac
"
        perl_libdir_choice="
    if (\`uname -m\` =~ /^(aarch64|ppc64|s390x|sparc64|x86_64)\$/) {
        \$libdir = \"$libdir64\";
    } else {
        \$libdir = \"$libdir32\";
    }
"
        ;;
    *)
        libdir_choice="libdir=\"$libdir\""
        perl_libdir_choice="    \$libdir = \"$libdir\";";
        ;;
esac

echo "$libdir_choice" | sed "s/\"/'/g" > globus-script-libdir-choice
GLOBUS_LIBDIR_CHOICE="globus-script-libdir-choice"

echo "$perl_libdir_choice" | sed "s/^    //" > globus-perl-libdir-choice
GLOBUS_PERL_LIBDIR_CHOICE="globus-perl-libdir-choice"

AC_SUBST_FILE(GLOBUS_LIBDIR_CHOICE)
AC_SUBST_FILE(GLOBUS_PERL_LIBDIR_CHOICE)

cat > globus-script-initializer << EOF
if test -n "\${GLOBUS_LOCATION}" ; then
    prefix="\${GLOBUS_LOCATION}"
else
    prefix="$initializer_prefix"
fi

exec_prefix="$initializer_exec_prefix"
sbindir="$sbindir"
bindir="$bindir"
$libdir_choice
includedir="$includedir"
datarootdir="$datarootdir"
datadir="$datadir"
libexecdir="$libexecdir"
sysconfdir="$sysconfdir"
sharedstatedir="$sharedstatedir"
localstatedir="$localstatedir"
aclocaldir="$aclocaldir"
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
    if (exists \$ENV{GLOBUS_LOCATION})
    {
        \$prefix = \$ENV{GLOBUS_LOCATION};
    }
    else
    {
        \$prefix = "$initializer_prefix";
    }

    \$exec_prefix = "$initializer_exec_prefix";
$perl_libdir_choice
    \$sbindir = "$sbindir";
    \$bindir = "$bindir";
    \$includedir = "$includedir";
    \$datarootdir = "$datarootdir";
    \$datadir = "$datadir";
    \$perlmoduledir = "$perlmoduledir";
    \$libexecdir = "$libexecdir";
    \$sysconfdir = "$sysconfdir";
    \$sharedstatedir = "$sharedstatedir";
    \$localstatedir = "$localstatedir";
    \$aclocaldir = "$aclocaldir";

    if (exists \$ENV{GPT_LOCATION})
    {
        unshift(@INC, "\$ENV{GPT_LOCATION}/lib/perl");
    }

    unshift(@INC, "\${perlmoduledir}");
}
EOF

GLOBUS_PERL_INITIALIZER=globus-perl-initializer
AC_SUBST_FILE(GLOBUS_PERL_INITIALIZER)

])
