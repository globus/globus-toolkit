AC_DEFUN([GLOBUS_INITIALIZERS], [
initializer_prefix="${prefix}"
test "$initializer_prefix" = "NONE" && initializer_prefix="$ac_default_prefix"
GLOBUS_SCRIPT_INITIALIZER=" \
eval_path() \
{ \
    _pathval=\"\[$]1\" ; \
    _old_pathval=\"\" ; \
 \
    while test \"\$_pathval\" != \"\$_old_pathval\"; do \
        _old_pathval=\"\$_pathval\" ; \
        eval _pathval=\"\$_pathval\" ; \
    done ; \
    echo \"\$_pathval\" ; \
} ; \
 \
if test -n \"\${GLOBUS_LOCATION}\" ; then \
    prefix=\"\${GLOBUS_LOCATION}\" ; \
else \
    prefix='$initializer_prefix' ; \
fi ; \
 \
exec_prefix=\"\`eval_path $exec_prefix\`\" ; \
test \"\$exec_prefix\" = NONE && exec_prefix=\"\$prefix\" ; \
sbindir=\"\`eval_path $sbindir\`\" ; \
bindir=\"\`eval_path $bindir\`\" ; \
libdir=\"\`eval_path $libdir\`\" ; \
includedir=\"\`eval_path $includedir\`\" ; \
datarootdir=\"\`eval_path $datarootdir\`\" ; \
datadir=\"\`eval_path $datadir\`\" ; \
libexecdir=\"\`eval_path $libexecdir\`\" ; \
sysconfdir=\"\`eval_path $sysconfdir\`\" ; \
sharedstatedir=\"\`eval_path $sharedstatedir\`\" ; \
localstatedir=\"\`eval_path $localstatedir\`\" ; \
aclocaldir=\"\`eval_path $aclocaldir\`\" ; \
"
AC_SUBST(GLOBUS_SCRIPT_INITIALIZER)

GLOBUS_PERL_INITIALIZER=" \
my (\$prefix, \$exec_prefix, \$libdir, \$perlmoduledir); \
my (\$sbindir, \$bindir, \$includedir, \$datarootdir, \
    \$datadir, \$libexecdir, \$sysconfdir, \$sharedstatedir, \
    \$localstatedir, \$aclocaldir); \
BEGIN \
{ \
    sub eval_path \
    { \
        my \$path = shift; \
        my \$last = \$path; \
 \
        while (\$path =~ m/\\\${([[^}]]*)}/) \
        { \
            my \$varname = \${1}; \
            my \$evaluated; \
            eval \"\\\$evaluated = \\\${\$varname}\"; \
 \
            \$path =~ s/\\\${\$varname}/\$evaluated/g; \
            if (\$path eq \$last) \
            { \
                die \"Error evaluating \$last\n\"; \
            } \
            \$last = \$path; \
        } \
        return \$path; \
    } \
 \
    if (exists \$ENV{GLOBUS_LOCATION}) \
    { \
        \$prefix = \$ENV{GLOBUS_LOCATION}; \
    } \
    else \
    { \
        \$prefix = '$initializer_prefix'; \
    } \
 \
    \$exec_prefix=eval_path('$exec_prefix'); \
    \$libdir = eval_path('$libdir'); \
    \$perlmoduledir = eval_path('$perlmoduledir'); \
    \$sbindir = eval_path('$sbindir'); \
    \$bindir = eval_path('$bindir'); \
    \$incluedir = eval_path('$includedir'); \
    \$datarootdir = eval_path('$datarootdir'); \
    \$datadir = eval_path('$datadir'); \
    \$libexecdir = eval_path('$libexecdir'); \
    \$sysconfdir = eval_path('$sysconfdir'); \
    \$sharedstatedir = eval_path('$sharedstatedir'); \
    \$localstatedir = eval_path('$localstatedir'); \
    \$aclocaldir = eval_path('$aclocaldir'); \
 \
    push(@INC, \"\${perlmoduledir}\"); \
 \
    if (exists \$ENV{GPT_LOCATION}) \
    { \
        push(@INC, \"\$ENV{GPT_LOCATION}/lib/perl\"); \
    } \
} \
"

AC_SUBST(GLOBUS_PERL_INITIALIZER)

])
