AC_REVISION($Revision$)
AC_INIT(gpt, 3.2)
AC_CONFIG_SRCDIR(Makefile.am)
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([ no-installman ])

echo $target > ./etc/gpt/gnu_target

AC_ARG_WITH([perl],
	
[ --with-perl=<path>     specify path to perl binary ],
[
	case $withval in
	no)
		echo "--with-perl requires an argument" >&2
		exit 1
		;;
	yes)
		echo "--with-perl requires an argument" >&2
		exit 1
		;;
	*)
                PERL=$withval
                AC_SUBST(PERL) 
                POD2MAN=`echo $PERL | sed 's!bin/perl!bin/pod2man!'`
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



AC_SUBST(POD2MAN)

#echo "POD2MAN=$POD2MAN"

# checking for the GPT_LOCATION

if test "x$GPT_LOCATION" = "x"; then
    # checking for the GLOBUS_LOCATION

    if test "x$GLOBUS_LOCATION" = "x"; then
        echo "ERROR Please specify GLOBUS_LOCATION or GPT_LOCATION" >&2
        exit 1
    else
        GPT_LOCATION=$GLOBUS_LOCATION
    fi
fi

AC_PATH_PROGS(TAR, gtar tar)
AC_PATH_PROGS(GUNZIP, gunzip)
AC_PATH_PROGS(GZIP, gzip)
AC_PROG_LN_S

AC_SUBST(GPT_LOCATION)

AC_CONFIG_FILES(Makefile 
        perl/scripts/gpt_version
        perl/GPT/GPTIdentity.pm
        )
AC_OUTPUT()
