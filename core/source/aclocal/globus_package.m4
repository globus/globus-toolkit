AC_DEFUN([GLOBUS_INIT], [

AM_MAINTAINER_MODE

# checking for the GLOBUS_LOCATION

if test "x$GLOBUS_LOCATION" = "x"; then
    echo "ERROR Please specify GLOBUS_LOCATION" >&2
    exit 1
fi
if test "x$GPT_LOCATION" = "x"; then
    GPT_LOCATION=$GLOBUS_LOCATION
    export GPT_LOCATION
fi

#extract whether the package is built with flavors from the src metadata
$GPT_LOCATION/sbin/gpt_extract_data --build $srcdir/pkgdata/pkg_data_src.gpt.in > tmpfile.gpt

. ./tmpfile.gpt
rm ./tmpfile.gpt

if test "x$GPT_BUILD_WITH_FLAVORS" = "xno"; then
        GLOBUS_FLAVOR_NAME="noflavor"
fi

AC_ARG_WITH(flavor,
	[ --with-flavor=<FL>     Specify the globus build flavor or without-flavor for a flavor independent  ],

	[
	case $withval in
	no)
		NO_FLAVOR="yes"
		;;
	yes)
		echo "Please specify a globus build flavor" >&2
		exit 1
		;;
	*)
        if test "x$GLOBUS_FLAVOR_NAME" = "xnoflavor"; then
	        echo "Warning: package doesn't build with flavors $withval ignored" >&2
	        echo "Warning: $withval ignored" >&2
        else
		GLOBUS_FLAVOR_NAME=$withval
                if test ! -f "$GLOBUS_LOCATION/etc/globus_core/flavor_$GLOBUS_FLAVOR_NAME.gpt"; then
	                echo "ERROR: Flavor $GLOBUS_FLAVOR_NAME has not been installed" >&2
	                exit 1
                fi 

        fi
		;;
	esac
	],

	[ 
        if test "x$GLOBUS_FLAVOR_NAME" = "x"; then
	        echo "Please specify a globus build flavor" >&2
	        exit 1
        fi
	]
)


GPT_INIT



AM_CONDITIONAL(WITHOUT_FLAVORS, test "$NO_FLAVOR" = "yes")
AC_SUBST(GLOBUS_FLAVOR_NAME)


# get the environment scripts

if test "x$GLOBUS_FLAVOR_NAME" != "xnoflavor" ; then
	. $GLOBUS_LOCATION/libexec/globus-build-env-$GLOBUS_FLAVOR_NAME.sh
fi

prefix='$(GLOBUS_LOCATION)'
exec_prefix='$(GLOBUS_LOCATION)'

AC_SUBST(CC)
AC_SUBST(CPP)
AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LD)
AC_SUBST(LDFLAGS)
AC_SUBST(LIBS)
AC_SUBST(CXX)
AC_SUBST(CXXCPP)
AC_SUBST(CXXFLAGS)
AC_SUBST(INSURE)
AC_SUBST(DOXYGEN)
AC_SUBST(F77)
AC_SUBST(F77FLAGS)
AC_SUBST(F90)
AC_SUBST(F90FLAGS)
AC_SUBST(AR)
AC_SUBST(ARFLAGS)
AC_SUBST(RANLIB)
AC_SUBST(PERL)
AC_SUBST(CROSS)
AC_SUBST(cross_compiling)
AC_SUBST(OBJEXT)
AC_SUBST(EXEEXT)
AC_SUBST(OBJECT_MODE)


define([AM_PROG_LIBTOOL],[
	LIBTOOL='$(SHELL) $(GLOBUS_LOCATION)/sbin/libtool-$(GLOBUS_FLAVOR_NAME)'
	AC_SUBST(LIBTOOL)
	AC_SUBST(LN_S)
])

dnl define FILELIST_FILE variable
FILELIST_FILE=`pwd`;
FILELIST_FILE="$FILELIST_FILE/pkgdata/master.filelist"
AC_SUBST(FILELIST_FILE)

dnl export version information
dnl branch id 99999 means that timestamp refers to build time
if test -f $srcdir/dirt.sh ; then
    . $srcdir/dirt.sh
else
    DIRT_TIMESTAMP=`perl -e 'print time'`
    DIRT_BRANCH_ID=99999
fi

dnl GPT_MAJOR_VERSION and GPT_MINOR_VERSION provided by GPT_INIT
AC_SUBST(GPT_MAJOR_VERSION)
AC_SUBST(GPT_MINOR_VERSION)
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)


AC_ARG_ENABLE([programs],
[   --disable-programs    Don't compile/link programs],
    [case "${enableval}" in
        yes) 
            ENABLE_PROGRAMS=true
        ;;
        no)
            ENABLE_PROGRAMS=false
        ;;
        *)
            AC_MSG_ERROR([bad value ${enableval} for --enable-programs])
        ;;
    esac],
    [ENABLE_PROGRAMS=true])
AM_CONDITIONAL(ENABLE_PROGRAMS, test "x$ENABLE_PROGRAMS" = "xtrue")


dnl END OF GLOBUS_INIT
])


AC_DEFUN([GLOBUS_FINALIZE], [

lac_INSURE=$INSURE

AC_ARG_ENABLE(insure,
 	changequote(<<, >>)dnl
  <<--disable-insure	disable Insure++ >>,
	changequote([, ])dnl
	[
		if test "$enableval" = "yes"; then
			lac_INSURE="${INSURE-insure}"
		else
			lac_INSURE="$enableval"
		fi
	],
	[
		lac_INSURE=""
	])


if test ! -z "$lac_INSURE"; then
	CC=$lac_INSURE
	LD=$lac_INSURE
	CXX=$lac_INSURE
	AC_SUBST(CC) 
	AC_SUBST(LD) 
	AC_SUBST(CXX) 
fi 

])

