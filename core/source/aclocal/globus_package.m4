AC_DEFUN(GLOBUS_INIT, [

GPT_INIT

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
		GLOBUS_FLAVOR_NAME=$withval
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

AC_ARG_ENABLE(doxygen,
changequote(<<, >>)dnl	
<<  --enable-doxygen[=PATH]	use Doxygen to generate documentation>>,
changequote([, ])dnl
[
	if test "$enableval" = "yes"; then
		AC_PATH_PROG(DOXYGEN,
			doxygen,
			[
				AC_MSG_ERROR(Doxygen installation not found)
			])
	else
		DOXYGEN="$enableval"
		AC_SUBST(DOXYGEN)
	fi
],
[
	DOXYGEN=""
	AC_SUBST(DOXYGEN)
])


AC_ARG_ENABLE(internal-doc,
[  --enable-internal-doc	Generate Doxygen documentation for internal 
				functions. Requires --enable-doxygen.],
[
	DOXYFILE="Doxyfile-internal"
	AC_SUBST(DOXYFILE) 
],
[
	DOXYFILE="Doxyfile"
	AC_SUBST(DOXYFILE)
])




AM_CONDITIONAL(WITHOUT_FLAVORS, test "$NO_FLAVOR" = "yes")
AC_SUBST(GLOBUS_FLAVOR_NAME)

# checking for the GLOBUS_LOCATION

if test "x$GLOBUS_LOCATION" = "x"; then
    echo "ERROR Please specify GLOBUS_LOCATION" >&2
    exit 1
fi
if test "x$GPT_LOCATION" = "x"; then
    GPT_LOCATION=$GLOBUS_LOCATION
    export GPT_LOCATION
fi

# get the environment scripts
. $GLOBUS_LOCATION/libexec/globus-sh-tools.sh

. $GLOBUS_LOCATION/libexec/globus-build-env-$GLOBUS_FLAVOR_NAME.sh


prefix='$(GLOBUS_LOCATION)'
exec_prefix='$(GLOBUS_LOCATION)'

AC_SUBST(CC)
AC_SUBST(CPP)
AC_SUBST(CFLAGS)
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
AC_SUBST(CROSS)
AC_SUBST(cross_compiling)
AC_SUBST(OBJEXT)
AC_SUBST(EXEEXT)


define([AM_PROG_LIBTOOL],[
	LIBTOOL='$(SHELL) $(GLOBUS_LOCATION)/sbin/libtool-$(GLOBUS_FLAVOR_NAME)'
	AC_SUBST(LIBTOOL)
	AC_SUBST(LN_S)
])

dnl define FILELIST_FILE variable
FILELIST_FILE=`pwd`;
FILELIST_FILE="$FILELIST_FILE/pkgdata/master.filelist"
AC_SUBST(FILELIST_FILE)

dnl END OF GLOBUS_INIT
])


AC_DEFUN(GLOBUS_FINALIZE, [
if test ! -z "$INSURE"; then
	CC=$INSURE
	LD=$INSURE
	CXX=$INSURE
	AC_SUBST(CC) 
	AC_SUBST(LD) 
	AC_SUBST(CXX) 
fi 

])

