AC_DEFUN([GLOBUS_INIT], [
globus_prefix="${prefix}"
test "$globus_gprefix" = "NONE" && globus_gprefix="$ac_default_prefix"

AM_MAINTAINER_MODE

dnl Default prefix is $GLOBUS_LOCATION, falling back to /usr if that
dnl is not present in the environment. Can be overridden by using
dnl --prefix during configure time
AC_PREFIX_DEFAULT(${GLOBUS_LOCATION:-/usr})

# checking for the GLOBUS_LOCATION
GLOBUS_LOCATION="${GLOBUS_LOCATION:-/usr}"
GPT_LOCATION="${GPT_LOCATION:-${GLOBUS_LOCATION}}"

# This is created in globus-bootstrap.sh
. "${srcdir}/gptdata.sh"

if test "x$GPT_BUILD_WITH_FLAVORS" = "xno"; then
        GLOBUS_FLAVOR_NAME="noflavor"
fi

eval_path()
{
    _pathval="[$]1"
    _old_pathval=""

    while test "$_pathval" != "$_old_pathval"; do
        _old_pathval="$_pathval"
        eval "_pathval=\"$_pathval\""
    done
    echo "$_pathval"
}

AC_ARG_WITH(flavor,
        AC_HELP_STRING([--with-flavor=FLAVOR],
        [Specify the globus build flavor or without-flavor for a flavor independent]),

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
                if test ! -f "${GLOBUS_LOCATION}/share/globus/flavors/flavor_$GLOBUS_FLAVOR_NAME.gpt"; then
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

. ${GLOBUS_LOCATION}/share/globus/globus-build-env-$GLOBUS_FLAVOR_NAME.sh

GLOBUS_INITIALIZERS

doxygendir="`eval_path '$doxygendir'`"

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

AC_SUBST(setupdir)
AC_SUBST(testdir)
AC_SUBST(flavorincludedir)
AC_SUBST(pkgdir)
AC_SUBST(aclocaldir)
AC_SUBST(perlmoduledir)
AC_SUBST(doxygendir)


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
AC_SUBST(GPT_AGE_VERSION)
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)


AC_ARG_ENABLE([programs],
    AC_HELP_STRING([--disable-programs], [Don't compile/link programs]),
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


dnl Nothing to do here after ensure flavoring is removed
AC_DEFUN([GLOBUS_FINALIZE], []) 
