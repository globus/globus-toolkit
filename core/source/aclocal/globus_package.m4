AC_DEFUN(GLOBUS_INIT, [
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
	echo "Please specify a globus build flavor" >&2
	exit 1
	]
)

AM_CONDITIONAL(WITHOUT_FLAVORS, test "$NO_FLAVOR" = "yes")
AC_SUBST(GLOBUS_FLAVOR_NAME)

# checking for the GLOBUS_INSTALL_PATH

if test "x$GLOBUS_INSTALL_PATH" = "x"; then
    echo "ERROR Please specify GLOBUS_INSTALL_PATH" >&2
    exit 1
fi

# get the environment scripts
. $GLOBUS_INSTALL_PATH/etc/globus-sh-tools.sh

. $GLOBUS_INSTALL_PATH/etc/globus-build-env-$GLOBUS_FLAVOR_NAME.sh

prefix='$(GLOBUS_INSTALL_PATH)'
exec_prefix='$(GLOBUS_INSTALL_PATH)'

AC_SUBST(CC)
AC_SUBST(CPP)
AC_SUBST(CFLAGS)
AC_SUBST(LD)
AC_SUBST(LDFLAGS)
AC_SUBST(LIBS)
AC_SUBST(CXX)
AC_SUBST(CXXCPP)
AC_SUBST(CXXFLAGS)
AC_SUBST(F77)
AC_SUBST(F77FLAGS)
AC_SUBST(F90)
AC_SUBST(F90FLAGS)
AC_SUBST(AR)
AC_SUBST(ARFLAGS)
AC_SUBST(RANLIB)
AC_SUBST(CROSS)
AC_SUBST(cross_compiling)

define([AM_PROG_LIBTOOL],[
	LIBTOOL='$(SHELL) $(GLOBUS_INSTALL_PATH)/bin/libtool-$(GLOBUS_FLAVOR_NAME)'
	AC_SUBST(LIBTOOL) 
])

dnl define FILELIST_FILE variable
FILELIST_FILE=`pwd`;
FILELIST_FILE="$FILELIST_FILE/$GLOBUS_FLAVOR_NAME.filelist"
AC_SUBST(FILELIST_FILE)

])