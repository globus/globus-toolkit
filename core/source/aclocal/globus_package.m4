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
AC_SUBST(OBJEXT)
AC_SUBST(EXEEXT)

# These files are not used outside of automake.  But the makefile still
# has them as dependent targets.
if test ! -L globus_automake_targets; then
    echo "installing extra automake files"
    ln -s $GLOBUS_INSTALL_PATH/share/globus_aclocal/automake_targets \
    globus_automake_targets
    ln -s $GLOBUS_INSTALL_PATH/share/globus_aclocal/automake_rules \
    globus_automake_rules
    ln -s $GLOBUS_INSTALL_PATH/share/globus_aclocal/automake_top_rules \
    globus_automake_top_rules
fi




define([AM_PROG_LIBTOOL],[
	LIBTOOL='$(SHELL) $(GLOBUS_INSTALL_PATH)/bin/libtool-$(GLOBUS_FLAVOR_NAME)'
	AC_SUBST(LIBTOOL)
	AC_SUBST(LN_S)
])

dnl define FILELIST_FILE variable
FILELIST_FILE=`pwd`;
FILELIST_FILE="$FILELIST_FILE/$GLOBUS_FLAVOR_NAME.filelist"
AC_SUBST(FILELIST_FILE)

])

dnl GLOBUS_BUILD_DEPS(<list of package names seperated by spaces>)
AC_DEFUN(GLOBUS_SET_BUILD_DEPS, [

	for pkg in $1; do
		bfile="$GLOBUS_INSTALL_PATH/etc/globus_packages/$pkg/build_parameters_$GLOBUS_FLAVOR_NAME"
		if ! test -f $bfile; then

			AC_MSG_ERROR(["Package $pkg is not installed for flavor $GLOBUS_FLAVOR_NAME"])
		fi 
	done

	GLOBUS_BUILD_DEPS="$1";

])

dnl GLOBUS_SET_XTRA_LIBS("External libraries the package needs to link with")
AC_DEFUN(GLOBUS_ADD_XTRA_LIBS, [

	GLOBUS_XTRA_LIBS="$GLOBUS_XTRA_LIBS $1"

])

dnl GLOBUS_GENERATE
AC_DEFUN(GLOBUS_GENERATE, [

	AC_SUBST(GLOBUS_XTRA_LIBS)
	AC_SUBST(GLOBUS_BUILD_DEPS)

	GLOBUS_LINKLINE=`$GLOBUS_INSTALL_PATH/bin/globus_build_config.pl --flavor=$GLOBUS_FLAVOR_NAME --ldflags="$GLOBUS_XTRA_LIBS" $GLOBUS_BUILD_DEPS`

	AC_SUBST(GLOBUS_LINKLINE)
	
])