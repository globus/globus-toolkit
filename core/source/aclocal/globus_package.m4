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

# checking for the GLOBUS_INSTALL_PATH

if test "x$GLOBUS_INSTALL_PATH" = "x"; then
    echo "ERROR Please specify GLOBUS_INSTALL_PATH" >&2
    exit 1
fi

# get the environment scripts
. $GLOBUS_INSTALL_PATH/libexec/globus-sh-tools.sh

. $GLOBUS_INSTALL_PATH/libexec/globus-build-env-$GLOBUS_FLAVOR_NAME.sh


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

GPT_INIT

# These files are not used outside of automake.  But the makefile still
# has them as dependent targets.
if test ! -h globus_automake_targets; then
    echo "installing extra automake files"
    ln -s $GLOBUS_INSTALL_PATH/share/globus_aclocal/automake_targets \
    globus_automake_targets
    ln -s $GLOBUS_INSTALL_PATH/share/globus_aclocal/automake_rules \
    globus_automake_rules
    ln -s $GLOBUS_INSTALL_PATH/share/globus_aclocal/automake_top_rules \
    globus_automake_top_rules
fi




define([AM_PROG_LIBTOOL],[
	LIBTOOL='$(SHELL) $(GLOBUS_INSTALL_PATH)/sbin/libtool-$(GLOBUS_FLAVOR_NAME)'
	AC_SUBST(LIBTOOL)
	AC_SUBST(LN_S)
])

dnl define FILELIST_FILE variable
FILELIST_FILE=`pwd`;
FILELIST_FILE="$FILELIST_FILE/pkgdata/master.filelist"
AC_SUBST(FILELIST_FILE)

])


AC_DEFUN(GLOBUS_FINALIZE, [
if test ! -z $INSURE; then
	CC=$INSURE
	LD=$INSURE
	CXX=$INSURE
	AC_SUBST(CC) 
	AC_SUBST(LD) 
	AC_SUBST(CXX) 
fi 

])

AC_DEFUN(LAC_DOXYGEN_PROJECT,dnl
[
    lac_doxygen_project=[$1]
    AC_SUBST(lac_doxygen_project)
])

AC_DEFUN(LAC_DOXYGEN_SOURCE_DIRS,dnl
[
    lac_doxygen_srcdirs=[$1]
    AC_SUBST(lac_doxygen_srcdirs)
])


AC_DEFUN(LAC_DOXYGEN_OUTPUT_TAGFILE,dnl
[
    lac_doxygen_output_tagfile=[$1]
    AC_SUBST(lac_doxygen_output_tagfile)
])

AC_DEFUN(LAC_DOXYGEN_TAGFILES,dnl
[
    lac_doxygen_tagfiles=""
    for x in "" $1; do
        if test "X$x" != "X" ; then
            lac_doxygen_tagfiles="$lac_doxygen_tagfiles";
            lac_doxygen_internal_tagfiles="$lac_doxygen_internal_tagfiles";
	fi
    done
    AC_SUBST(lac_doxygen_tagfiles)
    AC_SUBST(lac_doxygen_internal_tagfiles)
])

AC_DEFUN(LAC_DOXYGEN_FILE_PATTERNS,dnl
[
    lac_doxygen_file_patterns=[$1]
])

AC_DEFUN(LAC_DOXYGEN_EXAMPLE_DIR,dnl
[
    lac_doxygen_examples=[$1]
])

AC_DEFUN(LAC_DOXYGEN_PREDEFINES,dnl
[
    lac_doxygen_predefines=[$1]
])

AC_DEFUN(LAC_DOXYGEN,dnl
[
    AC_PATH_PROG(DOT, dot)
    AC_PATH_PROG(PERL, perl5 perl)
    if test "$DOT" != ""; then
       HAVE_DOT=YES
    else
       HAVE_DOT=NO
    fi
    AC_SUBST(HAVE_DOT)

    LAC_DOXYGEN_PROJECT($1)
    LAC_DOXYGEN_SOURCE_DIRS($2)
    LAC_DOXYGEN_OUTPUT_TAGFILE($3)
    LAC_DOXYGEN_TAGFILES($4)

    AC_SUBST(lac_doxygen_file_patterns)
    AC_SUBST(lac_doxygen_examples)
    AC_SUBST(lac_doxygen_predefines)
])




