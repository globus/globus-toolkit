dnl
dnl acdoxygen.m4
dnl
dnl Set up doxygen
dnl Users of this module should call
dnl LAC_DOXYGEN()
dnl To set the various variables
dnl
dnl The variables that are set and substituted (AC_SUBST) by the
dnl LAC_DOXYGEN macro are:
dnl   DOXYGEN
dnl
dnl The following variables are cached:
dnl
dnl   lac_cv_DOXYGEN
dnl
dnl

dnl LAC_DOXYGEN_ARGS()
AC_DEFUN(LAC_DOXYGEN_ARGS,
[
AC_ARG_ENABLE(doxygen,
 	changequote(<<, >>)dnl	
  <<--enable-doxygen[=PATH]	use Doxygen to generate documentation>>,
	changequote([, ])dnl
	[
		if test "$enableval" = "yes"; then
			AC_PATH_PROG(lac_cv_DOXYGEN,
				doxygen,
				[
					AC_MSG_ERROR(Doxygen installation not found)
				])
		else
			lac_cv_DOXYGEN="$enableval"
		fi 
	],
	[
		lac_cv_DOXYGEN=""
	])
])


dnl ---------------------------------------------------------------


AC_DEFUN(LAC_DOXYGEN_ENABLE,
[
LAC_DOXYGEN_ARGS

LAC_SUBSTITUTE_DOXYGEN_VAR(DOXYGEN)

])

dnl LAC_SUBSTITUTE_COMPILER_VAR
AC_DEFUN(LAC_SUBSTITUTE_DOXYGEN_VAR,
[
    if test -n "[$]lac_cv_$1"; then
        $1=[$]lac_cv_$1
        AC_SUBST($1)
    fi
])
