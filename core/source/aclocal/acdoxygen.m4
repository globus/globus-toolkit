

dnl
dnl Doxygen related macros
dnl



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
    LAC_DOXYGEN_FILE_PATTERNS($5)	


    AC_SUBST(lac_doxygen_file_patterns)
    AC_SUBST(lac_doxygen_examples)
    AC_SUBST(lac_doxygen_predefines)
])
