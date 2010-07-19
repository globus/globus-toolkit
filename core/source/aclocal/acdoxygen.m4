

dnl
dnl Doxygen related macros
dnl



AC_DEFUN([LAC_DOXYGEN_PROJECT],dnl
[
    lac_doxygen_project=`echo "$1" | sed -e 's/_/ /g'`
    AC_SUBST(lac_doxygen_project)
])

AC_DEFUN([LAC_DOXYGEN_SOURCE_DIRS],dnl
[
    lac_doxygen_srcdirs=[$1]
    AC_SUBST(lac_doxygen_srcdirs)
])

AC_DEFUN([LAC_DOXYGEN_INPUT_FILTER],dnl
[
    lac_doxygen_input_filter=[$1]
    AC_SUBST(lac_doxygen_input_filter)
])

AC_DEFUN([LAC_DOXYGEN_OUTPUT_TAGFILE],dnl
[
    lac_doxygen_output_tagfile=[$1]
    AC_SUBST(lac_doxygen_output_tagfile)
])

AC_DEFUN([LAC_DOXYGEN_TAGFILES],dnl
[
    lac_doxygen_tagfiles=""
    for x in "" $1; do
        if test "X$x" != "X" ; then
        lac_tag_base=`echo ${x} | sed -e 's|.*/||' -e 's|\.tag$||'`
        lac_tag="${lac_tag_base}.tag"
            lac_doxygen_tagfiles="$lac_doxygen_tagfiles $x"
            lac_doxygen_internal_tagfiles="$lac_doxygen_internal_tagfiles ${x}i"
        lac_doxygen_installdox="$lac_doxygen_installdox -l${lac_tag}@../../${lac_tag_base}/html"
    fi
    done
    AC_SUBST(lac_doxygen_tagfiles)
    AC_SUBST(lac_doxygen_internal_tagfiles)
    AC_SUBST(lac_doxygen_installdox)
])

AC_DEFUN([LAC_DOXYGEN_FILE_PATTERNS],dnl
[
    lac_doxygen_file_patterns=[$1]
])

AC_DEFUN([LAC_DOXYGEN_EXAMPLE_DIR],dnl
[
    lac_doxygen_examples=[$1]
])

AC_DEFUN([LAC_DOXYGEN_PREDEFINES],dnl
[
    lac_doxygen_predefines=[$1]
])

AC_DEFUN([LAC_DOXYGEN],dnl
[
    AC_ARG_ENABLE(doxygen,
    changequote(<<, >>)dnl  
<< --enable-doxygen[=PATH]     use Doxygen to generate documentation>>,
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
    [ --enable-internal-doc        Generate Doxygen documentation for
                   internal functions. Requires --enable-doxygen],
    [
    DOXYFILE="Doxyfile-internal"
    AC_SUBST(DOXYFILE) 
    ],
    [
    DOXYFILE="Doxyfile"
    AC_SUBST(DOXYFILE)
    ])


    if test -n "$DOXYGEN" ; then
    AC_PATH_PROG(DOT, dot)
    
    if test -z "$GLOBUS_SH_PERL" ; then
        AC_PATH_PROG(PERL, perl)
    else
        PERL="$GLOBUS_SH_PERL"
        AC_SUBST(PERL)
    fi
    if test "$DOT" != ""; then
        HAVE_DOT=YES
    else
        HAVE_DOT=NO
    fi

    AC_SUBST(HAVE_DOT)

    LAC_DOXYGEN_SOURCE_DIRS($1)
    LAC_DOXYGEN_FILE_PATTERNS($2)   
    LAC_DOXYGEN_INPUT_FILTER($3)

    LAC_DOXYGEN_PROJECT($GPT_NAME)
    LAC_DOXYGEN_OUTPUT_TAGFILE($GPT_NAME)

    lac_dep_check="$GLOBUS_LOCATION/sbin/globus-build-doxygen-dependencies"

    if test ! -x $lac_dep_check ; then

        # assume we are dealing with common
        
        lac_dep_check="$srcdir/scripts/globus-build-doxygen-dependencies"
        chmod 0755 $lac_dep_check

    fi

    AC_MSG_CHECKING([documentation dependencies])

    tagfiles="`$lac_dep_check -src $srcdir/pkgdata/pkg_data_src.gpt.in 2>/dev/null`"
    if test "$?" != "0"; then
        AC_MSG_RESULT([failed])
        AC_MSG_ERROR([Documentation dependencies could not be satisfied.])
    else
        AC_MSG_RESULT([ok])
    fi

    LAC_DOXYGEN_TAGFILES($tagfiles)

    AC_SUBST(lac_doxygen_file_patterns)
    AC_SUBST(lac_doxygen_examples)
    AC_SUBST(lac_doxygen_predefines)
    fi
]
)
