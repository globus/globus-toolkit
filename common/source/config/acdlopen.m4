dnl CHECK_NEED_LDL
AC_DEFUN([CHECK_NEED_LDL],
[
    if test "X$GPT_LINKTYPE" != "Xstatic"; then
    AC_CHECK_FUNC([dlopen],
    [],
    [
        AC_CHECK_LIB([dl],[dlopen],
        [
            EXTERNAL_LIBS="$EXTERNAL_LIBS -ldl"
        ],
        [
            AC_CHECK_LIB([dld],[dlopen],
            [
                EXTERNAL_LIBS="$EXTERNAL_LIBS -ldld"
            ],
            [
                AC_MSG_ERROR("Unable to find dynamic linking library")
            ])
        ])
    ])
    fi
])
