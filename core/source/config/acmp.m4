
AC_DEFUN([LAC_MP],
[
    MP=
    LAC_MP_ARGS
    LAC_MP_INC_ARGS
    
    if test "$GLOBUS_CC" = "mpicc" ; then
        if test "$mpi_own_lib" = "yes" ; then
            AC_MSG_ERROR([you cannot specify your own mpi includes when using an mpi compiler])
            exit 1
        fi
        build_arg_mpi='yes'
    fi
    
    if test "$build_arg_mpi" = "yes" ; then
        MP=mpi
        if test "$mpi_own_lib" = "yes" ; then
            echo "Using user provided MPI libs"
        fi
    fi

    MP_INCLUDES="$mpi_cflags"
    MP_LIBS="$mpi_ldflags"

    AC_SUBST(MP)
    AC_SUBST(MP_INCLUDES)
    AC_SUBST(MP_LIBS)
])

AC_DEFUN([LAC_MP_INC_ARGS],
[
AC_ARG_WITH(mpi-includes,
    [  --with-mpi-includes     Specify include flags for MPI
                          (example --with-mpi-includes=-I/path/to/mpi/headers)],
    [if test "$build_arg_mpi" != "yes" ; then
        AC_MSG_ERROR([you must specify --with-mpi[[=yes]] to use --with-mpi-includes])
        exit 1
     elif test "$withval" = "yes" ; then
        AC_MSG_ERROR([you must specify an argument when using --with-mpi-includes])
        exit 1
     else
        mpi_cflags=$withval
        mpi_own_lib='yes'
     fi
    ])

AC_ARG_WITH(mpi-libs,
    [  --with-mpi-libs         Specify libs and LDFLAGS for MPI
                          (example --with-mpi-libs=\"-L/path/to/mpi/libs -lmpi\")],
    [if test "$build_arg_mpi" != "yes" ; then
        AC_MSG_ERROR([you must specify --with-mpi[[=yes]] to use --with-mpi-libs])
        exit 1
     elif test "$withval" = "yes" ; then
        AC_MSG_ERROR([you must specify an argument when using --with-mpi-libs])
        exit 1
     else
        mpi_ldflags=$withval
        mpi_own_lib='yes'
     fi
    ])
])

AC_DEFUN([LAC_MP_ARGS],
[
AC_ARG_WITH(mpi,
    [  --with-mpi              include the MPI protocols],
    [if test "$withval" = "yes" ; then
        build_arg_mpi='yes'
     else
        build_arg_mpi='no'
     fi
    ])
])
