
AC_DEFUN(LAC_MP,
[
    MP=
    LAC_MP_ARGS
    LAC_MP_INC_ARGS

    if test "$build_arg_mpi" = "yes" ; then
        if test "$mpi_own_lib" = "yes" ; then
            echo "Using user provided MPI libs"
            MP=mpi
        else
            LAC_MP_MPI
            MP=mpi
        fi
    fi

    MP_INCLUDES="$mpi_cflags"
    MP_LIBS="$mpi_ldflags"

    AC_SUBST(MP)
    AC_SUBST(MP_INCLUDES)
    AC_SUBST(MP_LIBS)
])

AC_DEFUN(LAC_MP_INC_ARGS,
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

AC_DEFUN(LAC_MP_ARGS,
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

AC_DEFUN(LAC_MP_MPI,
[
    AC_MSG_CHECKING(for MPI)
    AC_CACHE_VAL(lac_cv_mpi, [dnl
        case "$host" in
            *-ibm-aix* )
                poepackage="`/usr/bin/lslpp -clq | grep '/usr/lib/objrepos.*Parallel Operating Environment' | wc -l`"
                case "$poepackage" in
                    *1 )
                        lac_cv_mpi="yes"
                    ;;
                    * )
                        lac_cv_mpi="no"
                    ;;
                esac
            ;;
            mips-sgi-irix* )
                if versions -I -b mpi | grep mpi >/dev/null 2>&1 ; then
                    lac_cv_mpi="yes"
                elif which mpirun > /dev/null 2>&1 ; then
                    mpi_basedir=`which mpirun | sed "s/\/usr\/bin\/mpirun//"`
                    versions_stdout=`versions -r $mpi_basedir -I -b mpi 2>/dev/null | grep " mpi "`
                    if test "X${versions_stdout}" = "X" ; then
                        lac_cv_mpi="no"
                    else
                        lac_cv_mpi="yes"
                    fi
                else
                     lac_cv_mpi="no"
                fi
            ;;
            alpha-cray-unicosmk* )
                lac_cv_mpi="yes"
            ;;
            *-hp-hpux10* | *-hp-hpux11* )
                lac_cv_mpi="yes"
            ;;
            i860-intel-osf* )
                lac_cv_mpi="yes"
            ;;
            * )
                lac_cv_mpi="no"
            ;;
        esac])
    AC_MSG_RESULT($lac_cv_mpi)

    if test "$lac_cv_mpi" != "yes" ; then
        AC_MSG_ERROR([This system does not support MPI])
        exit 1
    fi

    if test $GLOBUS_THREADS != "none" ; then
        case "$host" in
            *-ibm-aix* )
                if test ! -x /usr/bin/mpcc_r ; then
                    cant_do_mpi='true'
                fi
                ;;
            *-hp* )
                cant_do_mpi='true'
                ;;
        esac

        if test "$cant_do_mpi" = "true" ; then
            AC_MSG_ERROR([Cannot build MPI with threads on this system. Libs are not thread safe.])
            exit 1
        fi
    fi
])
