dnl
dnl accompiler.m4
dnl
dnl A configure.in should call exactly one of the following macros 
dnl supplied by this file:
dnl
dnl   LAC_COMPILERS_ARGS()
dnl     Use this to get all compiler related command line arguments
dnl     listed in configure --help.
dnl     Subsets of this can also be called explicitly
dnl         LAC_COMPILERS_ARGS_GENERAL()
dnl         LAC_COMPILERS_ARGS_TARGETST()
dnl         LAC_COMPILERS_ARGS_TARGETMT()
dnl         LAC_COMPILERS_ARGS_TARGET()
dnl         LAC_COMPILERS_ARGS_SERVICE()
dnl         LAC_COMPILERS_ARGS_HOST()
dnl
dnl   LAC_COMPILERS_TARGETST(REQUIRE-CXX-WORKS)
dnl     Set the various variables based on a single-threaded $target
dnl
dnl   LAC_COMPILERS_TARGETMT(REQUIRE-CXX-WORKS)
dnl     Set the various variables based on a multi-threaded $target
dnl
dnl   LAC_COMPILERS_TARGET(REQUIRE-CXX-WORKS)
dnl     Choose between TARGETST and TARGETMT, based on --with-threads argument.
dnl
dnl   LAC_COMPILERS_SERVICE(REQUIRE-CXX-WORKS)
dnl     Set the various variables based on a single-threaded $service
dnl
dnl   LAC_COMPILERS_HOST(REQUIRE-CXX-WORKS)
dnl     Set the various variables based on a single-threaded $host
dnl
dnl If the REQUIRE_CXX_WORKS argument is "yes", then this macro will 
dnl cause an error if the various C++ compilers do not work.
dnl
dnl The difference between TARGET, SERVICE, and HOST are as follows:
dnl   TARGET:  On a parallel computer, TARGET gives the compilers and options
dnl            to compile a program for the nodes of the parallel computer.
dnl   SERVICE: On a parallel computer, SERVICE gives the compilers and options
dnl            to compile a program for the services nodes of the parallel
dnl            computer.  For example, on a Paragon, this is the service
dnl            nodes onto which you typically login, etc.  On an IBM SP, 
dnl            this is the compile/service nodes (i.e. normal AIX machines).
dnl   HOST:    When cross compiling, HOST gives the compilers and options
dnl            to compile a program for the machine on which cross
dnl            compilation is occurring.
dnl
dnl The variables that are set and substituted (AC_SUBST) by the
dnl LAC_COMPILERS_* macros are:
dnl   CC
dnl   CPP
dnl   CFLAGS
dnl   CXX
dnl   CXXCPP
dnl   CXXFLAGS
dnl   LD
dnl   LDFLAGS
dnl   LIBS
dnl   AR
dnl   ARFLAGS
dnl   RANLIB
dnl   CXX_WORKS
dnl   CROSS
dnl   F77
dnl   F77FLAGS
dnl   F90
dnl   F90FLAGS
dnl
dnl CXX_WORKS is set to "yes" or "no", depending of if the C++
dnl             compiler works.
dnl
dnl CROSS is set to "yes" or "no", where "yes" means the compiler is
dnl         is a cross compiler.
dnl
dnl The following variables are cached:
dnl
dnl   lac_cv_TARGETST_CC
dnl   lac_cv_TARGETST_CPP
dnl   lac_cv_TARGETST_CFLAGS
dnl   lac_cv_TARGETST_CXX
dnl   lac_cv_TARGETST_CXXCPP
dnl   lac_cv_TARGETST_CXXFLAGS
dnl   lac_cv_TARGETST_LD
dnl   lac_cv_TARGETST_LDFLAGS
dnl   lac_cv_TARGETST_LIBS
dnl   lac_cv_TARGETST_AR
dnl   lac_cv_TARGETST_ARFLAGS
dnl   lac_cv_TARGETST_RANLIB
dnl   lac_cv_TARGETST_CXX_WORKS
dnl   lac_cv_TARGETST_CROSS
dnl   lac_cv_TARGETST_F77
dnl   lac_cv_TARGETST_F77FLAGS
dnl   lac_cv_TARGETST_F90
dnl   lac_cv_TARGETST_F90FLAGS
dnl
dnl   lac_cv_TARGETMT_CC
dnl   lac_cv_TARGETMT_CPP
dnl   lac_cv_TARGETMT_CFLAGS
dnl   lac_cv_TARGETMT_CXX
dnl   lac_cv_TARGETMT_CXXCPP
dnl   lac_cv_TARGETMT_CXXFLAGS
dnl   lac_cv_TARGETMT_LD
dnl   lac_cv_TARGETMT_LDFLAGS
dnl   lac_cv_TARGETMT_LIBS
dnl   lac_cv_TARGETMT_AR
dnl   lac_cv_TARGETMT_ARFLAGS
dnl   lac_cv_TARGETMT_RANLIB
dnl   lac_cv_TARGETMT_CXX_WORKS
dnl   lac_cv_TARGETMT_CROSS
dnl   lac_cv_TARGETMT_F77
dnl   lac_cv_TARGETMT_F77FLAGS
dnl   lac_cv_TARGETMT_F90
dnl   lac_cv_TARGETMT_F90FLAGS
dnl
dnl   lac_cv_SERVICE_CC
dnl   lac_cv_SERVICE_CPP
dnl   lac_cv_SERVICE_CFLAGS
dnl   lac_cv_SERVICE_CXX
dnl   lac_cv_SERVICE_CXXCPP
dnl   lac_cv_SERVICE_CXXFLAGS
dnl   lac_cv_SERVICE_LD
dnl   lac_cv_SERVICE_LDFLAGS
dnl   lac_cv_SERVICE_LIBS
dnl   lac_cv_SERVICE_AR
dnl   lac_cv_SERVICE_ARFLAGS
dnl   lac_cv_SERVICE_RANLIB
dnl   lac_cv_SERVICE_CXX_WORKS
dnl   lac_cv_SERVICE_CROSS
dnl   lac_cv_SERVICE_F77
dnl   lac_cv_SERVICE_F77FLAGS
dnl   lac_cv_SERVICE_F90
dnl   lac_cv_SERVICE_F90FLAGS
dnl
dnl   lac_cv_HOST_CC
dnl   lac_cv_HOST_CPP
dnl   lac_cv_HOST_CFLAGS
dnl   lac_cv_HOST_CXX
dnl   lac_cv_HOST_CXXCPP
dnl   lac_cv_HOST_CXXFLAGS
dnl   lac_cv_HOST_LD
dnl   lac_cv_HOST_LDFLAGS
dnl   lac_cv_HOST_LIBS
dnl   lac_cv_HOST_AR
dnl   lac_cv_HOST_ARFLAGS
dnl   lac_cv_HOST_RANLIB
dnl   lac_cv_HOST_CXX_WORKS
dnl   lac_cv_HOST_CROSS
dnl   lac_cv_HOST_F77
dnl   lac_cv_HOST_F77FLAGS
dnl   lac_cv_HOST_F90
dnl   lac_cv_HOST_F90FLAGS
dnl
dnl


dnl LAC_COMPILERS_ARGS()
AC_DEFUN(LAC_COMPILERS_ARGS,
[
LAC_COMPILERS_ARGS_GENERAL
LAC_COMPILERS_ARGS_TARGET
LAC_COMPILERS_ARGS_TARGETST
LAC_COMPILERS_ARGS_TARGETMT
LAC_COMPILERS_ARGS_SERVICE
LAC_COMPILERS_ARGS_HOST
])

dnl LAC_COMPILERS_ARGS_GENERAL()
AC_DEFUN(LAC_COMPILERS_ARGS_GENERAL,
[
AC_ARG_WITH(threads,
	[  --with-threads                build target with threads],
	[lac_cv_threads_type="$withval"],
	[lac_cv_threads_type=${lac_cv_threads_type='no'}])

dnl if test $lac_cv_threads_type != 'no' ; then
dnl   AC_MSG_WARN(System might have some problems when running under threaded mode)
dnl fi

LAC_THREADS_ARGS

AC_ARG_ENABLE(debug,
	[  --enable-debug                compile in debugging features],
	[lac_cv_debug="$enableval"],
	[lac_cv_debug=${lac_cv_debug='no'}])

AC_ARG_ENABLE(64bit,
	[  --enable-64bit                build 64-bit objects (SGI Irix 6.x and HP HPUX 11.x only)],
	[lac_cv_build_64bit="$enableval"],
	[lac_cv_build_64bit=${lac_cv_build_64bit='no'}])

AC_ARG_WITH(mpl,
	[  --with-mpl                    include the IBM SP MPL protocols],
	[if test "$withval" = "yes" ; then
             LAC_COMPILERS_MPL
         fi
        ],
	[lac_cv_mpl=${lac_cv_mpl='no'}])

AC_ARG_WITH(mpi,
	[  --with-mpi                    include the MPI protocols],
	[if test "$withval" = "yes" ; then
             LAC_COMPILERS_MPI
         fi
        ],
	[lac_cv_mpi=${lac_cv_mpi='no'}])

AC_ARG_WITH(inx,
	[  --with-inx                    include the Paragon INX protocols],
	[if test "$withval" = "yes" ; then
             LAC_COMPILERS_INX
         fi
        ],
	[lac_cv_inx=${lac_cv_inx='no'}])
])

AC_DEFUN(LAC_COMPILERS_MPL,
[
    AC_MSG_CHECKING(for MPL)
    AC_CACHE_VAL(lac_cv_mpl, [dnl
        case "$target" in
            *-ibm-aix* )
                poepackage="`/usr/bin/lslpp -clq | grep '/usr/lib/objrepos.*Parallel Operating Environment' | wc -l`"
                case "$poepackage" in
                    *1 )
                        lac_cv_mpl="yes"
                    ;;
                    * )
                        lac_cv_mpl="no"
                    ;;
                esac
            ;;
            * )
                lac_cv_mpl="no"
            ;;
        esac])
    AC_MSG_RESULT($lac_cv_mpl)
])

AC_DEFUN(LAC_COMPILERS_MPI,
[
    AC_MSG_CHECKING(for MPI)
    AC_CACHE_VAL(lac_cv_mpi, [dnl
        case "$target" in
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
            mips-sgi-irix6* )
                lac_cv_mpi="yes"
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
])

AC_DEFUN(LAC_COMPILERS_INX,
[
    AC_MSG_CHECKING(for INX)
    AC_CACHE_VAL(lac_cv_inx, [dnl
        case "$target" in
            i860-intel-osf* )
                lac_cv_inx="yes"
            ;;
            * )
                lac_cv_inx="no"
            ;;
        esac])
    AC_MSG_RESULT($lac_cv_inx)
])

dnl LAC_COMPILERS_MP_CLEANUP(IS-TARGET)
AC_DEFUN(LAC_COMPILERS_MP_CLEANUP,
[
    if test "$1" = "yes" ; then
        if test "$lac_cv_mpl" = "yes" ; then
            if test "$lac_cv_mpi" = "yes" -o "$lac_cv_inx" = "yes" ; then
                AC_MSG_ERROR([you can only use one of --with-mpi, --with-mpl, and --with-inx])
            fi
            lac_mpl=$lac_cv_mpl
        fi
        if test "$lac_cv_mpi" = "yes" ; then
            if test "$lac_cv_mpl" = "yes" -o "$lac_cv_inx" = "yes" ; then
                AC_MSG_ERROR([you can only use one of --with-mpi, --with-mpl, and --with-inx])
            fi
            lac_mpi=$lac_cv_mpi
        fi
        if test "$lac_cv_inx" = "yes" ; then
            if test "$lac_cv_mpi" = "yes" -o "$lac_cv_mpl" = "yes" ; then
                AC_MSG_ERROR([you can only use one of --with-mpi, --with-mpl, and --with-inx])
            fi
            lac_inx=$lac_cv_inx
        fi
    else
	lac_mpl="no"
        lac_mpi="no"
        lac_inx="no"
    fi
])


dnl LAC_COMPILERS_APPLY_ALL(FUNC, GROUP)
AC_DEFUN(LAC_COMPILERS_APPLY_ALL,
[
$1(CC, $2)dnl
$1(CPP, $2)dnl
$1(CFLAGS, $2)dnl
$1(CXX, $2)dnl
$1(CXXCPP, $2)dnl
$1(CXXFLAGS, $2)dnl
$1(LD, $2)dnl
$1(LDFLAGS, $2)dnl
$1(LIBS, $2)dnl
$1(AR, $2)dnl
$1(ARFLAGS, $2)dnl
$1(RANLIB, $2)dnl
$1(CXX_WORKS, $2)dnl
$1(CROSS, $2)dnl
$1(F77, $2)dnl
$1(F77FLAGS, $2)dnl
$1(F90, $2)dnl
$1(F90FLAGS, $2)dnl
])


AC_DEFUN(LAC_COMPILERS_ARGS_TARGETST, [LAC_COMPILERS_ARGS_GROUP(TARGETST)])
AC_DEFUN(LAC_COMPILERS_ARGS_TARGETMT, [LAC_COMPILERS_ARGS_GROUP(TARGETMT)])
AC_DEFUN(LAC_COMPILERS_ARGS_SERVICE, [LAC_COMPILERS_ARGS_GROUP(SERVICE)])
AC_DEFUN(LAC_COMPILERS_ARGS_HOST, [LAC_COMPILERS_ARGS_GROUP(HOST)])

dnl LAC_COMPILERS_ARGS_GROUP(GROUP)
AC_DEFUN(LAC_COMPILERS_ARGS_GROUP,
[
if test "$lac_ran_args_$1" != "yes" ; then
    LAC_COMPILERS_APPLY_ALL([LAC_COMPILERS_ARG_WITH], $1)
    lac_ran_args_$1="yes"
fi
])

dnl LAC_COMPILERS_ARG_WITH(VARIABLE,GROUP)
AC_DEFUN(LAC_COMPILERS_ARG_WITH,
[
    AC_ARG_WITH($2-$1,
	[  --with-$2-$1=value       \tset $2 $1],
	[lac_cv_$2_$1="$withval"],
	[lac_cv_$2_$1=${lac_cv_$2_$1='notset'}])
])


dnl LAC_COMPILERS_ARGS_TARGET(GROUP)
AC_DEFUN(LAC_COMPILERS_ARGS_TARGET,
[
if test "$lac_ran_args_$1" != "yes" ; then
    LAC_COMPILERS_APPLY_ALL([LAC_COMPILERS_ARG_WITH_TARGET], TARGET)
    lac_ran_args_$1="yes"
fi
])

dnl LAC_COMPILERS_ARG_WITH_TARGET(VARIABLE,GROUP)
AC_DEFUN(LAC_COMPILERS_ARG_WITH_TARGET,
[
    AC_ARG_WITH($2-$1,
	[  --with-$2-$1=value       \tset $2MT and $2ST $1],
	[lac_cv_$2MT_$1="$withval"
	 lac_cv_$2ST_$1="$withval"], )
])


dnl ---------------------------------------------------------------


dnl LAC_COMPILERS_*(REQUIRE-CXX-WORKS)
AC_DEFUN(LAC_COMPILERS_SERVICE,
[
LAC_COMPILERS_ARGS_GENERAL
LAC_COMPILERS_ARGS_SERVICE
LAC_COMPILERS_MP_CLEANUP(no)
LAC_THREADS_NONE
LAC_COMPILERS_SET($1,SERVICE,$service,no)
LAC_COMPILERS_OTHER($service,no)
])

AC_DEFUN(LAC_COMPILERS_HOST,
[
LAC_COMPILERS_ARGS_GENERAL
LAC_COMPILERS_ARGS_HOST
LAC_COMPILERS_MP_CLEANUP(no)
LAC_THREADS_NONE
LAC_COMPILERS_SET($1,HOST,$host,no)
LAC_COMPILERS_OTHER($host,no)
])

AC_DEFUN(LAC_COMPILERS_TARGETST,
[
LAC_COMPILERS_ARGS_GENERAL
LAC_COMPILERS_ARGS_TARGETST
LAC_COMPILERS_MP_CLEANUP(yes)
LAC_THREADS_NONE
LAC_COMPILERS_SET($1,TARGETST,$target,no)
LAC_COMPILERS_OTHER($target,no)
])

AC_DEFUN(LAC_COMPILERS_TARGETMT,
[
LAC_COMPILERS_ARGS_GENERAL
LAC_COMPILERS_ARGS_TARGETMT
LAC_COMPILERS_MP_CLEANUP(yes)
LAC_THREADS
LAC_COMPILERS_SET($1,TARGETMT,$target,$lac_cv_threads_type)
LAC_COMPILERS_OTHER($target,$lac_cv_threads_type)
])

AC_DEFUN(LAC_COMPILERS_TARGET,
[
LAC_COMPILERS_ARGS_GENERAL
LAC_COMPILERS_ARGS_TARGET
LAC_COMPILERS_ARGS_TARGETST
LAC_COMPILERS_ARGS_TARGETMT
LAC_COMPILERS_MP_CLEANUP(yes)

if test "$lac_cv_threads_type" = "no" ; then
    LAC_THREADS_NONE
    LAC_COMPILERS_SET($1,TARGETST,$target,no)
    LAC_COMPILERS_OTHER($target,no)
else
    LAC_THREADS
    LAC_COMPILERS_SET($1,TARGETMT,$target,$lac_cv_threads_type)
    LAC_COMPILERS_OTHER($target,$lac_cv_threads_type)
fi
])


dnl LAC_COMPILERS_OTHER(SYSTEM-TYPE,THREAD-TYPE)
AC_DEFUN(LAC_COMPILERS_OTHER,
[
dnl AC_PROG_YACC
dnl LAC_PROG_LEX
globus_cv_system_type=$1
globus_cv_threads_type=$2
])


dnl LAC_COMPILERS_SET(REQUIRE-CXX-WORKS,GROUP,TARGET,THREAD-TYPE)
AC_DEFUN(LAC_COMPILERS_SET,
[
echo "checking for $2 compilers..."
lac_all_values_$2=""
LAC_COMPILERS_APPLY_ALL([LAC_COMPILERS_ADD_VALUE], $2)
lac_var_not_set="no"
for lac_var in $lac_all_values_$2
do
    if test "$lac_var" = "notset" ; then
        lac_var_not_set="yes"
    fi
done
if test "$lac_var_not_set" = "yes" ; then
    LAC_COMPILERS_SET_ALL_VARS($1,$2,$3,$4)
fi

LAC_COMPILERS_APPLY_ALL([LAC_COMPILERS_SET_VAR], $2)

LAC_COMPILERS_SET_DEFAULT($2)
LAC_COMPILERS_PRINT_DEFAULT
])


dnl LAC_COMPILERS_ADD_VALUE(VARIABLE, GROUP)
AC_DEFUN(LAC_COMPILERS_ADD_VALUE,
[
lac_all_values_$2="$lac_all_values_$2 $lac_cv_$2_$1"
])


dnl LAC_COMPILERS_SET_VAR(VARIABLE, GROUP)
AC_DEFUN(LAC_COMPILERS_SET_VAR,
[
$2_$1=${lac_cv_[$2]_[$1]}
AC_SUBST($2_$1)
])


dnl LAC_COMPILERS_SET_ALL_VARS(REQUIRE-CXX-WORKS,GROUP,TARGET,THREAD-TYPE)
AC_DEFUN(LAC_COMPILERS_SET_ALL_VARS,
[
lac_CFLAGS=""
lac_CXXFLAGS=""
lac_LDFLAGS=""
lac_LIBS=""
lac_F77FLAGS=""
lac_F90FLAGS=""
unset lac_cflags_opt
unset lac_cxxflags_opt

case $3--$4 in
    *sunos4* ) 
	LAC_CHECK_PROGS(lac_cv_$2_CC, [gcc], gcc)
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [g++], g++)
	LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
	;;
    *solaris2*)
	cc_noucb_paths=`echo $PATH | sed 's-/usr/ucb--'`
	cc_opt_paths=`/usr/bin/find /opt -type f -name cc -print \
	  2>/dev/null | sed 's-/cc$--'`
	cc_opt_paths=`echo $cc_opt_paths | sed 's- -:-'`

	LAC_PATH_PROGS(lac_cv_$2_CC, [cc], notset,
                       [${cc_opt_paths}:${cc_noucb_paths}])
	LAC_CHECK_PROGS(lac_cv_$2_CC, [gcc], notset)

	LAC_PROG_CC_GNU($lac_cv_$2_CC,
			[if test "$4" = "solaristhreads" -o "$4" = "pthreads" ; then
				lac_CFLAGS="-D_REENTRANT $lac_CFLAGS"
			 fi
			],
			[if test "$4" = "solaristhreads" -o "$4" = "pthreads" ; then
				lac_CFLAGS="-mt $lac_CFLAGS"
			 fi
			 lac_cflags_opt="-xO3"
			])

	cxx_opt_paths=`/usr/bin/find /opt -type f -name CC -print \
	  2>/dev/null | sed 's-/CC$--'`
	cxx_opt_paths=`echo $cxx_opt_paths | sed 's- -:-'`
	LAC_PATH_PROGS(lac_cv_$2_CXX, [CC], notset, [${cxx_opt_paths}])
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [CC g++], CC)

	LAC_PROG_CC_GNU($lac_cv_$2_CXX,
			[if test "$4" = "solaristhreads" -o "$4" = "pthreads" ; then
				lac_CXXFLAGS="-D_REENTRANT $lac_CXXFLAGS"
			 fi
			],
			[if test "$4" = "solaristhreads" -o "$4" = "pthreads" ; then
				lac_CXXFLAGS="-mt $lac_CXXFLAGS"
			 fi
			 lac_cxxflags_opt="-xO3"
			])
	lac_LIBS="$lac_LIBS -lsocket -lnsl"

	f77_opt_paths=`/usr/bin/find /opt -type f -name f77 -print \
	  2>/dev/null | sed 's-/f77$--'`
	f77_opt_paths=`echo $f77_opt_paths | sed 's- -:-'`
	LAC_PATH_PROGS(lac_cv_$2_F77, [f77], notset, [${f77_opt_paths}])
	LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)

	f90_opt_paths=`/usr/bin/find /opt -type f -name f90 -print \
	  2>/dev/null | sed 's-/f90$--'`
	f90_opt_paths=`echo $f90_opt_paths | sed 's- -:-'`
	LAC_PATH_PROGS(lac_cv_$2_F90, [f90], notset, [${f90_opt_paths}])
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)

	;;
    *-hp-hpux11* )
        if test "$GCC" != "yes"; then
           case $lac_cv_build_64bit in
               yes )  lac_64bit_flag="+DA2.0W"
                      ;;

               +*  )  lac_64bit_flag="$lac_cv_build_64bit"
                      ;;

               *   )  lac_64bit_flag="+DA2.0"  
                      ;;
           esac
        else
           lac_64_bit_flag=""
        fi

        if test "$lac_mpi" != "yes" ; then
	    LAC_CHECK_PROGS(lac_cv_$2_CC, [cc gcc], gcc)
	    LAC_PROG_CC_GNU($lac_cv_$2_CC, ,
		[lac_CFLAGS="$lac_64bit_flag -Aa -D_HPUX_SOURCE $lac_CFLAGS"
                 lac_LDFLAGS="$lac_64bit_flag -Aa $lac_LDFLAGS"])
	    LAC_CHECK_PROGS(lac_cv_$2_CXX, [aCC g++], g++)
	    LAC_PROG_CC_GNU($lac_cv_$2_CXX, ,
		[lac_CXXFLAGS="$lac_64bit_flag -Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
	    LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	    LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
        else
            dnl for --with-threads=pthreads and --with-mpi, we need
            dnl to compile with an additional -lmtmpi, even when not
            dnl linking
            LAC_CHECK_PROGS(lac_cv_$2_CC, [mpicc], mpicc)
            LAC_CHECK_PROGS(lac_cv_$2_CXX, [mpiCC], mpiCC)
	    LAC_CHECK_PROGS(lac_cv_$2_F77, [mpif77], mpif77)
	    LAC_CHECK_PROGS(lac_cv_$2_F90, [mpif90], mpif90)
            if test "$4" = "pthreads" ; then
                lac_CFLAGS="$lac_CFLAGS -lmtmpi"
                lac_CXXFLAGS="$lac_CXXFLAGS -lmtmpi"
            fi
            LAC_PROG_CC_GNU($lac_cv_$2_CC, ,
                [lac_CFLAGS="$lac_64bit_flag -Ae -D_HPUX_SOURCE $lac_CFLAGS"
                 lac_LDFLAGS="$lac_64bit_flag -Ae $lac_LDFLAGS"])
            LAC_PROG_CC_GNU($lac_cv_$2_CXX, ,
                [lac_CXXFLAGS="$lac_64bit_flag -Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
        fi
        ;;
    *-hp-hpux10*--no )
	if test "$lac_mpi" != "yes" ; then
	    LAC_CHECK_PROGS(lac_cv_$2_CC, [cc gcc], gcc)
	    LAC_CHECK_PROGS(lac_cv_$2_CXX, [CC g++], g++)
	    LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	    LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
	else
	    LAC_CHECK_PROGS(lac_cv_$2_CC, [mpicc], mpicc)
	    LAC_CHECK_PROGS(lac_cv_$2_CXX, [mpiCC], mpiCC)
	    LAC_CHECK_PROGS(lac_cv_$2_F77, [mpif77], mpif77)
	    LAC_CHECK_PROGS(lac_cv_$2_F90, [mpif90], mpif90)
	fi
        LAC_PROG_CC_GNU($lac_cv_$2_CC, ,
            [lac_CFLAGS="-Ae -D_HPUX_SOURCE $lac_CFLAGS"])
        LAC_PROG_CC_GNU($lac_cv_$2_CXX, ,
            [lac_CXXFLAGS="-Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
        ;;
    *-hp-hpux9* | *-hp-hpux10* )
	LAC_CHECK_PROGS(lac_cv_$2_CC, [cc gcc], gcc)
	LAC_PROG_CC_GNU($lac_cv_$2_CC, ,
		[lac_CFLAGS="-Ae -D_HPUX_SOURCE $lac_CFLAGS"])
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [CC g++], g++)
	LAC_PROG_CC_GNU($lac_cv_$2_CXX, ,
		[lac_CXXFLAGS="-Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
        case "$target" in
          *-hp-hpux9* )
 	      lac_LDFLAGS="-Wl -a,archive"
            ;;
        esac
	if test "$4" = "pthreads" ; then
	    lac_CFLAGS="$lac_CFLAGS -I/usr/include/reentrant"
	    lac_CXXFLAGS="$lac_CXXFLAGS -I/usr/include/reentrant"
	fi
        LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
	;;
    mips-sgi-irix5* )
	LAC_CHECK_PROGS(lac_cv_$2_CC, [cc gcc], gcc)
	LAC_PROG_CC_GNU($lac_cv_$2_CC, ,
		[lac_CFLAGS="-woff 3262 $lac_CFLAGS"])
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [CC g++], g++)
	LAC_PROG_CC_GNU($lac_cv_$2_CXX, ,
		[lac_CFLAGS="-woff 3262 $lac_CFLAGS"])
        lac_cv_$2_ARFLAGS="crv"
        LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
      ;;	
    mips-sgi-irix6* )

dnl     if test "$lac_cv_build_64bit" = "yes" -a "$GCC" != "yes"; then
dnl	    lac_64bit_flag="-64"
dnl	fi

        if test "$GCC" != "yes"; then
           case $lac_cv_build_64bit in
               yes )  lac_64bit_flag="-64"
                      ;;

               -*  )  lac_64bit_flag="$lac_cv_build_64bit"
                      ;;

               *   )  lac_64bit_flag="-n32"  
                      ;;
           esac
        else
           lac_64_bit_flag=""
        fi

	LAC_CHECK_PROGS(lac_cv_$2_CC, [cc gcc], gcc)
	LAC_PROG_CC_GNU($lac_cv_$2_CC, ,[])

	LAC_CHECK_CFLAGS($lac_cv_$2_CC,[$lac_64bit_flag $lac_CFLAGS],
		[lac_CFLAGS="$lac_64bit_flag $lac_CFLAGS"
		 lac_LDFLAGS="$lac_64bit_flag $lac_LDFLAGS"])

	LAC_CHECK_CFLAGS($lac_cv_$2_CC,[-woff 1048 $lac_CFLAGS],
		[lac_CFLAGS="-woff 1048 $lac_CFLAGS"])

	LAC_CHECK_LDFLAGS($lac_cv_$2_CC,
		[$lac_CFLAGS],[-Wl,-woff,84 $lac_LDFLAGS],
		[lac_LDFLAGS="-Wl,-woff,84 $lac_LDFLAGS"])

	LAC_CHECK_PROGS(lac_cv_$2_CXX, [CC g++], g++)
	LAC_PROG_CC_GNU($lac_cv_$2_CXX, ,
		[lac_CXXFLAGS="$lac_64bit_flag $lac_CXXFLAGS"])
	LAC_CHECK_CFLAGS($lac_cv_$2_CXX, [-woff 1048 $lac_CXXFLAGS],
		[lac_CXXFLAGS="-woff 1048 $lac_CXXFLAGS"])		

        dnl RANLIB is more or less defunct on SIG IRIX6.
        dnl Don't set RANLIB for since if its present its
	dnl probable gnu and is incompatible
        dnl     This fixes the reported problem on  modi4.ncsa.uiuc.edu 
	lac_cv_$2_RANLIB="true"

        if test "$lac_mpi" = "yes" ; then
            lac_LIBS="$lac_LIBS -lmpi"
        fi

        LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
	lac_F77FLAGS="$lac_64bit_flag $lac_F77FLAGS"
	lac_F90FLAGS="$lac_64bit_flag $lac_F90FLAGS"
      ;;	
    *-ibm-aix*--pthreads )
	if test "$lac_mpl" != "yes" -a "$lac_mpi" != "yes" ; then
	    LAC_CHECK_PROGS(lac_cv_$2_CC, [xlc_r], xlc_r)
	    LAC_CHECK_PROGS(lac_cv_$2_CXX, [xlC_r], xlC_r)
	    LAC_CHECK_PROGS(lac_cv_$2_F77, [xlf_r], xlf_r)
	    LAC_CHECK_PROGS(lac_cv_$2_F90, [xlf90_r], xlf_r)
	    if test "$lac_cv_$2_F90" = "xlf_r" ; then
		lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
	    fi
	else
	    LAC_CHECK_PROGS(lac_cv_$2_CC, [mpcc_r], mpcc_r)
	    LAC_CHECK_PROGS(lac_cv_$2_CXX, [mpCC_r], mpCC_r)
	    LAC_CHECK_PROGS(lac_cv_$2_F77, [mpxlf_r], mpxlf_r)
	    LAC_CHECK_PROGS(lac_cv_$2_F90, [mpxlf90_r], mpxlf_r)
	    if test "$lac_cv_$2_F90" = "mpxlf_r" ; then
		lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
	    fi
	fi
	lac_CFLAGS="-D_ALL_SOURCE $lac_CFLAGS"
	lac_CXXFLAGS="-D_ALL_SOURCE $lac_CXXFLAGS"
        if test "$lac_cv_debug" = "yes"; then
	    lac_CFLAGS="-qfullpath $lac_CFLAGS"
	    lac_CXXFLAGS="-qfullpath $lac_CXXFLAGS"
	fi
      ;;
    *-ibm-aix*--no )
	if test "$lac_mpl" != "yes" -a "$lac_mpi" != "yes" ; then
	    LAC_CHECK_PROGS(lac_cv_$2_CC, [xlc gcc], gcc)
	    LAC_CHECK_PROGS(lac_cv_$2_CXX, [xlC g++], g++)
	    LAC_CHECK_PROGS(lac_cv_$2_F77, [xlf], xlf)
	    LAC_CHECK_PROGS(lac_cv_$2_F90, [xlf90], xlf)
	    if test "$lac_cv_$2_F90" = "xlf" ; then
		lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
	    fi
	else
	    LAC_CHECK_PROGS(lac_cv_$2_CC, [mpcc], mpcc)
	    LAC_CHECK_PROGS(lac_cv_$2_CXX, [mpCC], mpCC)
	    LAC_CHECK_PROGS(lac_cv_$2_F77, [mpxlf], mpxlf)
	    LAC_CHECK_PROGS(lac_cv_$2_F90, [mpxlf90], mpxlf)
	    if test "$lac_cv_$2_F90" = "mpxlf" ; then
		lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
	    fi
	fi
	lac_CFLAGS="-D_ALL_SOURCE $lac_CFLAGS"
	lac_CXXFLAGS="-D_ALL_SOURCE $lac_CXXFLAGS"
        if test "$lac_cv_debug" = "yes"; then
	    lac_CFLAGS="-qfullpath $lac_CFLAGS"
	    lac_CXXFLAGS="-qfullpath $lac_CXXFLAGS"
	fi
      ;;
    i860-intel-osf* )
	LAC_CHECK_PROGS(lac_cv_$2_CC, [icc], icc)
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [iCC], iCC)
	if test "$2" != "SERVICE" -a "$2" != "HOST" ; then
	    lac_CFLAGS="-nx $lac_CFLAGS"
	    lac_CXXFLAGS="-nx $lac_CXXFLAGS"
	    lac_LDFLAGS="-nx $lac_LDFLAGS"
	fi
        if test "$lac_mpi" = "yes" ; then
            lac_LIBS="$lac_LIBS -lmpi"
        fi
	LAC_CHECK_PROGS(lac_cv_$2_AR, [ar860], ar860)
	LAC_CHECK_PROGS(lac_cv_$2_RANLIB, [true], true)
	LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
      ;;
    alpha-dec-osf3* )
	LAC_CHECK_PROGS(lac_cv_$2_CC, [cc gcc], gcc)
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [cxx g++], g++)
	if test "$4" = "pthreads" ; then
            LAC_PROG_CC_GNU($lac_cv_$2_CC,
			[ ],
			[lac_CFLAGS="-threads $lac_CFLAGS"])
	    LAC_PROG_CC_GNU($lac_cv_$2_CXX,
			[ ],
			[lac_CXXFLAGS="-threads $lac_CXXFLAGS"])
	fi
	LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
      ;;
    alpha-dec-osf4* )
	LAC_CHECK_PROGS(lac_cv_$2_CC, [cc gcc], gcc)
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [CC cxx g++], g++)
	if test "$4" = "pthreads" ; then
            LAC_PROG_CC_GNU($lac_cv_$2_CC,
			[ ],
			[lac_CFLAGS="-pthread $lac_CFLAGS"
			 lac_LDFLAGS="-pthread $lac_LDFLAGS"])
	    LAC_PROG_CC_GNU($lac_cv_$2_CXX,
			[ ],
			[lac_CXXFLAGS="-pthread $lac_CXXFLAGS"])
	fi
        lac_CFLAGS="-D_OSF_SOURCE $lac_CFLAGS"
        lac_CXXFLAGS="-D_OSF_SOURCE $lac_CXXFLAGS"
	LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
      ;;
    alpha-cray-unicosmk* )
	dnl Cray T3E
	LAC_CHECK_PROGS(lac_cv_$2_CC, [cc], cc)
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [CC], CC)
	lac_CFLAGS="-Xm $lac_CFLAGS"
	lac_CXXFLAGS="-Xm $lac_CXXFLAGS"
	lac_LDFLAGS="-Xm $lac_LDFLAGS"
	LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
      ;;
    *linux*--pthreads )
	LAC_CHECK_PROGS(lac_cv_$2_CC, [cc gcc], gcc)
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [CC g++], g++)
	LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
	lac_CFLAGS="-D_REENTRANT $lac_CFLAGS"
	lac_CXXFLAGS="-D_REENTRANT $lac_CXXFLAGS"
      ;;
    * ) 
	LAC_CHECK_PROGS(lac_cv_$2_CC, [cc gcc], gcc)
	LAC_CHECK_PROGS(lac_cv_$2_CXX, [CC g++], g++)
	LAC_CHECK_PROGS(lac_cv_$2_F77, [f77], f77)
	LAC_CHECK_PROGS(lac_cv_$2_F90, [f90], f90)
      ;;
esac

if test "$4" != "no" ; then
    lac_CFLAGS="$lac_CFLAGS $lac_cv_threads_CFLAGS"
    lac_CXXFLAGS="$lac_CXXFLAGS $lac_cv_threads_CXXFLAGS"
    lac_LDFLAGS="$lac_LDFLAGS $lac_cv_threads_LDFLAGS"
    lac_LIBS="$lac_LIBS $lac_cv_threads_LIBS"
fi

if test -z "$lac_cv_[$2]_CC" ; then
    AC_MSG_ERROR([no acceptable C compiler found in \$PATH])
fi
if test "$lac_cv_debug" = "yes"; then
    lac_CFLAGS="-g $lac_CFLAGS"
    lac_CXXFLAGS="-g $lac_CXXFLAGS"
else
    if test -z "$lac_cflags_opt" ; then
	lac_CFLAGS="-O $lac_CFLAGS"
    else
	lac_CFLAGS="$lac_cflags_opt $lac_CFLAGS"
    fi
    if test -z "$lac_cxxflags_opt" ; then
	lac_CXXFLAGS="-O $lac_CXXFLAGS"
    else
	lac_CXXFLAGS="$lac_cxx_flags_opt $lac_CXXFLAGS"
    fi
fi
if test "$lac_cv_$2_CFLAGS" = "notset" ; then
    lac_cv_$2_CFLAGS=$lac_CFLAGS
fi
if test "$lac_cv_$2_CXXFLAGS" = "notset" ; then
    lac_cv_$2_CXXFLAGS=$lac_CXXFLAGS
fi
if test "$lac_cv_$2_LDFLAGS" = "notset" ; then
    lac_cv_$2_LDFLAGS=$lac_LDFLAGS
fi
if test "$lac_cv_$2_LIBS" = "notset" ; then
    lac_cv_$2_LIBS=$lac_LIBS
fi
if test "$lac_cv_$2_CPP" = "notset" ; then
    lac_cv_$2_CPP="$lac_cv_$2_CC -E"
fi
if test "$lac_cv_$2_CXXCPP" = "notset" ; then
    lac_cv_$2_CXXCPP="$lac_cv_$2_CXX -E"
fi
if test "$lac_cv_$2_F77FLAGS" = "notset" ; then
    lac_cv_$2_F77FLAGS=$lac_F77FLAGS
fi
if test "$lac_cv_$2_F90FLAGS" = "notset" ; then
    lac_cv_$2_F90FLAGS=$lac_F90FLAGS
fi


dnl Note that if RANLIB is set appropriate
dnl This line should do nothing
LAC_CHECK_PROGS(lac_cv_$2_RANLIB, [ranlib true], true)


LAC_CHECK_PROGS(lac_cv_$2_AR, [ar], ar)
if test "$lac_cv_$2_ARFLAGS" = "notset" ; then
    lac_cv_$2_ARFLAGS="ruv"
fi


LAC_COMPILERS_SET_DEFAULT($2)

unset ac_cv_prog_cc_works
unset ac_cv_prog_cc_cross
AC_PROG_CC_WORKS
if test "$lac_cv_$2_CROSS" = "notset" ; then
    lac_cv_$2_CROSS=$cross_compiling
fi
LAC_CHECK_CC_PROTOTYPES

if test "$1" = "yes" ; then
    unset ac_cv_prog_cxx_works
    unset ac_cv_prog_cxx_cross
    AC_PROG_CXX_WORKS
else
    ac_cv_prog_cxx_works="unknown"
fi
if test "$lac_cv_$2_CXX_WORKS" = "notset" ; then
    lac_cv_$2_CXX_WORKS=$ac_cv_prog_cxx_works
fi

if test "$globus_cv_nxproto_xtp" = "yes" ; then
    lac_cv_$2_LD=${lac_cv_$2_CXX}
else
    lac_cv_$2_LD=${lac_cv_$2_CC}
fi
])


dnl LAC_CHECK_PROGS(VARIABLE, PROGS-TO-CHECK-FOR [, VALUE-IF-NOT-FOUND
dnl                 [, PATH]])
AC_DEFUN(LAC_CHECK_PROGS,
[
if test "${[$1]}" = "notset" ; then
    unset $1
    AC_CHECK_PROGS($1, $2, $3, $4)
fi
])

dnl LAC_PATH_PROGS(VARIABLE, PROGS-TO-CHECK-FOR [, VALUE-IF-NOT-FOUND
dnl                 [, PATH]])
AC_DEFUN(LAC_PATH_PROGS,
[
if test "${[$1]}" = "notset" ; then
    unset $1
    AC_PATH_PROGS($1, $2, $3, $4)
fi
])

dnl LAC_PROG_CC_GNU(COMPILER, ACTION-IF-TRUE, ACTION-IF-FALSE)
AC_DEFUN(LAC_PROG_CC_GNU,
[dnl The semicolon is to pacify NeXT's syntax-checking cpp.
cat > conftest.c <<EOF
#ifdef __GNUC__
  yes;
#endif
EOF
if AC_TRY_COMMAND($1 -E conftest.c) | egrep yes >/dev/null 2>&1; then
    lac_prog_cc_gnu_tmp=""
    $2
else
    lac_prog_cc_gnu_tmp=""
    $3
fi])


dnl LAC_CHECK_CC_PROTOTYPES(true-action, false-action)
dnl Check that the compiler accepts ANSI prototypes.
AC_DEFUN(LAC_CHECK_CC_PROTOTYPES,[
AC_MSG_CHECKING(that the compiler $CC accepts ANSI prototypes)
AC_TRY_COMPILE([int f(double a){return 0;}],,
  eval "ac_cv_ccworks=yes",
  eval "ac_cv_ccworks=no")
if test "$ac_cv_ccworks" = yes; then
  AC_MSG_RESULT(yes)
  $1
else
  AC_MSG_RESULT(no)
  $2
fi
])

dnl
dnl LAC_CHECK_CFLAGS(compiler,flags,true-action,false-action)
dnl
AC_DEFUN(LAC_CHECK_CFLAGS,[
AC_MSG_CHECKING(that the compiler $1 accepts arguments $2)
cat > conftest.c <<EOF
#include "confdefs.h"
int main(void)
{
    return 0;
}
EOF
if test "X`$1 $2 -c conftest.c 2>&1`" = "X" ; then
    AC_MSG_RESULT(yes)
    $3
else
    AC_MSG_RESULT(no)
    $4
fi
])

dnl
dnl LAC_CHECK_LDFLAGS(compiler,cflags,ldflags,true-action,false-action)
dnl
AC_DEFUN(LAC_CHECK_LDFLAGS,[
AC_MSG_CHECKING(that the compiler accepts compiler/link flags $2 $3)
cat > conftest.c <<EOF
#include "confdefs.h"
int main(void)
{
    return 0;
}
EOF
if test "X`$1 $2 conftest.c $3 2>&1`" = "X" ; then
    AC_MSG_RESULT(yes)
    $4
else
    AC_MSG_RESULT(no)
    $5
fi
])


dnl LAC_COMPILERS_SET_DEFAULT(GROUP)
AC_DEFUN(LAC_COMPILERS_SET_DEFAULT,
[
LAC_COMPILERS_APPLY_ALL([LAC_COMPILERS_SET_DEFAULT_VAR], $1)
])

dnl LAC_COMPILERS_SET_DEFAULT_VAR(VARIABLE, GROUP)
dnl
dnl GLOBUS_* aliases are created to avoid undesirable side effects
dnl associated with defining symbols which conflict with those
dnl  defined in the set of autoconf macros. --BRT
AC_DEFUN(LAC_COMPILERS_SET_DEFAULT_VAR,
[dnl
$1=$lac_cv_$2_$1
GLOBUS_$1=$lac_cv_$2_$1
AC_SUBST($1)dnl
AC_SUBST(GLOBUS_$1)dnl
])

dnl LAC_COMPILERS_PRINT_DEFAULT()
AC_DEFUN(LAC_COMPILERS_PRINT_DEFAULT,
[dnl
LAC_COMPILERS_APPLY_ALL([LAC_COMPILERS_PRINT_DEFAULT_VAR], FOO)dnl
])

dnl LAC_COMPILERS_PRINT_DEFAULT_VAR(VARIABLE, GROUP)
AC_DEFUN(LAC_COMPILERS_PRINT_DEFAULT_VAR,
[dnl
echo "setting $1=$[GLOBUS_$1]"
])
