dnl
dnl accompiler2.m4
dnl
dnl Probe for the basic compiler tools needed to build globus.
dnl Users of this module should call
dnl LAC_COMPILERS(REQUIRE-CXX-WORKS)
dnl To set the various variables
dnl
dnl If the REQUIRE_CXX_WORKS argument is "yes", then this macro will
dnl cause an error if the various C++ compilers do not work.
dnl
dnl The variables that are set and substituted (AC_SUBST) by the
dnl LAC_COMPILERS macro are:
dnl   CC
dnl   CPP
dnl   CPPFLAGS
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
dnl   INSURE
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
dnl   lac_cv_CC
dnl   lac_cv_CPP
dnl   lac_cv_CFLAGS
dnl   lac_cv_CPPFLAGS
dnl   lac_cv_CXX
dnl   lac_cv_CXXCPP
dnl   lac_cv_CXXFLAGS
dnl   lac_cv_LD
dnl   lac_cv_LDFLAGS
dnl   lac_cv_LIBS
dnl   lac_cv_AR
dnl   lac_cv_ARFLAGS
dnl   lac_cv_RANLIB
dnl   lac_cv_CXX_WORKS
dnl   lac_cv_CROSS
dnl   lac_cv_INSURE
dnl   lac_cv_F77
dnl   lac_cv_F77FLAGS
dnl   lac_cv_F90
dnl   lac_cv_F90FLAGS
dnl
dnl

dnl LAC_COMPILERS_ARGS()
AC_DEFUN(LAC_COMPILERS_ARGS,
[
AC_ARG_WITH(threads,
	[  --with-threads=TYPE		build target with threads],
	[lac_cv_threads_type="$withval"],
	[lac_cv_threads_type=${lac_cv_threads_type='no'}])

LAC_THREADS_ARGS

AC_ARG_ENABLE(debug,
	[  --enable-debug                compile in debugging features],
	[lac_cv_debug="$enableval"],
	[lac_cv_debug=${lac_cv_debug='no'}])

AC_ARG_ENABLE(64bit,
	[  --enable-64bit                build 64-bit objects (SGI Irix 6.x, HP HPUX 11.x, IA-64 only)],
	[lac_cv_build_64bit="$enableval"],
	[lac_cv_build_64bit=${lac_cv_build_64bit='no'}])

AC_ARG_ENABLE(insure,
 	changequote(<<, >>)dnl
  <<--enable-insure[=PATH]	use Insure++ [default=insure]>>,
	changequote([, ])dnl
	[
		if test "$enableval" = "yes"; then
			lac_cv_INSURE="insure"
		else
			lac_cv_INSURE="$enableval"
		fi
	],
	[
		lac_cv_INSURE=""
	])
])

AC_DEFUN(LAC_COMPILERS,
[
AC_CANONICAL_HOST
LAC_COMPILERS_ARGS
LAC_THREADS
LAC_MP

LAC_COMPILERS_SET($lac_threads_type)

LAC_SUBSTITUTE_COMPILER_VAR(CC)
LAC_SUBSTITUTE_COMPILER_VAR(CPP)
LAC_SUBSTITUTE_COMPILER_VAR(CFLAGS)
LAC_SUBSTITUTE_COMPILER_VAR(CPPFLAGS)
LAC_SUBSTITUTE_COMPILER_VAR(CXX)
LAC_SUBSTITUTE_COMPILER_VAR(CXXCPP)
LAC_SUBSTITUTE_COMPILER_VAR(CXXFLAGS)
LAC_SUBSTITUTE_COMPILER_VAR(LD)
LAC_SUBSTITUTE_COMPILER_VAR(LDFLAGS)
LAC_SUBSTITUTE_COMPILER_VAR(LIBS)
LAC_SUBSTITUTE_COMPILER_VAR(AR)
LAC_SUBSTITUTE_COMPILER_VAR(ARFLAGS)
LAC_SUBSTITUTE_COMPILER_VAR(RANLIB)
LAC_SUBSTITUTE_COMPILER_VAR(INSURE)
LAC_SUBSTITUTE_COMPILER_VAR(F77)
LAC_SUBSTITUTE_COMPILER_VAR(CROSS)
LAC_SUBSTITUTE_COMPILER_VAR(F77FLAGS)
LAC_SUBSTITUTE_COMPILER_VAR(F90)
LAC_SUBSTITUTE_COMPILER_VAR(F90FLAGS)
])

dnl LAC_SUBSTITUTE_COMPILER_VAR
AC_DEFUN(LAC_SUBSTITUTE_COMPILER_VAR,
[
    if test -n "[$]lac_cv_$1"; then
        $1=[$]lac_cv_$1
        AC_SUBST($1)
    fi
])

dnl LAC_COMPILERS_SET(THREAD-TYPE)
AC_DEFUN(LAC_COMPILERS_SET,
[
echo "checking for compilers..."
LAC_COMPILERS_SET_ALL_VARS($1)
])


dnl LAC_COMPILERS_SET_ALL_VARS(THREAD-TYPE)
AC_DEFUN(LAC_COMPILERS_SET_ALL_VARS,
[
lac_CFLAGS="$CFLAGS "
lac_CPPFLAGS="$CPPFLAGS -I$GLOBUS_LOCATION/include -I$GLOBUS_LOCATION/include/$globus_cv_flavor"
lac_CXXFLAGS="$CXXFLAGS "
lac_LDFLAGS="$LDFLAGS "
lac_LIBS="$LIBS "
lac_F77FLAGS="$F77FLAGS "
lac_F90FLAGS="$F90FLAGS "
unset lac_cflags_opt
unset lac_cxxflags_opt
case ${host}--$1 in
    *solaris2*)
        dnl On Solaris, avoid the pre-ansi BSD compatibility compiler

        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
        if test ! -z "$CC"; then
            AC_CHECK_PROG(lac_cv_CC, $CC, $CC, , , /usr/ucb/cc)
        fi
        if test -z "$lac_cv_CC"; then
            AC_CHECK_PROG(lac_cv_CC, cc, cc, , , /usr/ucb/cc)
	fi
        dnl if test -z "$lac_cv_CC" ; then
	dnl    AC_CHECK_PROG(lac_cv_CC, gcc, gcc)
        dnl fi
        dnl if test -n "$lac_cv_CC" ; then
        dnl    AC_PATH_PROG(lac_cv_CC, $lac_cv_CC)
	
	if test "$GLOBUS_CC" = "gcc"; then
	    AC_PATH_PROGS(lac_cv_CC, $CC gcc)
	else
	    AC_PATH_PROGS(lac_cv_CC, $CC cc $lac_cv_CC)
	fi
	CC="$lac_cv_CC"
        dnl fi

	LAC_PROG_CC_GNU($lac_cv_CC,
			[if test "$1" = "solaristhreads" -o "$1" = "pthreads" ; then
				lac_CFLAGS="-D_REENTRANT $lac_CFLAGS"
			 fi],
			[if test "$1" = "solaristhreads" -o "$1" = "pthreads" ; then
				lac_CFLAGS="-mt $lac_CFLAGS"
			 fi
			 lac_cflags_opt="-xO3"])

	AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)

	LAC_PROG_CC_GNU($lac_cv_CXX,
			[if test "$1" = "solaristhreads" -o "$1" = "pthreads" ; then
				lac_CXXFLAGS="-D_REENTRANT $lac_CXXFLAGS"
			 fi
			],
			[if test "$1" = "solaristhreads" -o "$1" = "pthreads" ; then
				lac_CXXFLAGS="-mt $lac_CXXFLAGS"
			 fi
			 lac_cxxflags_opt="-xO3"
			])
	AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
	AC_PATH_PROGS(lac_cv_F90, $F90 f90)
	;;
    *ia64-*linux* )
        if test "$lac_cv_build_64bit" = "no"; then
            AC_MSG_ERROR(32 bits not supported on this platform)
            exit 1
        fi
	dnl AC_PATH_PROGS(lac_cv_CC, $CC cc gcc)
	if test "$GLOBUS_CC" = "gcc"; then
	    AC_PATH_PROGS(lac_cv_CC, $CC gcc)
	else
	    AC_PATH_PROGS(lac_cv_CC, $CC cc)
	fi
	CC="$lac_cv_CC"
	AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
	AC_PATH_PROGS(lac_cv_F77, $F77 f77)
	AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        ;;
    alpha*linux* )
        if test "$lac_cv_build_64bit" = "no"; then
            AC_MSG_ERROR(32 bits not supported on this platform)
            exit 1
        fi
	dnl AC_PATH_PROGS(lac_cv_CC, $CC cc gcc)
	if test "$GLOBUS_CC" = "gcc"; then
	    AC_PATH_PROGS(lac_cv_CC, $CC gcc)
	else
	    AC_PATH_PROGS(lac_cv_CC, $CC ccc cc)
	fi
	CC="$lac_cv_CC"
	AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
	AC_PATH_PROGS(lac_cv_F77, $F77 f77)
	AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        ;;
    *-hp-hpux11* )
           case $lac_cv_build_64bit in
               yes )  lac_64bit_flag="+DA2.0W"
                      ;;

               +*  )  lac_64bit_flag="$lac_cv_build_64bit"
                      ;;

               *   )  lac_64bit_flag="+DA2.0"
                      ;;
           esac

        if test "$lac_mpi" != "yes" ; then
	    dnl AC_PATH_PROGS(lac_cv_CC, $CC cc gcc)
	    if test "$GLOBUS_CC" = "gcc"; then
	        AC_PATH_PROGS(lac_cv_CC, $CC gcc)
	    else
	        AC_PATH_PROGS(lac_cv_CC, $CC cc)
	    fi
	    CC="$lac_cv_CC"
	    LAC_PROG_CC_GNU($lac_cv_CC, ,
		[lac_CFLAGS="$lac_64bit_flag -Ae -D_HPUX_SOURCE $lac_CFLAGS"
                 lac_LDFLAGS="$lac_64bit_flag -Ae $lac_LDFLAGS"])
	    AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC aCC c++ g++ gcc)
	    LAC_PROG_CC_GNU($lac_cv_CXX, ,
		[lac_CXXFLAGS="$lac_64bit_flag -Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
	    AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
	    AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        else
            dnl for --with-threads=pthreads and --with-mpi, we need
            dnl to compile with an additional -lmtmpi, even when not
            dnl linking
            dnl AC_PATH_PROGS(lac_cv_CC, $CC mpicc)
	    if test "$GLOBUS_CC" = "gcc"; then
	        $lac_cv_CC=""
	    else
	        AC_PATH_PROGS(lac_cv_CC, $CC mpicc)
	    fi
	    CC="$lac_cv_CC"
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
	    AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
	    AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
            if test "$1" = "pthreads" ; then
                lac_CFLAGS="$lac_CFLAGS -lmtmpi"
                lac_CXXFLAGS="$lac_CXXFLAGS -lmtmpi"
            fi
            LAC_PROG_CC_GNU($lac_cv_CC, ,
                [lac_CFLAGS="$lac_64bit_flag -Ae -D_HPUX_SOURCE $lac_CFLAGS"
                 lac_LDFLAGS="$lac_64bit_flag -Ae $lac_LDFLAGS"])
            LAC_PROG_CC_GNU($lac_cv_CXX, ,
                [lac_CXXFLAGS="$lac_64bit_flag -Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
        fi
        ;;
    *-hp-hpux10*--no )
	if test "$lac_mpi" != "yes" ; then
	    dnl AC_PATH_PROGS(lac_cv_CC, $CC cc gcc)
	    if test "$GLOBUS_CC" = "gcc"; then
	        AC_PATH_PROGS(lac_cv_CC, $CC gcc)
	    else
	        AC_PATH_PROGS(lac_cv_CC, $CC cc)
	    fi
	    AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC c++ g++ gcc)
	    AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
	    AC_PATH_PROGS(lac_cv_CC, $F90 f90)
	else
	    dnl AC_PATH_PROGS(lac_cv_CC, $CC mpicc)
	    if test "$GLOBUS_CC" = "gcc"; then
	        lac_cv_CC=""
	    else
	        AC_PATH_PROGS(lac_cv_CC, $CC mpicc)
	    fi
	    AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
	    AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
	    AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
	fi
	CC="$lac_cv_CC"
        LAC_PROG_CC_GNU($lac_cv_CC, ,
            [lac_CFLAGS="-Ae -D_HPUX_SOURCE $lac_CFLAGS"])
        LAC_PROG_CC_GNU($lac_cv_CXX, ,
            [lac_CXXFLAGS="-Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
        ;;
    *-hp-hpux10* )
	if test "$GLOBUS_CC" = "gcc"; then
	    AC_PATH_PROGS(lac_cv_CC, $CC gcc)
	else
	    AC_PATH_PROGS(lac_cv_CC, $CC cc)
	fi
	CC="$lac_cv_CC"
	LAC_PROG_CC_GNU($lac_cv_CC, ,
		[lac_CFLAGS="-Ae -D_HPUX_SOURCE $lac_CFLAGS"])
	AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
	LAC_PROG_CC_GNU($lac_cv_CXX, ,
		[lac_CXXFLAGS="-Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
	if test "$1" = "pthreads" ; then
	    lac_CFLAGS="$lac_CFLAGS -I/usr/include/reentrant"
	    lac_CXXFLAGS="$lac_CXXFLAGS -I/usr/include/reentrant"
	fi
        AC_PATH_PROGS(lac_cv_F77, $F77 f77)
	AC_PATH_PROGS(lac_cv_F90, $F90 f90)
	;;
    mips-sgi-irix6* )

        case $lac_cv_build_64bit in
            yes )  lac_64bit_flag="-64" ;;
            -*  )  lac_64bit_flag="$lac_cv_build_64bit" ;;
            *   )  lac_64bit_flag="-n32" ;;
        esac

	dnl AC_PATH_PROGS(lac_cv_CC, $CC cc gcc)

	if test "$GLOBUS_CC" = "gcc"; then
	    AC_PATH_PROGS(lac_cv_CC, $CC gcc)
	else
	    AC_PATH_PROGS(lac_cv_CC, $CC cc)
	fi
	CC="$lac_cv_CC"
	LAC_CHECK_CFLAGS($lac_cv_CC,[$lac_64bit_flag $lac_CFLAGS],
		[lac_CFLAGS="$lac_64bit_flag $lac_CFLAGS"
		 lac_LDFLAGS="$lac_64bit_flag $lac_LDFLAGS"])

	LAC_CHECK_CFLAGS($lac_cv_CC,[-woff 1048 $lac_CFLAGS],
		[lac_CFLAGS="-woff 1048 $lac_CFLAGS"])

	LAC_CHECK_LDFLAGS($lac_cv_CC,
		[$lac_CFLAGS],[-Wl,-woff,84 $lac_LDFLAGS],
		[lac_LDFLAGS="-Wl,-woff,84 $lac_LDFLAGS"])

	AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
	LAC_PROG_CC_GNU($lac_cv_CXX, ,
		[lac_CXXFLAGS="$lac_64bit_flag $lac_CXXFLAGS"])
	LAC_CHECK_CFLAGS($lac_cv_CXX, [-woff 1048 $lac_CXXFLAGS],
		[lac_CXXFLAGS="-woff 1048 $lac_CXXFLAGS"])

        dnl RANLIB is more or less defunct on SIG IRIX6.
        dnl Don't set RANLIB for since if its present its
	dnl probable gnu and is incompatible
        dnl     This fixes the reported problem on  modi4.ncsa.uiuc.edu
	AC_CACHE_VAL(lac_cv_RANLIB, lac_cv_RANLIB="true")

        if test "$lac_mpi" = "yes" ; then
            lac_LIBS="$lac_LIBS -lmpi"
        fi

        AC_PATH_PROGS(lac_cv_F77, $F77 f77 f77)
	AC_PATH_PROGS(lac_cv_F90, $F90 f90)
	lac_F77FLAGS="$lac_64bit_flag $lac_F77FLAGS"
	lac_F90FLAGS="$lac_64bit_flag $lac_F90FLAGS"
      ;;
    *-ibm-aix*--pthreads )
        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
	if test "$lac_mpl" != "yes" -a "$lac_mpi" != "yes" ; then
	    if test "$GLOBUS_CC" = "gcc"; then
	        AC_PATH_PROGS(lac_cv_CC, $CC gcc)
	    else
	        AC_PATH_PROGS(lac_cv_CC, $CC xlc_r)
	    fi
	    AC_PATH_PROGS(lac_cv_CXX, $CXX xlC_r)
	    AC_PATH_PROGS(lac_cv_F77, $F77 xlf_r)
	    AC_PATH_PROGS(lac_cv_F90, $F90 xlf90_r)
	    if test "$lac_cv_F90" = "xlf_r" ; then
		lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
	    fi
	else
	    if test "$GLOBUS_CC" = "gcc"; then
	        lac_cv_CC=""
	    else
	        AC_PATH_PROGS(lac_cv_CC, $CC mpcc_r)
	    fi
	    AC_PATH_PROGS(lac_cv_CXX, $CXX mpCC_r)
	    AC_PATH_PROGS(lac_cv_F77, $F77 mpxlf_r)
	    AC_PATH_PROGS(lac_cv_F90, $F90 mpxlf90_r)
	    if test "$lac_cv_F90" = "mpxlf_r" ; then
		lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
	    fi
	fi

	CC="$lac_cv_CC"	
        LAC_PROG_CC_GNU($lac_cv_CC,
	    [],
	    [
                AC_PATH_PROGS(lac_cv_CPP, $CPP cpp,[],/usr/lib:$PATH)
	    ])

	lac_CFLAGS="-D_ALL_SOURCE $lac_CFLAGS"
	lac_CXXFLAGS="-D_ALL_SOURCE $lac_CXXFLAGS"
        if test "$lac_cv_debug" = "yes"; then
	   LAC_PROG_CC_GNU($lac_cv_CC,
	       [],
	       [
	    	lac_CFLAGS="-qfullpath $lac_CFLAGS"
	    	lac_CXXFLAGS="-qfullpath $lac_CXXFLAGS"
	       ])
	fi
      ;;
    *-ibm-aix*--no )
        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
	if test "$lac_mpl" != "yes" -a "$lac_mpi" != "yes" ; then
	    if test "$GLOBUS_CC" = "gcc"; then
	         AC_PATH_PROGS(lac_cv_CC, $CC gcc)
            else
	         AC_PATH_PROGS(lac_cv_CC, $CC xlc)
	    fi
	    AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC xlC c++ g++ gcc)
	    AC_PATH_PROGS(lac_cv_F77, $F77 xlf)
	    AC_PATH_PROGS(lac_cv_F90, $F90 xlf90)
	    if test "$lac_cv_F90" = "xlf" ; then
		lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
	    fi
	else
	    if test "$GLOBUS_CC" = "gcc"; then
	        lac_cv_CC=""
	    else
	        AC_PATH_PROGS(lac_cv_CC, $CC mpcc)
	    fi
	    AC_PATH_PROGS(lac_cv_CXX, $CXX mpCC)
	    AC_PATH_PROGS(lac_cv_F77, $F77 mpxlf)
	    AC_PATH_PROGS(lac_cv_F90, $F90 mpxlf90)
	    if test "$lac_cv_F90" = "mpxlf" ; then
		lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
	    fi
	fi
	CC="$lac_cv_CC"	
        LAC_PROG_CC_GNU($lac_cv_CC,
	    [],
	    [
                AC_PATH_PROGS(lac_cv_CPP, $CPP cpp,[],/usr/lib:$PATH)
	    ])

	lac_CFLAGS="-D_ALL_SOURCE $lac_CFLAGS"
	lac_CXXFLAGS="-D_ALL_SOURCE $lac_CXXFLAGS"
        if test "$lac_cv_debug" = "yes"; then
	   LAC_PROG_CC_GNU($lac_cv_CC,
	       [],
	       [
	    	lac_CFLAGS="-qfullpath $lac_CFLAGS"
	    	lac_CXXFLAGS="-qfullpath $lac_CXXFLAGS"
	       ])
	fi
      ;;
    *-dec-osf4* | *-dec-osf5* )
        if test "$lac_cv_build_64bit" = "no"; then
            AC_MSG_ERROR(32 bits not supported on this platform, use the 64 bit flavor instead)
            exit 1
        fi
	dnl AC_PATH_PROGS(lac_cv_CC, $CC cc gcc)
	if test "$GLOBUS_CC" = "gcc"; then
	     AC_PATH_PROGS(lac_cv_CC, $CC gcc)
        else
	     AC_PATH_PROGS(lac_cv_CC, $CC cc)
	fi
	CC="$lac_cv_CC"
	AC_PATH_PROGS(lac_cv_CXX, $CXX CC cxx c++ g++ gcc)
	if test "$1" = "pthreads" ; then
            LAC_PROG_CC_GNU($lac_cv_CC,
			[lac_LIBS="$lac_LIBS -lpthread"],
			[lac_CFLAGS="-pthread $lac_CFLAGS"
                         lac_CPPFLAGS="-pthread $lac_CPPFLAGS"])
	    LAC_PROG_CC_GNU($lac_cv_CXX,
			[lac_LIBS="$lac_LIBS -lpthread"],
			[lac_CXXFLAGS="-pthread $lac_CXXFLAGS"])
	fi
        lac_CFLAGS="-D_OSF_SOURCE $lac_CFLAGS"
        lac_CXXFLAGS="-D_OSF_SOURCE $lac_CXXFLAGS"
	AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
	AC_PATH_PROGS(lac_cv_F90, $F90 f90)
      ;;
    alpha-cray-unicosmk* )
	dnl Cray T3E
        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
	dnl AC_PATH_PROGS(lac_cv_CC, $CC cc)
	if test "$GLOBUS_CC" = "gcc"; then
	     AC_PATH_PROGS(lac_cv_CC, $CC gcc)
        else
	     AC_PATH_PROGS(lac_cv_CC, $CC cc)
	fi
	CC="$lac_cv_CC"
	AC_PATH_PROGS(lac_cv_CXX, $CXX CC)
	lac_CFLAGS="-Xm $lac_CFLAGS"
	lac_CXXFLAGS="-Xm $lac_CXXFLAGS"
	lac_LDFLAGS="-Xm $lac_LDFLAGS"
	AC_PATH_PROGS(lac_cv_F77, $F77 f77)
	AC_PATH_PROGS(lac_cv_F90, $F90 f90)
      ;;
    *linux*--pthreads )
        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
	dnl AC_PATH_PROGS(lac_cv_CC, $CC cc gcc)
	if test "$GLOBUS_CC" = "gcc"; then
	     AC_PATH_PROGS(lac_cv_CC, $CC gcc)
        else
	     AC_PATH_PROGS(lac_cv_CC, $CC cc)
	fi
	CC="$lac_cv_CC"
	AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
	AC_PATH_PROGS(lac_cv_F77, $F77 f77)
	AC_PATH_PROGS(lac_cv_F90, $F90 f90)
      ;;
    * )
        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
	dnl AC_PATH_PROGS(lac_cv_CC, $CC cc gcc)
	if test "$GLOBUS_CC" = "gcc"; then
	     AC_PATH_PROGS(lac_cv_CC, $CC gcc)
        else
	     AC_PATH_PROGS(lac_cv_CC, $CC cc)
	fi
	CC="$lac_cv_CC"
	AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++  g++ gcc)
	AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
	AC_PATH_PROGS(lac_cv_F90, $F90 f90)
      ;;
esac

if test "$1" != "no" ; then
    lac_CFLAGS="$lac_CFLAGS $lac_cv_threads_CFLAGS"
    lac_CXXFLAGS="$lac_CXXFLAGS $lac_cv_threads_CXXFLAGS"
    lac_LDFLAGS="$lac_LDFLAGS $lac_cv_threads_LDFLAGS"
    lac_LIBS="$lac_LIBS $lac_cv_threads_LIBS"
fi

if test -z "$lac_cv_CC" ; then
    AC_MSG_ERROR([no acceptable C compiler found in \$PATH])
fi
if test "$lac_cv_debug" = "yes"; then
    lac_CFLAGS="-g $lac_CFLAGS"
    lac_CXXFLAGS="-g $lac_CXXFLAGS"
    AC_DEFINE(BUILD_DEBUG)
else
    if test -z "$lac_cflags_opt" ; then
	lac_CFLAGS="-O $lac_CFLAGS"
    else
	lac_CFLAGS="$lac_cflags_opt $lac_CFLAGS"
    fi
    if test -z "$lac_cxxflags_opt" ; then
	lac_CXXFLAGS="-O $lac_CXXFLAGS"
    else
	lac_CXXFLAGS="$lac_cxxflags_opt $lac_CXXFLAGS"
    fi
fi

GLOBUS_DEBUG="$lac_cv_debug"
AC_SUBST(GLOBUS_DEBUG)

LAC_PROG_CC_GNU([$lac_cv_CC],
[
    lac_CFLAGS="$lac_CFLAGS -Wall"
],
[])

AC_CACHE_CHECK("C flags", lac_cv_CFLAGS, lac_cv_CFLAGS=$lac_CFLAGS)
AC_CACHE_CHECK("C++ flags", lac_cv_CXXFLAGS, lac_cv_CXXFLAGS=$lac_CXXFLAGS)
AC_CACHE_CHECK("linker flags", lac_cv_LDFLAGS, lac_cv_LDFLAGS=$lac_LDFLAGS)
AC_CACHE_CHECK("required libraries", lac_cv_LIBS, lac_cv_LIBS=$lac_LIBS)
AC_CACHE_CHECK("C Preprocessor", lac_cv_CPP, lac_cv_CPP="$lac_cv_CC -E")
AC_CACHE_CHECK("C Preprocessor flags", lac_cv_CPPFLAGS,lac_cv_CPPFLAGS=$lac_CPPFLAGS)
AC_CACHE_CHECK("C++ Preprocessor", lac_cv_CXXCPP, lac_cv_CXXCPP="$lac_cv_CXX -E")
AC_CACHE_CHECK("F77 flags", lac_cv_F77FLAGS, lac_cv_F77FLAGS="$lac_F77FLAGS")
AC_CACHE_CHECK("F90 flags", lac_cv_F90FLAGS, lac_cv_F90FLAGS="$lac_F90FLAGS")

dnl If a system did not set the LD then set it using CC
if test -z "$lac_cv_LD" ; then
   lac_cv_LD="$lac_cv_CC"
fi

CC="$lac_cv_CC"
LD="$lac_cv_LD"
CFLAGS="$lac_cv_CFLAGS"
AC_PROG_CC
CROSS="$cross_compiling"
AC_SUBST(CROSS)
AC_SUBST(cross_compiling)
dnl Note that if RANLIB is set appropriately
dnl This line should do nothing
AC_PATH_PROGS(lac_cv_RANLIB, $lac_cv_RANLIB ranlib true, true)

AC_PATH_PROGS(lac_cv_AR, [ar], ar)
AC_CACHE_VAL(lac_cv_ARFLAGS, lac_cv_ARFLAGS="ruv")
])

dnl LAC_PROG_CC_GNU(COMPILER, ACTION-IF-TRUE, ACTION-IF-FALSE)
AC_DEFUN(LAC_PROG_CC_GNU,
[
AC_PROG_CC_GNU

if test "$ac_cv_prog_gcc" = "yes" ; then
    :
    $2
else
    :
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
