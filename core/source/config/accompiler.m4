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
dnl   OBJECT_MODE
dnl   NM
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
dnl   lac_cv_OBJECT_MODE
dnl   lac_cv_NM
dnl
dnl

dnl LAC_COMPILERS_ARGS()
AC_DEFUN([LAC_COMPILERS_ARGS],
[
AC_ARG_WITH(threads,
        [  --with-threads=TYPE          build target with threads],
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
  <<--enable-insure[=PATH]      use Insure++ [default=insure]>>,
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

AC_DEFUN([LAC_COMPILERS],
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
LAC_SUBSTITUTE_COMPILER_VAR(OBJECT_MODE)
LAC_SUBSTITUTE_COMPILER_VAR(NM)
])

dnl LAC_SUBSTITUTE_COMPILER_VAR
AC_DEFUN([LAC_SUBSTITUTE_COMPILER_VAR],
[
    if test -n "[$]lac_cv_$1"; then
        $1=[$]lac_cv_$1
        AC_SUBST($1)
    fi
])

dnl LAC_COMPILERS_SET(THREAD-TYPE)
AC_DEFUN([LAC_COMPILERS_SET],
[
echo "checking for compilers..."
LAC_COMPILERS_SET_ALL_VARS($1)
])


dnl LAC_COMPILERS_SET_ALL_VARS(THREAD-TYPE)
AC_DEFUN([LAC_COMPILERS_SET_ALL_VARS],
[
lac_CFLAGS="$CFLAGS "
lac_CPPFLAGS="$CPPFLAGS -I$GLOBUS_LOCATION/include -I$GLOBUS_LOCATION/include/$globus_cv_flavor"
lac_CXXFLAGS="$CXXFLAGS "
lac_LDFLAGS="$LDFLAGS -L$GLOBUS_LOCATION/lib"
lac_LIBS="$LIBS "
lac_F77FLAGS="$F77FLAGS "
lac_F90FLAGS="$F90FLAGS "
lac_NM=""
lac_OBJECT_MODE=""
unset lac_cflags_opt
unset lac_cxxflags_opt

if test -z "$GLOBUS_CC" ; then
    if echo $globus_cv_flavor | grep gcc > /dev/null 2>&1 ; then
        GLOBUS_CC="gcc"
    else
        GLOBUS_CC="unknown"
    fi
fi

case ${host}--$1 in
    *solaris2*)
        dnl On Solaris, avoid the pre-ansi BSD compatibility compiler

        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC c++ g++ gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc $lac_cv_CC)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC)
            fi
            
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"

        if test "$CC" = "/usr/ucb/cc" ; then
            AC_MSG_ERROR([The compiler found was /usr/ucb/cc (not supported)])
            exit 1            
        fi

        LAC_PROG_CC_GNU($lac_cv_CC,
                        [if test "$1" = "solaristhreads" -o "$1" = "pthreads" ; then
                                lac_CFLAGS="-D_REENTRANT $lac_CFLAGS"
                         fi],
                        [if test "$1" = "solaristhreads" -o "$1" = "pthreads" ; then
                                lac_CFLAGS="-mt $lac_CFLAGS"
                         fi
                         lac_cflags_opt="-xO3"])

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

        if test "$lac_cv_build_64bit" = "yes"; then
            lac_CFLAGS="$lac_CFLAGS -xcode=pic32 -xarch=v9"
        fi

        ;;
    *ia64-*linux* )
        if test "$lac_cv_build_64bit" = "no"; then
            AC_MSG_ERROR(32 bits not supported on this platform)
            exit 1
        fi
        
        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)            
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
                AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
                AC_PATH_PROGS(lac_cv_F90, $F90 f90)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC icc ecc cc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC icc ecc CC c++)
                AC_PATH_PROGS(lac_cv_F77, $F77 ifort efc f77)
                AC_PATH_PROGS(lac_cv_F90, $F90 ifort efc f90)
                # should really check that we really are dealing 
                # with intel compiler 
                lac_CFLAGS="$lac_CFLAGS -no-gcc -restrict"
            fi
        fi
        CC="$lac_cv_CC"
        ;;
    *x86_64-*linux* )
        if test "$lac_cv_build_64bit" = "no"; then
            AC_MSG_ERROR(32 bits not supported on this platform)
            exit 1
        fi

        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
                AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
                AC_PATH_PROGS(lac_cv_F90, $F90 f90)
            else
                AC_MSG_ERROR(vendorcc not supported on this platform)
            fi
        fi
        CC="$lac_cv_CC"
	lac_CFLAGS="$lac_CFLAGS -m64"
        ;;
    alpha*linux* )
        if test "$lac_cv_build_64bit" = "no"; then
            AC_MSG_ERROR(32 bits not supported on this platform)
            exit 1
        fi
        
        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC ccc cc)
            fi
            
            AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"
        ;;
    hppa1*-hp-hpux11* )
        
        dnl No 64bit on this platform
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
        
        if test "$GLOBUS_CC" = "mpicc"; then
            dnl for --with-threads=pthreads and --with-mpi, we need
            dnl to compile with an additional -lmtmpi, even when not
            dnl linking
            
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
            
            if test "$1" = "pthreads" ; then
                lac_CFLAGS="$lac_CFLAGS -lmtmpi"
                lac_CXXFLAGS="$lac_CXXFLAGS -lmtmpi"
            fi
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC c++ g++ gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC aCC)
            fi
            
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"

        LAC_PROG_CC_GNU($lac_cv_CC,[],
            [lac_CFLAGS="+DAportable -Ae -D_HPUX_SOURCE $lac_CFLAGS"
             lac_LDFLAGS="+DAportable -Ae $lac_LDFLAGS"])
        LAC_PROG_CC_GNU($lac_cv_CXX,[],
            [lac_CXXFLAGS="+DAportable -Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
        ;;
    *-hp-hpux11* )

        case $lac_cv_build_64bit in
            yes )
                lac_64bit_flag="+DA2.0W"
                ;;

            +* )  
                lac_64bit_flag="$lac_cv_build_64bit"
                ;;

            * )  
                lac_64bit_flag="+DA2.0"
                ;;
        esac

        if test "$GLOBUS_CC" = "mpicc"; then
            dnl for --with-threads=pthreads and --with-mpi, we need
            dnl to compile with an additional -lmtmpi, even when not
            dnl linking
            
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
            
            if test "$1" = "pthreads" ; then
                lac_CFLAGS="$lac_CFLAGS -lmtmpi"
                lac_CXXFLAGS="$lac_CXXFLAGS -lmtmpi"
            fi
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC c++ g++ gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC aCC)
            fi
            
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"

        LAC_PROG_CC_GNU($lac_cv_CC,[],
            [lac_CFLAGS="$lac_64bit_flag -Ae -D_HPUX_SOURCE $lac_CFLAGS"
             lac_LDFLAGS="$lac_64bit_flag -Ae $lac_LDFLAGS"])
        LAC_PROG_CC_GNU($lac_cv_CXX,[],
            [lac_CXXFLAGS="$lac_64bit_flag -Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
        ;;
    *-hp-hpux10*--no )
    
        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC c++ g++ gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC aCC)
            fi
            
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"
        LAC_PROG_CC_GNU($lac_cv_CC, ,
            [lac_CFLAGS="-Ae -D_HPUX_SOURCE $lac_CFLAGS"])
        LAC_PROG_CC_GNU($lac_cv_CXX, ,
            [lac_CXXFLAGS="-Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
        ;;
    *-hp-hpux10* )
        
        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC c++ g++ gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC aCC c++ g++ gcc)
            fi
            
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"
        LAC_PROG_CC_GNU($lac_cv_CC, ,
                [lac_CFLAGS="-Ae -D_HPUX_SOURCE $lac_CFLAGS"])
        LAC_PROG_CC_GNU($lac_cv_CXX, ,
                [lac_CXXFLAGS="-Ae -D_HPUX_SOURCE $lac_CXXFLAGS"])
        if test "$1" = "pthreads" ; then
            lac_CFLAGS="$lac_CFLAGS -I/usr/include/reentrant"
            lac_CXXFLAGS="$lac_CXXFLAGS -I/usr/include/reentrant"
        fi
        ;;
    mips-sgi-irix6* )
        lac_cv_CC=
        
        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        fi
        
        if test "X$lac_cv_CC" = "X" ; then
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc)
            fi
            
            AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
            
            if test "$build_arg_mpi" = "yes" -a "$mpi_own_lib" != "yes"; then
                lac_LIBS="$lac_LIBS -lmpi"
            fi
        fi
        CC="$lac_cv_CC"
        
        LAC_PROG_CC_GNU([$lac_cv_CC],
                [
                case $lac_cv_build_64bit in
                        yes )  lac_64bit_flag="-mabi=64" ;;
                        -*  )  lac_64bit_flag="$lac_cv_build_64bit" ;;
                        *   )  lac_64bit_flag="-mabi=n32" ;;
                esac
                ],
                [
                case $lac_cv_build_64bit in
                        yes )  lac_64bit_flag="-64" ;;
                        -*  )  lac_64bit_flag="$lac_cv_build_64bit" ;;
                        *   )  lac_64bit_flag="-n32" ;;
                esac
                ])      

        LAC_CHECK_CFLAGS($lac_cv_CC,[$lac_64bit_flag $lac_CFLAGS],
                [lac_CFLAGS="$lac_64bit_flag $lac_CFLAGS"
                 lac_LDFLAGS="$lac_64bit_flag $lac_LDFLAGS"])

        LAC_CHECK_CFLAGS($lac_cv_CC,[-woff 1048 $lac_CFLAGS],
                [lac_CFLAGS="-woff 1048 $lac_CFLAGS"])

        LAC_CHECK_LDFLAGS($lac_cv_CC,
                [$lac_CFLAGS],[-Wl,-woff,84 $lac_LDFLAGS],
                [lac_LDFLAGS="-Wl,-woff,84 $lac_LDFLAGS"])

        LAC_PROG_CC_GNU($lac_cv_CXX, ,
                [lac_CXXFLAGS="$lac_64bit_flag $lac_CXXFLAGS"])
        LAC_CHECK_CFLAGS($lac_cv_CXX, [-woff 1048 $lac_CXXFLAGS],
                [lac_CXXFLAGS="-woff 1048 $lac_CXXFLAGS"])

        dnl RANLIB is more or less defunct on SIG IRIX6.
        dnl Don't set RANLIB for since if its present its
        dnl probable gnu and is incompatible
        dnl     This fixes the reported problem on  modi4.ncsa.uiuc.edu
        AC_CACHE_VAL(lac_cv_RANLIB, lac_cv_RANLIB="true")

        lac_F77FLAGS="$lac_64bit_flag $lac_F77FLAGS"
        lac_F90FLAGS="$lac_64bit_flag $lac_F90FLAGS"
      ;;
    *-ibm-aix*--pthreads )

        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpcc_r mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpCC_r mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpxlf_r mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpxlf90_r mpif90)
            if test "$lac_cv_F90" = "mpxlf_r" ; then
                lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
            fi
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_MSG_ERROR(GCC not supported on this platform)
                exit 1
            fi

            AC_PATH_PROGS(lac_cv_CC, $CC xlc_r)
            if test "x$lac_cv_CC" != "x"; then
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_CC="$lac_cv_CC -q64"
                else
                    lac_cv_CC="$lac_cv_CC -q32"
                fi
            fi

            AC_PATH_PROGS(lac_cv_CXX, $CXX xlC_r)
            if test "x$lac_cv_CXX" != "x"; then
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_CXX="$lac_cv_CXX -q64"
                else
                    lac_cv_CXX="$lac_cv_CXX -q32"
                fi
            fi
            AC_PATH_PROGS(lac_cv_F77, $F77 xlf_r)
            if test "x$lac_cv_F77" != "x"; then
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_F77="$lac_cv_F77 -q64"
                else
                    lac_cv_F77="$lac_cv_F77 -q32"
                fi
            fi

            AC_PATH_PROGS(lac_cv_F90, $F90 xlf90_r)
            if test "$lac_cv_F90" = "xlf_r" ; then
                lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
            fi
            if test "x$lac_cv_F90" != "x"; then
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_F90="$lac_cv_F90 -q64"
                else
                    lac_cv_F90="$lac_cv_F90 -q32"
                fi
            fi
        fi
        CC="$lac_cv_CC"
        LAC_PROG_CC_GNU($lac_cv_CC,
            [],
            [
                AC_PATH_PROGS(lac_cv_CPP, $CPP cpp,[],/usr/lib:$PATH)
                dnl other parts of the toolchain needs to know about 32/64 bits
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_AR="/usr/bin/ar -X64"
                    lac_ARFLAGS="-X64 $lac_ARFLAGS"
                    lac_CFLAGS="-q64 -D_ALL_SOURCE $lac_CFLAGS"
                    lac_CXXFLAGS="-q64 -D_ALL_SOURCE $lac_CXXFLAGS"
                    lac_LDFLAGS="-b64 $lac_LDFLAGS"
                    lac_NM="/usr/bin/nm -X64 -B"
                    lac_OBJECT_MODE="64"
                else
                    lac_cv_AR="/usr/bin/ar -X32"
                    lac_ARFLAGS="-X32 $lac_ARFLAGS"
                    lac_CFLAGS="-q32 -D_ALL_SOURCE $lac_CFLAGS"
                    lac_CXXFLAGS="-q32 -D_ALL_SOURCE $lac_CXXFLAGS"
                    lac_LDFLAGS="-b32 $lac_LDFLAGS"
                    lac_NM="/usr/bin/nm -X32 -B"
                    lac_OBJECT_MODE="32"
                fi
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

        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpcc mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpCC mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpxlf mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpxlf90 mpif90)
            if test "$lac_cv_F90" = "mpxlf" ; then
                lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
            fi
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_MSG_ERROR(GCC not supported on this platform)
                exit 1
            fi

            dnl Note: we are using the reentrant compilers (_r)
            dnl even for non-threaded flavors. It looks like
            dnl this is needed when linking with some system
            dnl libraries.

            AC_PATH_PROGS(lac_cv_CC, $CC xlc_r)
            if test "x$lac_cv_CC" != "x"; then
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_CC="$lac_cv_CC -q64"
                else
                    lac_cv_CC="$lac_cv_CC -q32"
                fi
            fi

            AC_PATH_PROGS(lac_cv_CXX, $CXX xlC_r)
            if test "x$lac_cv_CXX" != "x"; then
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_CXX="$lac_cv_CXX -q64"
                else
                    lac_cv_CXX="$lac_cv_CXX -q32"
                fi
            fi

            AC_PATH_PROGS(lac_cv_F77, $F77 xlf_r)
            if test "x$lac_cv_F77" != "x"; then
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_F77="$lac_cv_F77 -q64"
                else
                    lac_cv_F77="$lac_cv_F77 -q32"
                fi
            fi

            AC_PATH_PROGS(lac_cv_F90, $F90 xlf90_r)
            if test "$lac_cv_F90" = "xlf_r" ; then
                lac_F90FLAGS="-qfree=f90 $lac_F90FLAGS"
            fi
            if test "x$lac_cv_F90" != "x"; then
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_F90="$lac_cv_F90 -q64"
                else
                    lac_cv_F90="$lac_cv_F90 -q32"
                fi
            fi
        fi

        CC="$lac_cv_CC"
        LAC_PROG_CC_GNU($lac_cv_CC,
            [],
            [
                AC_PATH_PROGS(lac_cv_CPP, $CPP cpp,[],/usr/lib:$PATH)
                dnl other parts of the toolchain needs to know about 32/64 bits
                if test "$lac_cv_build_64bit" = "yes"; then
                    lac_cv_AR="/usr/bin/ar -X64"
                    lac_ARFLAGS="-X64 $lac_ARFLAGS"
                    lac_CFLAGS="-q64 -D_ALL_SOURCE $lac_CFLAGS"
                    lac_CXXFLAGS="-q64 -D_ALL_SOURCE $lac_CXXFLAGS"
                    lac_LDFLAGS="-b64 $lac_LDFLAGS"
                    lac_NM="/usr/bin/nm -X64 -B"
                    lac_OBJECT_MODE="64"
                else
                    lac_cv_AR="/usr/bin/ar -X32"
                    lac_ARFLAGS="-X32 $lac_ARFLAGS"
                    lac_CFLAGS="-q32 -D_ALL_SOURCE $lac_CFLAGS"
                    lac_CXXFLAGS="-q32 -D_ALL_SOURCE $lac_CXXFLAGS"
                    lac_LDFLAGS="-b32 $lac_LDFLAGS"
                    lac_NM="/usr/bin/nm -X32 -B"
                    lac_OBJECT_MODE="32"
                fi
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
        
        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX CC c++ g++ gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX CC cxx)
            fi
            
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"
        
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
      ;;
    alpha-cray-unicosmk* )
        dnl Cray T3E
        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
        
        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc)
            fi
            
            AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC)
            AC_PATH_PROGS(lac_cv_F77, $F77 f77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"
        lac_CFLAGS="-Xm $lac_CFLAGS"
        lac_CXXFLAGS="-Xm $lac_CXXFLAGS"
        lac_LDFLAGS="-Xm $lac_LDFLAGS"
      ;;
    *linux* )
        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
        
        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC g++ gcc CC c++)
                AC_PATH_PROGS(lac_cv_F77, $F77 g77 f77)
                AC_PATH_PROGS(lac_cv_F90, $F90 f90)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC icc cc)
                AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC icc CC c++)
                AC_PATH_PROGS(lac_cv_F77, $F77 ifort ifc f77)
                AC_PATH_PROGS(lac_cv_F90, $F90 ifort ifc f90)
                # should really check that we really are dealing 
                # with intel compiler 
                lac_CFLAGS="$lac_CFLAGS -no-gcc"                
            fi
        fi
        CC="$lac_cv_CC"
      ;;
    *-darwin* )
        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
        
        lac_CPPFLAGS="$lac_CPPFLAGS -I/sw/include"
        lac_LDFLAGS="$lac_LDFLAGS -L/sw/lib"

        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
        	lac_CFLAGS="$lac_CFLAGS -fno-common"
        	lac_CPPFLAGS="$lac_CPPFLAGS -no-cpp-precomp"
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc)
            fi
            
            AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"
	
	# for now assume fink is installed in /sw

        lac_CFLAGS="$lac_CFLAGS -I/sw/include -DBIND_8_COMPAT"
        lac_CXXFLAGS="$lac_CXXFLAGS -I/sw/include"
        lac_CPPFLAGS="$lac_CPPFLAGS -I/sw/include"
        lac_LDFLAGS="$lac_LDFLAGS -L/sw/lib"
      ;;
    * )
        dnl No 64bit support yet
        if test "$lac_cv_build_64bit" = "yes"; then
                AC_MSG_ERROR(64 bits not supported on this platform)
                exit 1
        fi
        
        if test "$GLOBUS_CC" = "mpicc"; then
            AC_PATH_PROGS(lac_cv_CC,  $CC  mpicc)
            AC_PATH_PROGS(lac_cv_CXX, $CXX mpiCC)
            AC_PATH_PROGS(lac_cv_F77, $F77 mpif77)
            AC_PATH_PROGS(lac_cv_F90, $F90 mpif90)
        else
            if test "$GLOBUS_CC" = "gcc"; then
                AC_PATH_PROGS(lac_cv_CC, $CC gcc)
            else
                AC_PATH_PROGS(lac_cv_CC, $CC cc)
            fi
            
            AC_PATH_PROGS(lac_cv_CXX, $CXX $CCC CC c++ g++ gcc)
            AC_PATH_PROGS(lac_cv_F77, $F77 f77 g77)
            AC_PATH_PROGS(lac_cv_F90, $F90 f90)
        fi
        CC="$lac_cv_CC"
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

LAC_PROG_CC_GNU([$lac_cv_CC $lac_CFLAGS],
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

dnl Only set AR if it has not been explicitly set earlier
AR="$lac_cv_AR"
if test "x$lac_cv_AR" = "x"; then
    AC_PATH_PROGS(lac_cv_AR, [ar], ar)
fi
AC_CACHE_VAL(lac_cv_ARFLAGS, lac_cv_ARFLAGS="ruv")
NM="$lac_NM"
OBJECT_MODE="$lac_OBJECT_MODE"
])

dnl LAC_PROG_CC_GNU(COMPILER, ACTION-IF-TRUE, ACTION-IF-FALSE)
AC_DEFUN([LAC_PROG_CC_GNU],
[
if test "X$1" != "X" ; then
	_SAVED_CC="$CC"
	CC="$1"
	_AC_LANG_COMPILER_GNU
	CC="$_SAVED_CC"
else
	_AC_LANG_COMPILER_GNU
fi

if test "$ac_cv_prog_gcc" = "yes" ; then
    :
    $2
else
    :
    $3
fi])


dnl LAC_CHECK_CC_PROTOTYPES(true-action, false-action)
dnl Check that the compiler accepts ANSI prototypes.
AC_DEFUN([LAC_CHECK_CC_PROTOTYPES],[
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
AC_DEFUN([LAC_CHECK_CFLAGS],[
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
AC_DEFUN([LAC_CHECK_LDFLAGS],[
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
