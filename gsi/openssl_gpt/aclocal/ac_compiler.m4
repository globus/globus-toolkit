dnl
dnl ac_compiler.m4
dnl
dnl
dnl Set up compiler flags
dnl
dnl


dnl LAC_COMPILER_ARGS()

AC_DEFUN([LAC_COMPILER_ARGS],
[
    AC_ARG_WITH([dso],
        [AC_HELP_STRING([--without-dso],
        [Disable DSO module])],
        [],
        [])

    if test "x$GPT_LINKTYPE" = "xstatic"; then
        with_dso=no
    fi

# Check whether --with-dso or --without-dso was given.

    if test "${with_dso+set}" != "set"; then
        with_dso="yes"
    fi

])

dnl LAC_COMPILER()

AC_DEFUN([LAC_COMPILER],
[
    AC_REQUIRE([AC_CANONICAL_HOST])
    AC_REQUIRE([LAC_CPU])
    AC_REQUIRE([AC_PROG_CC])
    LAC_COMPILER_ARGS

    # defaults:

    lac_CFLAGS="$CFLAGS -DOPENSSL_OTHER_DEFINES=1"
    lac_DSO_DLFCN=""
    lac_HAVE_DLFCN_H=""
    lac_OPENSSL_THREADS=""    

    if test "$GLOBUS_DEBUG" != "yes"; then
        LAC_COMPILER_SET_OPTIMIZATIONS
    fi

    LAC_COMPILER_SET_DEFINES
    LAC_SUBSTITUTE_VAR(CFLAGS)
    LAC_DEFINE_VAR(DSO_DLFCN)
    LAC_DEFINE_VAR(HAVE_DLFCN_H)
    LAC_DEFINE_VAR(OPENSSL_THREADS)
])


dnl LAC_COMPILER_SET_OPTIMIZATIONS
AC_DEFUN([LAC_COMPILER_SET_OPTIMIZATIONS],
[
    case ${host} in
        *solaris*)
            case ${lac_cv_CPU} in
                *sun4m*|*sun4d*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -mv8 -O3 -fomit-frame-pointer -Wall"
                    else
                        lac_CFLAGS="$lac_CFLAGS -xarch=v8 -xO5 -xstrconst -xdepend -Xa"
                    fi
                ;;
                *sun4u*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -mcpu=ultrasparc -O3 -fomit-frame-pointer -Wall"
                    else
                        case ${GLOBUS_FLAVOR_NAME} in
                            *64* )
                                lac_CFLAGS="-xtarget=ultra -xO5 -xstrconst -xdepend -Xa $lac_CFLAGS"
                            ;;
                            *32* )
                                lac_CFLAGS="-xarch=v8 -xO5 -xstrconst -xdepend -Xa $lac_CFLAGS"
                            ;;
                        esac
                    fi
                ;;
                *x86*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -O3 -fomit-frame-pointer -mcpu=i486 -Wall"
                    else
                        lac_CFLAGS="$lac_CFLAGS -fast -O -Xa"
                    fi
                ;;
            esac
        ;;   
        *linux*)
            case ${lac_cv_CPU} in
                *sun4m*|*sun4d*)
                    # gcc
                    lac_CFLAGS="$lac_CFLAGS -mv8 -O3 -fomit-frame-pointer -Wall"
                ;;
                *sun4u*)
                    # gcc
                    case ${GLOBUS_FLAVOR_NAME} in
                        *64* )
                            lac_CFLAGS="$lac_CFLAGS -mcpu=ultrasparc -O3 -fomit-frame-pointer -Wall"
                        ;;
                        *32* )
                            #lac_CFLAGS="$lac_CFLAGS -mcpu=ultrasparc -O3 -fomit-frame-pointer -Wall -Wa,-Av8plus -DBN_DIV2W"
                            lac_CFLAGS="$lac_CFLAGS -mcpu=ultrasparc -O3 -fomit-frame-pointer -Wall"
                        ;;
                    esac
                ;;
                *x86_64*)
                    # gcc
                    lac_CFLAGS="$lac_CFLAGS -O3 -Wall"
                ;;
                *x86*)
                    # gcc
                    lac_CFLAGS="$lac_CFLAGS -O3 -fomit-frame-pointer -mcpu=i486 -Wall"
                ;;
                *ia64*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -O3 -fomit-frame-pointer -Wall"
                    else
                        lac_CFLAGS="$lac_CFLAGS -O2 -Wall"
                    fi
                ;;
                *alpha*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -O3"
                    else
                        lac_CFLAGS="$lac_CFLAGS -fast -readonly_strings"
                    fi
                ;;
            esac
        ;;
        *irix6*)
            case ${lac_cv_CPU} in
                *mips3*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -mips3 -mmips-as -O3"
                    else
                        lac_CFLAGS="$lac_CFLAGS -mips3 -O2 -use_readonly_const"
                    fi
                ;;
                *mips4*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -mips4 -mmips-as -O3"
                    else
                        lac_CFLAGS="$lac_CFLAGS -mips4 -O2 -use_readonly_const"
                    fi
                ;;
            esac
        ;;
        *hpux*)
            if test "$GCC" = "yes"; then
                lac_CFLAGS="$lac_CFLAGS -O3"
            else
                lac_CFLAGS="$lac_CFLAGS +O3 +Optrs_strongly_typed +Olibcalls -Ae +ESlit"
            fi
        ;;
        *-ibm-aix*)
            if test "$GCC" = "yes"; then
                lac_CFLAGS="$lac_CFLAGS -O3 "
            else
                lac_CFLAGS="$lac_CFLAGS -O -qmaxmem=16384 -qfullpath"
            fi
        ;;
        *-dec-osf*)
            if test "$GCC" = "yes"; then
                lac_CFLAGS="$lac_CFLAGS -O3"
            else
                lac_CFLAGS="$lac_CFLAGS -std1 -tune host -fast -readonly_strings"
            fi
        ;;
        *-darwin*)
	    # assume gcc
       	    lac_CFLAGS="$lac_CFLAGS -O3"
        ;;
    esac
])

dnl LAC_COMPILER_SET_DEFINES
AC_DEFUN([LAC_COMPILER_SET_DEFINES],
[
    if test "$with_dso" = "yes"; then
        lac_CFLAGS="$lac_CFLAGS -DDSO_DLFCN -DHAVE_DLFCN_H"
        lac_DSO_DLFCN="1"
        lac_HAVE_DLFCN_H="1"
    fi

    if test ! "$GLOBUS_THREADS" = "none"; then
        lac_CFLAGS="$lac_CFLAGS -DOPENSSL_THREADS"
        lac_OPENSSL_THREADS="1"
    fi

    case ${host} in
        *solaris*)
            case ${lac_cv_CPU} in
                *sun4m*|*sun4d*)
                    lac_CFLAGS="-DB_ENDIAN"
                ;;
                *sun4u*)
                    lac_CFLAGS="$lac_CFLAGS -DB_ENDIAN -DOPENSSL_SYSNAME_ULTRASPARC"
                ;;
                *x86*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -DL_ENDIAN -DNO_INLINE_ASM"
                    fi
                ;;
            esac
        ;;   
        *linux*)
            case ${lac_cv_CPU} in
                *sun4m*|*sun4d*)
                    # gcc
                    lac_CFLAGS="$lac_CFLAGS -DB_ENDIAN -DTERMIO"
                ;;
                *sun4u*)
                    # gcc
                    case ${GLOBUS_FLAVOR_NAME} in
                        *64* )
                            lac_CFLAGS="$lac_CFLAGS -DB_ENDIAN -DTERMIO -DOPENSSL_SYSNAME_ULTRASPARC"
                        ;;
                        *32* )
                            lac_CFLAGS="$lac_CFLAGS -DB_ENDIAN -DTERMIO -DOPENSSL_SYSNAME_ULTRASPARC -DBN_DIV2W"
                        ;;
                    esac
                ;;
                *x86_64*)
                    # gcc
                    lac_CFLAGS="$lac_CFLAGS -DL_ENDIAN -DTERMIO -DMD32_REG_T=int"
                ;;
                *x86*|*ia64*|*alpha*)
                    # gcc
                    lac_CFLAGS="$lac_CFLAGS -DL_ENDIAN -DTERMIO"
                ;;
            esac
        ;;
        *irix6*)
            lac_CFLAGS="$lac_CFLAGS -DB_ENDIAN -DTERMIOS"
        ;;
        *hpux*)
            if test "$GCC" = "yes"; then
                lac_CFLAGS="$lac_CFLAGS -DB_ENDIAN"
            else
                lac_CFLAGS="$lac_CFLAGS -DB_ENDIAN -DMD32_XARRAY"
            fi
        ;;
        *-ibm-aix*)
            lac_CFLAGS="$lac_CFLAGS -DOPENSSL_SYSNAME_AIX -DB_ENDIAN"
        ;;
        *-darwin*)
            lac_CFLAGS="$lac_CFLAGS -D_DARWIN -DB_ENDIAN -DOPENSSL_SYSNAME_MACOSX"
        ;;
    esac
])







