dnl
dnl ac_compiler.m4
dnl
dnl
dnl Set up compiler flags
dnl
dnl


dnl LAC_COMPILER_ARGS()

AC_DEFUN(LAC_COMPILER_ARGS,
[
])

dnl LAC_COMPILER()

AC_DEFUN(LAC_COMPILER,
[
    AC_REQUIRE([AC_CANONICAL_HOST])
    AC_REQUIRE([LAC_CPU])
    AC_REQUIRE([AC_PROG_CC])
    LAC_COMPILER_ARGS
    LAC_COMPILER_SET
    LAC_SUBSTITUTE_VAR(CFLAGS)
    LAC_DEFINE_VAR(DSO_DLFCN)
    LAC_DEFINE_VAR(HAVE_DLFCN_H)
    LAC_DEFINE_VAR(THREADS)
])


dnl LAC_COMPILER_SET
AC_DEFUN(LAC_COMPILER_SET,
[
    # defaults:

    lac_CFLAGS="$CFLAGS -DDSO_DLFCN -DHAVE_DLFCN_H"
    lac_DSO_DLFCN="1"
    lac_HAVE_DLFCN_H="1"
    lac_THREADS=""

    if test ! "$GLOBUS_THREADS" = "none"; then
        lac_CFLAGS="$lac_CFLAGS -DTHREADS"
        lac_THREADS="1"
    fi

    case ${host} in
        *solaris*)
            case ${lac_cv_CPU} in
                *sun4m*|*sun4d*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -mv8 -O3 -fomit-frame-pointer -Wall -DB_ENDIAN -DBN_DIV2W"
                    else
                        lac_CFLAGS="$lac_CFLAGS -xarch=v8 -xO5 -xstrconst -xdepend -Xa -DB_ENDIAN -DBN_DIV2W"
                    fi
                ;;
                *sun4u*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -mcpu=ultrasparc -O3 -fomit-frame-pointer -Wall -DB_ENDIAN -DBN_DIV2W -DULTRASPARC"
                    else
                        lac_CFLAGS="$lac_CFLAGS -xtarget=ultra -xarch=v8plus -xO5 -xstrconst -xdepend -Xa -DB_ENDIAN -DBN_DIV2W -DULTRASPARC"
                    fi
                ;;
                *x86*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -O3 -fomit-frame-pointer -mcpu=i486 -Wall -DL_ENDIAN -DNO_INLINE_ASM"
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
                    lac_CFLAGS="$lac_CFLAGS -mv8 -DB_ENDIAN -DTERMIO -O3 -fomit-frame-pointer -Wall -DBN_DIV2W"
                ;;
                *sun4u*)
                    # gcc
                    lac_CFLAGS="$lac_CFLAGS -mcpu=ultrasparc -DB_ENDIAN -DTERMIO -O3 -fomit-frame-pointer -Wall -Wa,-Av8plus -DULTRASPARC -DBN_DIV2W"
                ;;
                *x86*)
                    # gcc
                    lac_CFLAGS="$lac_CFLAGS -DL_ENDIAN -DTERMIO -O3 -fomit-frame-pointer -mcpu=i486 -Wall"
                ;;
                *ia64*)
                    # gcc
                    lac_CFLAGS="$lac_CFLAGS -DL_ENDIAN -DTERMIO -O3 -fomit-frame-pointer -Wall"
                ;;
                *alpha*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -O3 -DL_ENDIAN -DTERMIO"
                    else
                        lac_CFLAGS="$lac_CFLAGS -fast -readonly_strings -DL_ENDIAN -DTERMIO"
                    fi
                ;;
            esac
        ;;
        *irix6*)
            case ${lac_cv_CPU} in
                *mips3*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -mmips-as -O3 -DTERMIOS -DB_ENDIAN"
                    else
                        lac_CFLAGS="$lac_CFLAGS -O2 -use_readonly_const -DTERMIOS -DB_ENDIAN"
                    fi
                ;;
                *mips4*)
                    if test "$GCC" = "yes"; then
                        lac_CFLAGS="$lac_CFLAGS -mips4 -mmips-as -O3 -DTERMIOS -DB_ENDIAN"
                    else
                        lac_CFLAGS="$lac_CFLAGS -mips4 -O2 -use_readonly_const -DTERMIOS -DB_ENDIAN"
                    fi
                ;;
            esac
        ;;
        *hpux*)
            if test "$GCC" = "yes"; then
                    lac_CFLAGS="$lac_CFLAGS -O3 -DB_ENDIAN -DBN_DIV2W"
            else
                    lac_CFLAGS="$lac_CFLAGS +O3 +Optrs_strongly_typed +Olibcalls -Ae +ESlit -DB_ENDIAN -DBN_DIV2W -DMD32_XARRAY"
            fi
        ;;
        *-ibm-aix*)
            if test "$GCC" = "yes"; then
                    lac_CFLAGS="$lac_CFLAGS -O3 -DAIX -DB_ENDIAN"
            else
                    lac_CFLAGS="$lac_CFLAGS -O -DAIX -DB_ENDIAN -qmaxmem=16384 -qfullpath"
            fi
        ;;
        *-dec-osf*)
            if test "$GCC" = "yes"; then
                    lac_CFLAGS="$lac_CFLAGS -O3"
            else
                    lac_CFLAGS="$lac_CFLAGS -std1 -tune host -fast -readonly_strings"
            fi
        ;;
    esac
])







