

dnl LAC_CPU_SET
AC_DEFUN([LAC_CPU_SET],
[
    AC_REQUIRE([AC_CANONICAL_HOST])

    case $host in
        *86_64*)
            lac_cv_CPU="x86_64"
        ;;        
        *86*)
            lac_cv_CPU="x86"
        ;;        
        *ia64*)
            lac_cv_CPU="ia64"
        ;;        
        *hpux*)
            lac_cv_CPU="parisc"
        ;;
        sparc64-*-linux*)
            lac_cv_CPU="sun4u"
        ;;
        *-ibm-aix*|*-dec-osf*|*alpha*linux*|*solaris*)
            lac_cv_CPU=`uname -m`
        ;;
        *irix6*)
            lac_tmp_CPU=`(hinv -t cpu) 2>/dev/null | head -1 |sed 's/^CPU:[[^R]]*R\([[0-9]]*\).*/\1/'`
            lac_tmp_CPU=${lac_tmp_CPU:-0}
            if test $lac_tmp_CPU -ge 5000; then
                lac_cv_CPU=mips4
            else
                lac_cv_CPU=mips3
            fi
        ;;
        *)
            lac_cv_CPU="unknown"
        ;;
    esac
])


dnl LAC_CPU
AC_DEFUN([LAC_CPU],
[
    AC_CACHE_CHECK([CPU type],lac_cv_CPU,[LAC_CPU_SET])
])



