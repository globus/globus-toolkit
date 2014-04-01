dnl
dnl LAC_THREADS()
dnl     Adds thread-related options to the configure command-line handling
dnl     Set the appropriate lac_cv_* variables:
dnl             lac_cv_threads_type ("no", "pthreads", 
dnl                                     "solaristhreads")
dnl             lac_cv_threads_defines
dnl             lac_cv_threads_CFLAGS
dnl             lac_cv_threads_CXXFLAGS
dnl             lac_cv_threads_LDFLAGS
dnl             lac_cv_threads_LIBS
dnl     The *FLAGS and *LIBS variables should only be set to flags
dnl     that are independent of the compiler.  Compiler dependent
dnl     flags should be specified in accompiler.m4.
dnl     Also setup lac_threads_* variables that mirror the lac_cv_threads_*
dnl     variables.

dnl LAC_THREADS()
AC_DEFUN([LAC_THREADS],
[
LAC_THREADS_PTHREADS
LAC_THREADS_WINDOWS

if test "$build_pthreads" = "yes"; then
    thread_models="$thread_models pthread"
fi
if test "$build_windows_threads" = "yes"; then
    thread_models="$thread_models windows"
fi
AC_SUBST(thread_models)

AC_SUBST(PTHREAD_PREOPEN_UNINSTALLED)
AC_SUBST(WINDOWS_PREOPEN_UNINSTALLED)
])

dnl LAC_THREADS_PTHREADS
AC_DEFUN([LAC_THREADS_PTHREADS],
[
    lib_type=""

    pthread_cflags=""
    pthread_libs=""
    pthread_ldflags=""

    AC_CACHE_CHECK(
        [if compiler recognizes -pthread], 
        [myapp_cv_gcc_pthread], 
        [
        ac_save_CFLAGS=$CFLAGS 
        CFLAGS="$CFLAGS -pthread" 
        AC_TRY_LINK([#include <pthread.h>], 
            [void *p = pthread_create;], 
            [pthread_cflags="-pthread"
             myapp_cv_gcc_pthread=yes], 
            [myapp_cv_gcc_pthread=no] 
        ) 
        CFLAGS="$ac_save_CFLAGS"
        ])

    have_pthreads=no
    have_sched_yield=no
    save_LIBS="$LIBS"
    AC_CHECK_HEADERS([pthread.h],
        AC_SEARCH_LIBS([pthread_create], [pthread], [have_pthreads=yes]))
    AC_CHECK_HEADERS([sched.h],
        AC_SEARCH_LIBS([sched_yield], [pthread posix4 rt], [have_sched_yield=yes]))
    if test X"$ac_cv_search_pthread_create" != Xno && \
        test X"$ac_cv_search_pthread_create" != X"none required"; then
        pthread_libs="${pthread_libs} $ac_cv_search_pthread_create" 
    fi
    if test X"$ac_cv_search_sched_yield" != Xno && \
        test X"$ac_cv_search_sched_yield" != X"none required"; then
        pthread_libs="${pthread_libs} $ac_cv_search_sched_yield" 
    fi
    LIBS="$save_LIBS"

    if test "$have_pthreads" = "no"; then
        AC_MSG_NOTICE([pthread package not found])
    else
        case "$host" in
          *-hp-hpux11* )
            pthread_libs="$pthread_libs -lm"
            pthread_cflags="$pthread_cflags -D_REENTRANT"
          ;;
          *solaris2* )
            pthread_cflags="$pthread_cflags -D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT"
          ;;
        esac
        build_pthreads=yes
    fi
    CFLAGS="${CFLAGS:+$CFLAGS }${pthread_cflags}"
    LDFLAGS="${LDFLAGS:+$LDFLAGS }${pthread_ldflags}"
    LIBS="${LIBS:+$LIBS }${pthread_libs}"
    if test "$build_pthreads" = "yes"; then
        PTHREAD_PREOPEN_UNINSTALLED="-dlopen '\${abs_top_builddir}/library/libglobus_thread_pthread.la'"
        AC_CONFIG_FILES([globus-thread-pthread-uninstalled.pc])
    fi
    AM_CONDITIONAL([BUILD_PTHREADS], [test "$build_pthreads" = "yes"])
])


dnl LAC_THREADS_WINDOWS
AC_DEFUN([LAC_THREADS_WINDOWS],
[
    found_inc="no"
    found_lib="no"
    found_compat_lib="no"

    windowsthreads_cflags=""
    windowsthreads_libs=""
    windowsthreads_ldflags=""

    case "$host" in
        *mingw* [)]
            build_windows_threads="yes"
            WINDOWS_PREOPEN_UNINSTALLED="-dlopen '\${abs_top_builddir}/library/libglobus_thread_windows.la'"
            AC_CONFIG_FILES([globus-thread-windows-uninstalled.pc])
            ;;
    esac

    AM_CONDITIONAL([BUILD_WINDOWS_THREADS], [test "$build_windows_threads" = "yes"])
])
