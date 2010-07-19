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
])

dnl LAC_THREADS_PTHREADS
AC_DEFUN([LAC_THREADS_PTHREADS],
[
    found_inc="no"
    found_lib="no"
    found_compat_lib="no"

    pthread_cflags=""
    pthread_libs=""
    pthread_ldflags=""

    LAC_FIND_USER_INCLUDE(pthread,$lac_thread_include_path, [found_inc="yes"])

    if test "$found_lib" = "no"; then
        LAC_FIND_USER_LIB(pthread,$lac_thread_library_path,
                [found_lib="yes"
                 lib_type="pthread"
                ])
    fi

    if test "$found_lib" = "no"; then
        AC_CACHE_CHECK( 
            [if compiler recognizes -pthread], 
            [myapp_cv_gcc_pthread], 
            [
            ac_save_CFLAGS=$CFLAGS 
            CFLAGS="$CFLAGS -pthread" 
            AC_TRY_LINK([#include <pthread.h>], 
                [void *p = pthread_create;], 
                [myapp_cv_gcc_pthread=yes], 
                [myapp_cv_gcc_pthread=no] 
            ) 
            CFLAGS=$ac_save_CFLAGS 
            ]
        )
        if test "$myapp_cv_gcc_pthread" = "yes" ; then 
           lib_type="bsd_pthread" 
        fi 
    fi

    if test "$found_lib" = "no"; then
        AC_MSG_NOTICE([pthread package not found])
    fi

    if test "$found_inc" = "yes" && test "$found_lib" = "yes"; then
        case "$lib_type" in
          pthread )
            case "$host" in
              *-hp-hpux11* )
                pthread_libs="-L$ac_find_lib_dir -lpthread -lm"
                pthread_cflags="-I$ac_find_inc_dir -D_REENTRANT"
              ;;
              *solaris2* )
                pthread_libs="-L$ac_find_lib_dir -lpthread -lposix4"
                pthread_cflags="-I$ac_find_inc_dir -D_REENTRANT"
              ;;
              *86-*-linux* | *darwin* )
                pthread_libs="-lpthread"
              ;;
              * )
                pthread_cflags="-I$ac_find_inc_dir"
                pthread_libs="-L$ac_find_lib_dir -lpthread"
              ;;
            esac
          ;;
          bsd_pthread )
            pthread_cflags="-I$ac_find_inc_dir -pthread -D_REENTRANT"
            pthread_ldflags="-pthread"
          ;;
        esac
        build_pthreads=yes
    fi
    AC_SUBST([PTHREAD_CFLAGS], ["$pthread_cflags"])
    AC_SUBST([PTHREAD_LDFLAGS], ["$pthread_ldflags"])
    AC_SUBST([PTHREAD_LIBS], ["$pthread_libs"])
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
        *cygwin* | *mingw* [)]
            build_windows_threads="yes"
            ;;
    esac

    AM_CONDITIONAL([BUILD_WINDOWS_THREADS], [test "$build_windows_threads" = "yes"])
])



dnl include_file, path
AC_DEFUN([LAC_FIND_USER_INCLUDE],[
AC_MSG_CHECKING([for include directory for $1])
ac_find_inc_dir=""
for dir in $2 \
        /usr \
        /usr/include \
        /usr/local \
        /usr/local/$1 \
        /usr/contrib \
        /usr/contrib/$1 \
        $HOME/$1 \
        /opt/$1 \
        /opt/local \
        /opt/local/$1 \
        /local/encap/$1 ; do
        if test -r $dir/$1.h ; then
            ac_find_inc_dir=$dir
            break
        fi
        if test -r $dir/include/$1.h ; then
            ac_find_inc_dir=$dir/include
            break
        fi
dnl     if test -r $dir/lib/lib$1.a ; then
dnl         ac_find_lib_file=$dir/lib/lib$1.a
dnl         break
dnl     fi
done
if test -n "$ac_find_inc_dir" ; then
  AC_MSG_RESULT(found $ac_find_inc_dir)
  ifelse([$3],,,[$3])
else
  AC_MSG_RESULT(no)
  ifelse([$4],,,[$4])
fi
])

AC_DEFUN([LAC_FIND_USER_LIB],[
AC_MSG_CHECKING([for library $1])
ac_find_lib_file=""
for dir in $2 \
        /usr \
        /usr/lib \
        /usr/shlib \
        /usr/local \
        /usr/local/$1 \
        /usr/contrib \
        /usr/contrib/$1 \
        $HOME/$1 \
        /opt/$1 \
        /opt/local \
        /opt/local/$1 \
        /local/encap/$1 ; do
  for ext in so a sl dylib ; do
        if test -r $dir/$1.$ext ; then
            ac_find_lib_file=$dir/$1.$ext
            ac_find_lib_dir=$dir
            break
        fi
        if test -r $dir/lib$1.$ext ; then
            ac_find_lib_file=$dir/lib$1.$ext
            ac_find_lib_dir=$dir
            break
        fi
        if test -r $dir/lib/$1.$ext ; then
            ac_find_lib_file=$dir/lib/$1.$ext
            ac_find_lib_dir=$dir/lib
            break
        fi
        if test -r $dir/lib/lib$1.$ext ; then
            ac_find_lib_file=$dir/lib/lib$1.$ext
            ac_find_lib_dir=$dir/lib
            break
        fi
    done
    if test -n "$ac_find_lib_file" ; then
        break
    fi
done
if test -n "$ac_find_lib_file" ; then
  AC_MSG_RESULT(found $ac_find_lib_file)
  ifelse([$3],,,[$3])
else
  AC_MSG_RESULT(no)
  ifelse([$4],,,[$4])
fi
])
