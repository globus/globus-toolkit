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

dnl LAC_THREADS_ARGS()
AC_DEFUN([LAC_THREADS_ARGS],
[
AC_BEFORE([$0], [LAC_THREADS])

])


dnl LAC_THREADS()
AC_DEFUN([LAC_THREADS],
[

LAC_THREADS_NONE
LAC_THREADS_PTHREADS
LAC_THREADS_WINDOWS

lac_threads_defines=$lac_cv_threads_defines

LAC_THREADS_DEFINE

])


AC_DEFUN([LAC_THREADS_NONE],
[
lac_threads_defines=""
])


dnl LAC_THREADS_PTHREADS
AC_DEFUN([LAC_THREADS_PTHREADS],
[
AC_MSG_CHECKING(for pthreads)

    found_inc="no"
    found_lib="no"
    found_compat_lib="no"

    LAC_FIND_USER_INCLUDE(pthread,$lac_thread_include_path /usr/local/fsu-pthreads,
                [found_inc="yes"
                 lac_thread_include_path="$ac_find_inc_dir"
                ])

    if test "$found_lib" = "no"; then
        LAC_FIND_USER_LIB(pthread,$lac_thread_library_path,
                [found_lib="yes"
                 lib_type="pthread"
                 lac_thread_library_path="$ac_find_lib_dir"
                 lac_thread_library_file="$ac_find_lib_file"
                ])
    fi

    if test "$found_lib" = "no"; then
        LAC_FIND_USER_LIB(pthreads,$lac_thread_library_path,
                [found_lib="yes"
                 lib_type="pthread"

                 lac_thread_library_path="$ac_find_lib_dir"
                 lac_thread_library_file="$ac_find_lib_file"
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
        if test $myapp_cv_gcc_pthread = yes ; then 
           lib_type="bsd_pthread" 
           found_lib="yes"
        fi 
    fi

    if test "$found_inc" = "yes" && test "$found_lib" = "yes"; then
        LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD)
        case "$lib_type" in
          pthread )
            case "$host" in
              mips-sgi-irix6* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT) 
                LAC_THREADS_ADD_DEFINE(_SGI_MP_SOURCE)  
              ;;
              *-hp-hpux11* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
                LAC_THREADS_ADD_DEFINE(_REENTRANT)
              ;;
              *solaris2* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT) 
                LAC_THREADS_ADD_DEFINE(_POSIX_PTHREAD_SEMANTICS) 
                LAC_THREADS_ADD_DEFINE(_REENTRANT)
              ;;
              *86-*-linux* | *darwin* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT) 
              ;;
              * )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT) 
              ;;
            esac
          ;;
          bsd_pthread )
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
            LAC_THREADS_ADD_DEFINE(_REENTRANT)
          ;;
        esac
    fi

AC_MSG_RESULT($found_lib)

])

dnl LAC_THREADS_WINDOWS
AC_DEFUN([LAC_THREADS_WINDOWS],
[
AC_MSG_CHECKING([for windows threads])
winthreads=no
case "$host" in
    *cygwin*|*mingw*)
        LAC_THREADS_ADD_DEFINE(HAVE_WINDOWS_THREADS)
        lac_cv_threads_CFLAGS="-DWINVER=0x0502"
        winthreads=yes
    ;;
    *mingw*)
        LAC_THREADS_ADD_DEFINE(HAVE_WINDOWS_THREADS)
        lac_cv_threads_CFLAGS="-DWINVER=0x0502"
        winthreads=yes
    ;;
esac
AC_MSG_RESULT([$winthreads])
])

dnl LAC_THREADS_ADD_DEFINE(SYMBOL)
dnl If you add a define for a new SYMBOL, you need to add that symbol
dnl to LAC_THREADS_DEFINE.
AC_DEFUN([LAC_THREADS_ADD_DEFINE],
[
    lac_cv_threads_defines="$lac_cv_threads_defines $1"
])

dnl LAC_THREADS_DEFINE()
AC_DEFUN([LAC_THREADS_DEFINE],
[
for lac_def in $lac_cv_threads_defines
do
    case $lac_def in
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD)
        LAC_THREADS_DEFINE_ONE(HAVE_WINDOWS_THREADS)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_PREEMPTIVE)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_SCHED)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_INIT_FUNC)
        LAC_THREADS_DEFINE_ONE(HAVE_THREAD_SAFE_STDIO)
        LAC_THREADS_DEFINE_ONE(HAVE_THREAD_SAFE_SELECT) 
        LAC_THREADS_DEFINE_ONE(_SGI_MP_SOURCE)  
        LAC_THREADS_DEFINE_ONE(__USE_FIXED_PROTOTYPES__)
        LAC_THREADS_DEFINE_ONE(_REENTRANT)
        LAC_THREADS_DEFINE_ONE(_POSIX_PTHREAD_SEMANTICS) 
        * )
            AC_MSG_ERROR([Internal error: acthreads.m4:LAC THREADS_DEFINE is missing a definition for "$lac_def"])
        ;;
    esac
done
])

AC_DEFUN([LAC_THREADS_DEFINE_ONE], [$1 ) AC_DEFINE($1) ;;])

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

