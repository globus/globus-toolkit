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

AC_ARG_WITH(thread-library,
        [  --with-thread-library=PATH    path to thread library files],
        [lac_thread_library_path="$withval"],
        [lac_thread_library_path=${lac_thread_library_path=''}])
AC_ARG_WITH(thread-includes,
        [  --with-thread-includes=PATH   path to thread include files],
        [lac_thread_include_path="$withval"],
        [lac_thread_include_path=${lac_thread_include_path=''}])
])


dnl LAC_THREADS()
AC_DEFUN([LAC_THREADS],
[

if test "$lac_cv_threads_vars_set" != "yes" ; then
    lac_cv_threads_defines=""
    lac_cv_threads_CFLAGS=""
    lac_cv_threads_CXXFLAGS=""
    lac_cv_threads_LDFLAGS=""
    lac_cv_threads_LIBS=""
    lac_cv_threads_vars_set="yes"

    case $lac_cv_threads_type in
        no)
            LAC_THREADS_NONE
            ;;
        solaristhreads)
            LAC_THREADS_SOLARISTHREADS
            ;;
        pthreads)
            LAC_THREADS_PTHREADS
            ;;
        sproc)
            LAC_THREADS_SPROC
            ;;
        external)
            LAC_THREADS_EXTERNAL
            ;;
        *)
            AC_MSG_ERROR([--with-threads=$lac_cv_threads_type is not a valid thread package])
            exit 1
            ;;
    esac
fi

lac_threads_type=$lac_cv_threads_type
lac_threads_defines=$lac_cv_threads_defines
lac_threads_CFLAGS=$lac_cv_threads_CFLAGS
lac_threads_CXXFLAGS=$lac_cv_threads_CXXFLAGS
lac_threads_LDFLAGS=$lac_cv_threads_LDFLAGS
lac_threads_LIBS=$lac_cv_threads_LIBS

LAC_THREADS_DEFINE

])


AC_DEFUN([LAC_THREADS_NONE],
[
lac_threads_type="no"
lac_threads_defines=""
lac_threads_CFLAGS=""
lac_threads_CXXFLAGS=""
lac_threads_LDFLAGS=""
lac_threads_LIBS=""
LAC_THREADS_ADD_DEFINE(BUILD_LITE)
])


dnl LAC_THREADS_SOLARISTHREADS
AC_DEFUN([LAC_THREADS_SOLARISTHREADS],
[
if test "$lac_cv_threads_type" = "solaristhreads" -o "$lac_cv_threads_type" = "yes" ; then

AC_MSG_CHECKING(for solaristhreads)

    case "$host" in
        *solaris2* )
            found_inc="no"
            found_lib="no"

            LAC_FIND_USER_INCLUDE(thread,$lac_thread_include_path,
                [found_inc="yes"
                 lac_thread_include_path="$ac_find_inc_dir"
                ])

            LAC_FIND_USER_LIB(thread,$lac_thread_library_path,
                [found_lib="yes"
                 lac_thread_library_path="$ac_find_lib_dir"
                 lac_thread_library_file="$ac_find_lib_file"
                ])

            if test "$found_inc" = "yes" -a "$found_lib" = "yes" ; then
                lac_cv_threads_type="solaristhreads"
                LAC_THREADS_ADD_DEFINE(HAVE_SOLARISTHREADS)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
                lac_cv_threads_CFLAGS="$lac_cv_threads_CFLAGS -D_REENTRANT"
                lac_cv_threads_LIBS="-lthread"
            else
                 AC_MSG_ERROR([solaris thread package not found!!])
                 exit 1

            fi
        ;;
        *)
                 AC_MSG_ERROR([solaris thread package not supported on this platform])
                 exit 1
        ;;
    esac
    AC_MSG_RESULT($found_lib)
fi
])

dnl LAC_THREADS_EXTERNAL
AC_DEFUN([LAC_THREADS_EXTERNAL],
[
if test "$lac_cv_threads_type" = "external"; then
dnl These are forced to yes, relying on the user to set the
dnl --with-thread-library appropriately
    found_inc="yes"
    found_lib="yes"

    lac_cv_threads_type="external"
    LAC_THREADS_ADD_DEFINE(HAVE_EXTERNALTHREADS)
    lac_cv_threads_LIBS="$lac_thread_library_path"
    lac_cv_threads_CFLAGS="-I$lac_thread_include_path -D_REENTRANT"
    
    case "$host" in
        mips-sgi-irix6* )
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)     
            LAC_THREADS_ADD_DEFINE(_SGI_MP_SOURCE)      
        ;;
        *-ibm-aix4* )
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
        ;;
        *solaris2* )
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)     
        ;;
        *86-*-linux* )
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)     
        ;;
        *ia64-*linux* )
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)     
        ;;
        * )
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)     
        ;;
    esac
fi
])


dnl LAC_THREADS_SPROC
AC_DEFUN([LAC_THREADS_SPROC],
[
if test "$lac_cv_threads_type" = "sproc" -o "$lac_cv_threads_type" = "yes" ; then

AC_MSG_CHECKING(for sproc)

   case "$host" in 
        *irix*)
        found_inc="no"

            LAC_FIND_USER_INCLUDE(sys/prctl,$lac_thread_include_path,
                [found_inc="yes"
                 lac_thread_include_path="$ac_find_inc_dir"
                ])

            if test "$found_inc" = "yes" ; then
                lac_cv_threads_type="sproc"
                LAC_THREADS_ADD_DEFINE(HAVE_SPROC)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
                LAC_THREADS_ADD_DEFINE(_SGI_MP_SOURCE)
                lac_cv_threads_LIBS="-lmutex"
            else
                 AC_MSG_ERROR([sproc package not found!!])
                 exit 1
            fi
        ;;
        *)
                 AC_MSG_ERROR([sproc package not supported on this platform])
                 exit 1
        ;;

    esac
fi
    AC_MSG_RESULT($found_inc)
])

dnl LAC_THREADS_PTHREADS
AC_DEFUN([LAC_THREADS_PTHREADS],
[
if test "$lac_cv_threads_type" = "pthreads" -o "$lac_cv_threads_type" = "yes"; then

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
                 dnl
                 dnl Under HPUX10, libpthreads.a is dce threads.
                 dnl
                 case "$host" in
                     *-hp-hpux10* )
                         lib_type="dce"
                     ;;
                     * )
                         lib_type="pthread"
                     ;;
                 esac

                 lac_thread_library_path="$ac_find_lib_dir"
                 lac_thread_library_file="$ac_find_lib_file"
                ])
                 
    fi

    if test "$found_lib" = "no"; then
        LAC_FIND_USER_LIB(dce,$lac_thread_library_path,
                [found_lib="yes"
                 lib_type="dce"
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

    if test "$found_lib" = "no"; then
        AC_MSG_ERROR([posix thread package not found!!])
        exit 1
    fi

    if test "$found_inc" = "yes" && test "$found_lib" = "yes"; then
        lac_cv_threads_type="pthreads"
        LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD)
        case "$lib_type" in
          pthread )
            case "$host" in
              mips-sgi-irix6* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT) 
                LAC_THREADS_ADD_DEFINE(_SGI_MP_SOURCE)  
                lac_cv_threads_LIBS="-lpthread"
              ;;
              *-ibm-aix4* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_8)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
                if test "$found_compat_lib" = "yes"; then
                    lac_cv_threads_LIBS="-lpthreads_compat"
                fi
              ;;
              *-dec-osf4* | *-dec-osf5* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT) 
                lac_cv_threads_CFLAGS="$lac_cv_threads_CFLAGS -D_REENTRANT"
              ;;
              *-hp-hpux10* | *-hp-hpux11* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
                lac_cv_threads_LIBS="-lpthread -lm"
                LAC_FIND_USER_LIB(cnx_syscall,,
                    [lac_cv_threads_LIBS="$lac_cv_threads_LIBS -lcnx_syscall"
                    ])
                lac_cv_threads_CFLAGS="$lac_cv_threads_CFLAGS -D_REENTRANT"
              ;;
              *solaris2* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT) 
                LAC_THREADS_ADD_DEFINE(_POSIX_PTHREAD_SEMANTICS) 
                lac_cv_threads_LIBS="-lpthread -lposix4"
                lac_cv_threads_CFLAGS="$lac_cv_threads_CFLAGS -D_REENTRANT"
              ;;
              *86-*-linux* | *darwin* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT) 
                lac_cv_threads_LIBS="-lpthread"
                lac_cv_threads_CFLAGS="$lac_cv_threads_CFLAGS -D_REENTRANT"
              ;;
              * )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT) 
                lac_cv_threads_LIBS="-lpthread"
              ;;
            esac
          ;;
          dce )
            case $host in 
              *-hp-hpux10* )
                LAC_THREADS_ADD_DEFINE(_CMA_REENTRANT_CLIB_)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_4)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_SCHED)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
                lac_cv_threads_CFLAGS="-I/usr/include/reentrant -D_REENTRANT"
                lac_cv_threads_CXXFLAGS="-I/usr/include/reentrant"
                lac_cv_threads_LIBS="-ldce -lm -lc_r"
                case "$host" in
                  *-hp-hpux10* | *-hp-hpux11* )
                    lac_cv_threads_LIBS="-ldce -lm"
                   ;;
                esac
              ;;
            esac
          ;;
          bsd_pthread )
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
            lac_cv_threads_CFLAGS="-pthread -D_REENTRANT"
          ;;
        esac
    fi
fi

AC_MSG_RESULT($found_lib)

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
        LAC_THREADS_DEFINE_ONE(HAVE_SOLARISTHREADS)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD)
        LAC_THREADS_DEFINE_ONE(HAVE_SPROC)
        LAC_THREADS_DEFINE_ONE(HAVE_EXTERNALTHREADS)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_DRAFT_4)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_DRAFT_6)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_DRAFT_8)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_DRAFT_10)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_PREEMPTIVE)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_SCHED)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_INIT_FUNC)
        LAC_THREADS_DEFINE_ONE(HAVE_PTHREAD_PLAIN_YIELD)
        LAC_THREADS_DEFINE_ONE(HAVE_THREAD_SAFE_STDIO)
        LAC_THREADS_DEFINE_ONE(HAVE_THREAD_SAFE_SELECT) 
        LAC_THREADS_DEFINE_ONE(_SGI_MP_SOURCE)  
        LAC_THREADS_DEFINE_ONE(_CMA_REENTRANT_CLIB_)
        LAC_THREADS_DEFINE_ONE(__USE_FIXED_PROTOTYPES__)
        LAC_THREADS_DEFINE_ONE(BUILD_LITE)
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

