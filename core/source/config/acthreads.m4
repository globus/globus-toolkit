dnl
dnl LAC_THREADS_ARGS()
dnl	Call this if you want the thread arguments.
dnl LAC_THREADS()
dnl	Calls LAC_THREADS_ARGS.
dnl	Set the appropriate lac_cv_* variables:
dnl		lac_cv_threads_type ("no", "pthreads", 
dnl					"solaristhreads")
dnl		lac_cv_threads_defines
dnl		lac_cv_threads_CFLAGS
dnl		lac_cv_threads_CXXFLAGS
dnl		lac_cv_threads_LDFLAGS
dnl		lac_cv_threads_LIBS
dnl	The *FLAGS and *LIBS variables should only be set to flags
dnl	that are independent of the compiler.  Compiler dependent
dnl	flags should be specified in accompiler.m4.
dnl     Also setup lac_threads_* variables that mirror the lac_cv_threads_*
dnl     variables.
dnl LAC_THREADS_NONE
dnl     Setup the various lac_threads_* variables to indicate no threads.
dnl	
dnl LAC_THREADS_DEFINE()
dnl	Perform the AC_DEFINE() calls, based on the variables set
dnl	by LAC_THREADS.
dnl

dnl LAC_THREADS_ARGS()
AC_DEFUN(LAC_THREADS_ARGS,
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
AC_DEFUN(LAC_THREADS,
[

if test "$lac_cv_threads_vars_set" != "yes" ; then
    lac_cv_threads_defines=""
    lac_cv_threads_CFLAGS=""
    lac_cv_threads_CXXFLAGS=""
    lac_cv_threads_LDFLAGS=""
    lac_cv_threads_LIBS=""
    lac_cv_threads_vars_set="yes"

    if test "$lac_cv_threads_type" != "no" ; then
        LAC_THREADS_SOLARISTHREADS
        LAC_THREADS_PTHREADS
	LAC_THREADS_SPROC
	LAC_THREADS_EXTERNAL
        AC_MSG_CHECKING(for thread library)
        if test "$lac_cv_threads_type" != "solaristhreads" \
             -a "$lac_cv_threads_type" != "pthreads" \
	     -a "$lac_cv_threads_type" != "sproc" \
	     -a "$lac_cv_threads_type" != "external" ; then
            AC_MSG_ERROR([no acceptable thread library found])
        else
            AC_MSG_RESULT($lac_cv_threads_type)
        fi
    fi
fi

lac_threads_type=$lac_cv_threads_type
lac_threads_defines=$lac_cv_threads_defines
lac_threads_CFLAGS=$lac_cv_threads_CFLAGS
lac_threads_CXXFLAGS=$lac_cv_threads_CXXFLAGS
lac_threads_LDFLAGS=$lac_cv_threads_LDFLAGS
lac_threads_LIBS=$lac_cv_threads_LIBS

LAC_THREADS_DEFINE

])


AC_DEFUN(LAC_THREADS_NONE,
[
lac_threads_type="no"
lac_threads_defines=""
lac_threads_CFLAGS=""
lac_threads_CXXFLAGS=""
lac_threads_LDFLAGS=""
lac_threads_LIBS=""
])


dnl ------------------------------------------------------------------------
dnl ----                   LAC_THREADS_SOLARISTHREADS
dnl ------------------------------------------------------------------------
AC_DEFUN(LAC_THREADS_SOLARISTHREADS,
[
if test "$lac_cv_threads_type" = "solaristhreads" -o "$lac_cv_threads_type" = "yes" ; then
    case "$target" in
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
                LAC_THREADS_ADD_DEFINE(_REENTRANT)
                lac_cv_threads_LIBS="-lthread"
            fi
        ;;
    esac
fi
])

dnl ------------------------------------------------------------------------
dnl ----                   LAC_THREADS_EXTERNAL
dnl ------------------------------------------------------------------------
AC_DEFUN(LAC_THREADS_EXTERNAL,
[
if test "$lac_cv_threads_type" = "external"; then
dnl These are forced to yes, relying on the user to set the
dnl --with-thread-library appropriately
    found_inc="yes"
    found_lib="yes"

    lac_cv_threads_type="external"
    LAC_THREADS_ADD_DEFINE(HAVE_EXTERNALTHREADS)
    LAC_THREADS_ADD_DEFINE(_REENTRANT)
    lac_cv_threads_LIBS="$lac_thread_library_path"
    lac_cv_threads_CFLAGS="-I$lac_thread_include_path"
    
    case "$target" in
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
        * )
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
            LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)	
        ;;
    esac
fi
])


dnl ------------------------------------------------------------------------
dnl ----                   LAC_THREADS_SPROC
dnl ------------------------------------------------------------------------
AC_DEFUN(LAC_THREADS_SPROC,
[
if test "$lac_cv_threads_type" = "sproc" -o "$lac_cv_threads_type" = "yes" ; then

   case "$target" in 
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
            fi
        ;;
    esac
fi
])

dnl ------------------------------------------------------------------------
dnl ----                         LAC_THREADS_PTHREADS
dnl ------------------------------------------------------------------------
AC_DEFUN(LAC_THREADS_PTHREADS,
[
if test "$lac_cv_threads_type" = "pthreads" -o "$lac_cv_threads_type" = "yes"; then
    found_inc="no"
    found_lib="no"
    found_compat_lib="no"

    LAC_FIND_USER_INCLUDE(pthread,$lac_thread_include_path /usr/local/fsu-pthreads,
                [found_inc="yes"
                 lac_thread_include_path="$ac_find_inc_dir"
                ])

    if test "$found_lib" = "no"; then
        LAC_FIND_USER_LIB(gthreads,$lac_thread_library_path /usr/local/fsu-pthreads,
                [found_lib="yes"
                 lib_type="fsu"
                 lac_thread_library_path="$ac_find_lib_dir"
                 lac_thread_library_file="$ac_find_lib_file"
                ])
    fi

    if test "$found_lib" = "no"; then
        LAC_FIND_USER_LIB(pthread,$lac_thread_library_path,
                [found_lib="yes"
                 lib_type="pthread"
                 lac_thread_library_path="$ac_find_lib_dir"
                 lac_thread_library_file="$ac_find_lib_file"
                ])
    fi

    if test "$found_lib" = "no"; then
        LAC_FIND_USER_LIB(pthreads,$lac_thread_library_path /usr/local/fsu-pthreads,
                [found_lib="yes"
                 dnl
                 dnl Old versions of fsu-pthreads for the Sun
                 dnl      installed to libpthreads.a.
                 dnl Under AIX3, HPUX9, HPUX10, and DEC Unix 3.x,
		 dnl      libpthreads.a is dce threads.
                 dnl
                 case "$target" in
                     *-ibm-aix3* | *-hp-hpux9* | *-hp-hpux10* | *-dec-osf3* )
                         lib_type="dce"
                     ;;
                     *sunos4* | *solaris1* )
                         lib_type="fsu-old"
                     ;;
                     * )
                         lib_type="pthread"
                     ;;
                 esac

                 lac_thread_library_path="$ac_find_lib_dir"
                 lac_thread_library_file="$ac_find_lib_file"
                ])
		 
    fi

    case "$target" in
	*-ibm-aix* )
	    LAC_FIND_USER_LIB(pthreads_compat,
		    $lac_thread_library_path /usr/local/fsu-pthreads,
		    [
		     found_compat_lib="yes"
		    ])
	;;
    esac


    if test "$found_lib" = "no"; then
        LAC_FIND_USER_LIB(dce,$lac_thread_library_path,
                [found_lib="yes"
                 lib_type="dce"
                 lac_thread_library_path="$ac_find_lib_dir"
                 lac_thread_library_file="$ac_find_lib_file"
                ])
    fi

    if test "$found_inc" = "yes" && test "$found_lib" = "yes"; then
        lac_cv_threads_type="pthreads"
        LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD)
        case "$lib_type" in
          pthread )
            case "$target" in
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
              alpha-dec-osf4* )
		LAC_THREADS_ADD_DEFINE(_REENTRANT)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)  
              ;;
	      *-hp-hpux10* | *-hp-hpux11* )
		LAC_THREADS_ADD_DEFINE(_REENTRANT)
		LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
		LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
		LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
		LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
		lac_cv_threads_LIBS="-lpthread -lm"
		LAC_FIND_USER_LIB(cnx_syscall,,
		    [lac_cv_threads_LIBS="$lac_cv_threads_LIBS -lcnx_syscall"
		    ])
	      ;;
              *solaris2* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)	
                lac_cv_threads_LIBS="-lpthread -lposix4"
	      ;;
              *86-*-linux* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_10)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_PREEMPTIVE)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)	
                lac_cv_threads_LIBS="-lpthread"
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
            case "$target" in
              *-ibm-aix3* )
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_4)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_SCHED)
              ;;
              *-hp-hpux9* | *-hp-hpux10* | *-hp-hpux11* )
                LAC_THREADS_ADD_DEFINE(_REENTRANT)
                LAC_THREADS_ADD_DEFINE(_CMA_REENTRANT_CLIB_)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_4)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_SCHED)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
                lac_cv_threads_CFLAGS="-I/usr/include/reentrant"
                lac_cv_threads_CXXFLAGS="-I/usr/include/reentrant"
		lac_cv_threads_LIBS="-ldce -lm -lc_r"
		case "$target" in
		  *-hp-hpux10* | *-hp-hpux11* )
		    lac_cv_threads_LIBS="-ldce -lm"
		   ;;
		esac
              ;;
              *-dec-osf3* )
dnl                LAC_THREADS_ADD_DEFINE(_REENTRANT)
dnl                LAC_THREADS_ADD_DEFINE(_CMA_REENTRANT_CLIB_)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_4)
                LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_SCHED)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_STDIO)
                LAC_THREADS_ADD_DEFINE(HAVE_THREAD_SAFE_SELECT)
              ;;
            esac
          ;;
          fsu )
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_6)
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_SCHED)
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_INIT_FUNC)
            LAC_THREADS_ADD_DEFINE(__USE_FIXED_PROTOTYPES__)
            lac_cv_threads_CFLAGS="-I$lac_thread_include_path"
            lac_cv_threads_CXXFLAGS="-I$lac_thread_include_path"
            lac_cv_threads_LIBS="-L$lac_thread_library_path -lgthreads -lmalloc"
          ;;
          fsu-old )
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_DRAFT_6)
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_SCHED)
            LAC_THREADS_ADD_DEFINE(HAVE_PTHREAD_INIT_FUNC)
            LAC_THREADS_ADD_DEFINE(__USE_FIXED_PROTOTYPES__)
            lac_cv_threads_CFLAGS="-I$lac_thread_include_path"
            lac_cv_threads_CXXFLAGS="-I$lac_thread_include_path"
            lac_cv_threads_LIBS="-L$lac_thread_library_path -lpthreads -lmalloc"
          ;;
        esac
    fi
fi
])


AC_DEFUN(LAC_SYS_LWP,
[ AC_MSG_CHECKING(for light-weight processes)
  AC_CACHE_VAL(ac_cv_sys_lwp, [dnl
  result=0
  AC_CHECK_FUNC(_lwp_getprivate, result=`expr $result + 1`)
  AC_CHECK_FUNC(_lwp_setprivate, result=`expr $result + 1`)
  if test "$result" = "2"; then
    ac_cv_sys_lwp="yes"
  else
    ac_cv_sys_lwp="no"
  fi
  ])
  AC_MSG_RESULT($ac_cv_sys_lwp)
  if test "$ac_cv_sys_lwp" = "yes"; then
    AC_DEFINE(HAVE_LWP)
  fi
])


dnl LAC_THREADS_ADD_DEFINE(SYMBOL)
dnl If you add a define for a new SYMBOL, you need to add that symbol
dnl to LAC_THREADS_DEFINE.
AC_DEFUN(LAC_THREADS_ADD_DEFINE,
[
    lac_cv_threads_defines="$lac_cv_threads_defines $1"
])

dnl LAC_THREADS_DEFINE()
AC_DEFUN(LAC_THREADS_DEFINE,
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
        LAC_THREADS_DEFINE_ONE(_REENTRANT)
        LAC_THREADS_DEFINE_ONE(_CMA_REENTRANT_CLIB_)
	LAC_THREADS_DEFINE_ONE(__USE_FIXED_PROTOTYPES__)
	LAC_THREADS_DEFINE_ONE(HAVE_LWP)
        * )
            AC_MSG_ERROR([Internal error: acthreads.m4:LAC THREADS_DEFINE is missing a definition for $lac_def])
	;;
    esac
done
])

AC_DEFUN(LAC_THREADS_DEFINE_ONE, [$1 ) AC_DEFINE($1) ;;])

dnl include_file, path
AC_DEFUN(LAC_FIND_USER_INCLUDE,[
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
dnl	if test -r $dir/lib/lib$1.a ; then
dnl	    ac_find_lib_file=$dir/lib/lib$1.a
dnl	    break
dnl	fi
done
if test -n "$ac_find_inc_dir" ; then
  AC_MSG_RESULT(found $ac_find_inc_dir)
  ifelse([$3],,,[$3])
else
  AC_MSG_RESULT(no)
  ifelse([$4],,,[$4])
fi
])

AC_DEFUN(LAC_FIND_USER_LIB,[
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
  for ext in so a sl; do
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

