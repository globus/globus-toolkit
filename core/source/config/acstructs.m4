AC_DEFUN([CHECK_FOR_TIMESPEC], [
AC_TRY_COMPILE(
         [
#            include <sys/time.h>
         ],
         [
#if  !HAVE_SOLARISTHREADS && !HAVE_PTHREAD
	     struct timespec foo;
#endif
         ],
         ac_cv_timespec="yes",
         ac_cv_timespec="no")
   
if test "$ac_cv_timespec" = "yes"; then 
   AC_DEFINE(GLOBUS_TIMESPEC_EXISTS)
fi

])

AC_DEFUN([CHECK_FOR_IOVEC], [
dnl check for struct iovec in <sys/uio.h>
AC_MSG_CHECKING(for struct iovec in sys/uio.h)
    lac_iovec_result="no"
    if test -n "$ac_cv_have_struct_iovec"; then
        if test "$ac_cv_have_struct_iovec" = "yes"; then
	    AC_DEFINE(HAVE_STRUCT_IOVEC)
	fi
	lac_iovec_result="(cached) $ac_cv_have_struct_iovec"
    else
        AC_TRY_COMPILE(
	    [
#               if HAVE_SYS_TYPES_H
#                   include <sys/types.h>
#               endif
#               if HAVE_SYS_UIO_H
#                   include <sys/uio.h>
#               endif
            ],
	    [
                struct foo {
        	    struct iovec foo;
        	};
            ],
	    lac_iovec_result="yes" ac_cv_have_struct_iovec="yes"
	        AC_DEFINE(HAVE_STRUCT_IOVEC),
	    lac_iovec_result="no"
	    ac_cv_have_struct_iovec="no")
    fi
AC_MSG_RESULT($lac_iovec_result)

AC_MSG_CHECKING(for maximum length of iovec array)
    if test -n "$lac_cv_max_iov" ; then
        ac_max_iov_result="(cached) $lac_cv_max_iov"
	if test "$lac_cv_max_iov" != "IOV_MAX"; then
	    AC_DEFINE_UNQUOTED(IOV_MAX, $lac_cv_max_iov)
	fi
    else
	lac_cv_max_iov=no
        ac_max_iov_result=""

        if test "$lac_cv_max_iov" = "no" ; then
            AC_TRY_COMPILE(
	        [
#                   if HAVE_SYS_TYPES
#                       include <sys/types.h>
#                   endif
#                   if HAVE_SYS_UIO_H
#                       include <sys/uio.h>
#                   endif
#                   if HAVE_LIMITS_H
#                       include <limits.h>
#                   endif
#                   include <stdio.h>
                ],
	        [
                    int foo = IOV_MAX;
                ],
	        lac_cv_max_iov=IOV_MAX)
        fi

        if test "$lac_cv_max_iov" = "no" ; then
            AC_TRY_COMPILE(
	        [
#                   if HAVE_SYS_TYPES
#                       include <sys/types.h>
#                   endif
#                   if HAVE_SYS_UIO_H
#                       include <sys/uio.h>
#                   endif
#                   if HAVE_SYS_LIMITS_H
#                       include <sys/limits.h>
#                   endif
                ],
	        [
                    int foo = IOV_MAX;
                ],
	        lac_cv_max_iov=IOV_MAX)
        fi

        if test $lac_cv_max_iov = "no" ; then
            AC_TRY_COMPILE(
            [
#                   if HAVE_SYS_TYPES
#                       include <sys/types.h>
#                   endif
#                   if HAVE_SYS_UIO_H
#                       include <sys/uio.h>
#                   endif
#                   if HAVE_LIMITS
#                       include <limits.h>
#                   endif
                ],
            [
                    int foo = MAXIOV;
                ],
                lac_cv_max_iov=MAXIOV
                AC_DEFINE_UNQUOTED(IOV_MAX,$lac_cv_max_iov)
        ac_max_iov_result="$lac_cv_max_iov")
        fi

        if test $lac_cv_max_iov = "no" ; then
            AC_TRY_COMPILE(
            [
#                   if HAVE_SYS_TYPES
#                       include <sys/types.h>
#                   endif
#                   if HAVE_SYS_UIO_H
#                       include <sys/uio.h>
#                   endif
#                   if HAVE_LIMITS
#                       include <limits.h>
#                   endif
                ],
            [
                    int foo = UIO_MAXIOV;
                ],
                lac_cv_max_iov=UIO_MAXIOV
                AC_DEFINE_UNQUOTED(IOV_MAX,$lac_cv_max_iov)
        ac_max_iov_result="$lac_cv_max_iov")
        fi


        if test $lac_cv_max_iov = "no" ; then
            AC_TRY_COMPILE(
	        [
#                   if HAVE_SYS_TYPES
#                       include <sys/types.h>
#                   endif
#                   if HAVE_LIMITS
#                       include <limits.h>
#                   endif
#                   if HAVE_SYS_UIO_H
#                       include <sys/uio.h>
#                   endif
#                   if HAVE_UNISTD_H
#                       include <unistd.h>
#                   endif
                ],
	        [
                    long foo = sysconf(_SC_IOV_MAX);
                ],
                lac_cv_max_iov="sysconf(_SC_IOV_MAX)"
                AC_DEFINE_UNQUOTED(IOV_MAX,$lac_cv_max_iov)
		ac_max_iov_result="$lac_cv_max_iov")
        fi

	if test $lac_cv_max_iov = "no" ; then
	    lac_cv_max_iov=16
	    AC_DEFINE_UNQUOTED(IOV_MAX, $lac_cv_max_iov)
	    ac_max_iov_result="unknown, using default of $lac_cv_max_iov"
	fi

    fi
AC_MSG_RESULT($ac_max_iov_result)

])

AC_DEFUN([CHECK_FOR_MEMMOVE], [
dnl check for availablility of atexit or on_exit
AC_MSG_CHECKING(checking for memmove)
lac_cv_memmove="no"
AC_TRY_LINK([#include <string.h>
    char b[10];],
    [memmove(b, &b[1], 1)
    ], AC_DEFINE(HAVE_MEMMOVE) lac_cv_memmove="memmove")
AC_MSG_RESULT($lac_cv_memmove)
])

AC_DEFUN([CHECK_FOR_ATEXIT], [
dnl check for availablility of atexit or on_exit
AC_MSG_CHECKING(how to execute a function on program exit)
lac_cv_atexit="no"
AC_TRY_LINK([#include <stdlib.h>
	void func() {}],
	[atexit(func)
    ], AC_DEFINE(HAVE_ATEXIT) lac_cv_atexit="atexit")

if test $lac_cv_atexit = "no"; then
AC_TRY_LINK([#include <stdlib.h>
	void func() {}],
	[on_exit(func)
    ], AC_DEFINE(HAVE_ONEXIT) lac_cv_atexit="on_exit")
fi

AC_MSG_RESULT($lac_cv_atexit)

])

