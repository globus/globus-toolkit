# Enable threads
# Pass with no value to take the default
# Pass with a value to specify a thread package
AC_DEFUN(LAC_THREADS,[
AC_REQUIRE([AC_CANONICAL_HOST])dnl

AC_CHECK_HEADER(thread.h, [have_thread_h=yes], [have_thread_h=])
AC_CHECK_HEADER(pthread.h, [have_pthread_h=yes], [have_pthread_h=])

#Check for thread libraries
if test x$have_thread_h = xyes; then 

	AC_CHECK_LIB(thread, thr_create, 
	[GLOBUS_HAVE_SOLARIS_THREADS="yes"
	 SOLARIS_THREAD_LIB_FLAGS="-lthread"
	])

fi

if test x$have_pthread_h = xyes; then 

# Add other libs if necessary

	case $host in # defined by AC_CANONICAL_HOST

        	*solaris2* ) other_libs="-lposix4";;
		*-hp-hpux10* | *-hp-hpux11* ) other_libs="-lm";;
		* ) other_libs=;;
	esac
        GLOBUS_HAVE_PTHREADS="yes"
fi

# Decide on one thread package


case $GLOBUS_THREADS in

solaristhreads)
	if test "$GLOBUS_HAVE_SOLARIS_THREADS" = "yes" ; then

		THREAD_LIB_FLAGS=$SOLARIS_THREAD_LIB_FLAGS
	else
		echo "ERROR: thread flavor $flavor not supported on this platform"
		exit 1
	fi
	;;

sproc)
;;

external)
;;
pthreads)
	if test "$GLOBUS_HAVE_PTHREADS" = "yes" ; then

		THREAD_LIB_FLAGS=$PTHREAD_LIB_FLAGS
	else
		echo "ERROR: thread flavor $flavor not supported on this platform"
		exit 1
	fi
	;;
none)
		THREAD_LIB_FLAGS=
;;
*)
	echo "ERROR: thread flavor $flavor not recognized"
	exit 1
	;;	
esac
AC_SUBST(THREAD_LIB_FLAGS)
])
