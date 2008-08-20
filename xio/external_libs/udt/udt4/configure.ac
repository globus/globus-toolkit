#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(udt, 4.0, http://sf.net/projects/udt)
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([m], [sqrt])
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([socket], [socket])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_HEADER_TIME
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([gettimeofday memset pow select socket strerror])

# Checks for platform
case $target in
   linux )
       OS=LINUX;;
   aix | solaris )
       OS=UNIX;;
   darwin | bsd | freebsd )
       OS=BSD;;
   * )
       OS=LINUX;;
esac

case $target_cpu in
    i386 | i486 | i586 | i686 )
        ARCH=IA32;;
    x86_64 )
        ARCH=AMD64;;
    ia64 )
        ARCH=IA64;;
    ppc | ppc64 | powerpc | power64 )
        ARCH=powerpc;;
    * )
        ARCH=IA32;;
esac

CPPFLAGS="-I ../src -D$OS -D$ARCH $CPPFLAGS"

AC_SUBST([LIBVER],[`echo AC_PACKAGE_VERSION | sed 's/\\./:/'`])
AC_SUBST([LIBUDT],[src/libudt.la])

AC_CONFIG_FILES([Makefile examples/Makefile src/Makefile])
AC_OUTPUT
