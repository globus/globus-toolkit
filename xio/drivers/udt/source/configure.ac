AC_PREREQ([2.60])

AC_INIT([globus_xio_udt_driver],[1.14],[https://globus.atlassian.net/])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [1])
AC_SUBST([PACKAGE_DEPS], ["globus-xio >= 3, globus-common >= 14"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
LT_INIT([dlopen win32-dll])

AC_PROG_CXX

AC_CANONICAL_HOST
AC_CANONICAL_BUILD

AC_LANG(C++)

AC_SUBST(lt_prog_compiler_pic)

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

AM_CONDITIONAL([HOST_OSX], [case $host in *darwin*) true ;; *) false ;; esac]) 
if test "x$GCC" = "xyes"; then
    UDT_CXXFLAGS="-finline-functions -O3 -fno-strict-aliasing -fvisibility=hidden"
else
    UDT_CXXFLAGS=""
fi
case $host in
    *mingw*)
        CPPFLAGS="${CPPFLAGS} -DWINVER=0x0502"
        UDT_LIBADD="-lws2_32 -liphlpapi -lm"
        ;;
    *)
        UDT_LIBADD="-lpthread -lm"
        ;;
esac

AC_SUBST(UDT_CXXFLAGS)
AC_SUBST(UDT_LIBADD)
PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_ARG_WITH([static-udt],
    AS_HELP_STRING([--with-static-udt],[Build UDT library]),
    [if test "$withval" = yes; then
        use_included_udt=1
     fi])

AC_ARG_WITH([static-libnice],
    AS_HELP_STRING([--with-static-libnice],[Build libnice library]),
    [if test "$withval" = yes; then
        use_included_nice=1
     fi])

AC_ARG_WITH([static-glib2],
    AS_HELP_STRING([--with-static-glib2],[Build glib2 library]),
    [if test "$withval" = yes; then
        use_included_glib2=1
     fi])

AC_ARG_WITH([static-libffi],
    AS_HELP_STRING([--with-static-libffi],[Build libffi library]),
    [if test "$withval" = yes; then
        use_included_libffi=1
     fi])

AC_ARG_WITH([static-gettext],
    AS_HELP_STRING([--with-static-gettext],[Build gettext library]),
    [if test "$withval" = yes; then
        use_included_gettext=1
     fi])

AC_ARG_WITH([udt-include],
    AS_HELP_STRING([--with-udt-include=PATH],
        [Add -I@<:@PATH@:>@ to preprocessor flags]),
    [if test "$withval" != yes; then
        UDT_CPPFLAGS="-I$withval"
     fi])

AC_ARG_WITH([udt-lib],
    AS_HELP_STRING([--with-udt-lib=PATH],
        [Add -L@<:@PATH@:>@ to linker flags]),
    [if test "$withval" != yes; then
        UDT_LDFLAGS="-L$withval -ludt"
     else
        UDT_LDFLAGS="-ludt"
     fi],
    [UDT_LDFLAGS="-ludt"])


PKG_PROG_PKG_CONFIG
PKG_CONFIG="${PKG_CONFIG} --static"

if test X"$use_included_udt" = "X"; then
    AC_CHECK_HEADER([udt.h], [AC_DEFINE([HAVE_UDT_H], [1], [Define to 1 if you have udt.h])])
    AC_CHECK_HEADER([udt/udt.h], [AC_DEFINE([HAVE_UDT_UDT_H], [1], [Define to 1 if you have udt/udt.h])])
    if test x"$ac_cv_header_udt_h" = xno && \
       test x"$ac_cv_header_udt_udt_h" = xno; then
       use_included_udt=1
    fi
fi

if test X"$use_included_nice" = "X"; then
    PKG_CHECK_MODULES([NICE], [nice >= 0.0.12],[],[use_included_nice=1])
fi

UDT_DRIVER_PKG_CONFIG_PATH="${PKG_CONFIG_PATH}"
if test X"$use_included_nice" = X1; then
    LIBNICE_SUBDIR=libnice
    LIBNICE_PKG_CONFIG_PATH="\$(abs_top_builddir)/\$(LIBNICE_SUBDIR)\$(prefix)/lib/pkgconfig"
    UDT_DRIVER_PKG_CONFIG_PATH="${UDT_DRIVER_PKG_CONFIG_PATH}:${LIBNICE_PKG_CONFIG_PATH}"
    NICE_CFLAGS="\$\$(env PKG_CONFIG_PATH=\"\$(UDT_DRIVER_PKG_CONFIG_PATH)\" ${PKG_CONFIG} --define-variable=prefix=\"\$(abs_builddir)/libnice\$(prefix)\" --cflags nice)"
    NICE_LIBS="\$\$(env PKG_CONFIG_PATH=\"\$(UDT_DRIVER_PKG_CONFIG_PATH)\" ${PKG_CONFIG} --define-variable=prefix=\"\$(abs_builddir)/libnice\$(prefix)\" --libs nice)"

    if test X"$use_included_glib2" = "X"; then
        PKG_CHECK_MODULES([GLIB2], [glib-2.0 >= 2.30 gobject-2.0 >= 2.30 gthread-2.0 >= 2.30 gio-2.0 >= 2.30], [], [use_included_glib2=1])
    fi
fi

if test X"$use_included_glib2" = X1; then
    GLIB2_SUBDIR=glib2
    GLIB2_PKG_CONFIG_PATH="\$(abs_top_builddir)/\$(GLIB2_SUBDIR)/lib/pkgconfig"
    UDT_DRIVER_PKG_CONFIG_PATH="${UDT_DRIVER_PKG_CONFIG_PATH}:${GLIB2_PKG_CONFIG_PATH}"

    if test X"$use_included_libffi" = "X"; then
        PKG_CHECK_MODULES([LIBFFI], [libffi >= 3.0], [], [use_included_libffi=1])
    fi
    AC_CHECK_PROGS([GETTEXT], [gettext])
    if test X"$GETTEXT" = X""; then
        use_included_gettext=1
    fi
fi

if test X"$use_included_libffi" = X1; then
    LIBFFI_SUBDIR=libffi
    LIBFFI_PKG_CONFIG_PATH="\$(abs_top_builddir)/\$(LIBFFI_SUBDIR)/lib/pkgconfig"
    UDT_DRIVER_PKG_CONFIG_PATH="${UDT_DRIVER_PKG_CONFIG_PATH}:${LIBFFI_PKG_CONFIG_PATH}"
fi

if test X"$use_included_udt" = X1; then
    AC_DEFINE([HAVE_UDT_H], [1], [Define to 1 if you have udt.h])
    UDT_CPPFLAGS="-Iudt/udt4/src"
    UDT_LDFLAGS="-Ludt -ludt"
    UDT_SUBDIR="udt"
    udt_has_bind2=yes
else
    save_CXXFLAGS="$CXXFLAGS"
    save_LIBS="$LIBS"
    CXXFLAGS="$CXXFLAGS $UDT_CPPFLAGS"
    LIBS="$UDT_LDFLAGS $LIBS"

    # udt 4.11 renamed the 2 parameter bind() function to bind2().
    AC_MSG_CHECKING([UDT bind2() function])
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([
        #if HAVE_UDT_H
        #include <udt.h>
        #elif HAVE_UDT_UDT_H
        #include <udt/udt.h>
        #endif],
        [UDT::bind2(0,0);])],
        [udt_has_bind2=yes],
        [udt_has_bind2=no])
    CXXFLAGS="$save_CXXFLAGS"
    LIBS="$save_LIBS"
    AC_MSG_RESULT([$udt_has_bind2])
fi


if test x"$use_included_gettext" = x1; then
    GETTEXT_SUBDIR=gettext
    GETTEXT_PATH="\$(abs_top_builddir)/\$(GETTEXT_SUBDIR)/bin"
    GETTEXT_CPPFLAGS="-I\$(abs_top_builddir)/\$(GETTEXT_SUBDIR)/include"
    GETTEXT_LDFLAGS="-L\$(abs_top_builddir)/\$(GETTEXT_SUBDIR)/lib"
fi


if test "$udt_has_bind2" = yes; then
    AC_DEFINE([UDT_HAS_BIND2], [1], [Define to 1 if udt has bind() function])
fi

AC_CHECK_PROGS([GZIP], [gzip])
AC_CHECK_PROGS([XZ], [xz])
if test X"$XZ" = X && test X"$GZIP" != ""; then
    AC_MSG_CHECKING([if gzip can handle xz files])
    $GZIP -dc < $srcdir/empty.xz > /dev/null
    if test "$?" = 0; then
        XZ="$GZIP"
        result="yes"
    else
        result="no"
    fi
    AC_MSG_RESULT($result)
fi
AM_CONDITIONAL([XZ_WORKS], [test X"$XZ" != "X"])
AC_CHECK_PROGS([CURL], [curl])
AC_CHECK_PROGS([WGET], [wget])
if test x"$CURL" != x; then
    DOWNLOAD_TO_STDOUT="\$(CURL) -Ls"
elif test x"$WGET" != x; then
    DOWNLOAD_TO_STDOUT="\$(WGET) -O-"
elif test x"$use_included_gettext$use_included_udt$use_included_libffi$use_included_glib2$use_included_nice" != x; then
    DOWNLOAD_TO_STDOUT="echo 1>&2 Download into \$PWD; exit 1;#"
fi

AC_SUBST(DOWNLOAD_TO_STDOUT)
AC_SUBST(UDT_DRIVER_PKG_CONFIG_PATH)

AC_SUBST(UDT_SUBDIR)
AC_SUBST(UDT_CPPFLAGS)
AC_SUBST(UDT_LDFLAGS)

AC_SUBST(LIBNICE_SUBDIR)
AC_SUBST(LIBNICE_PKG_CONFIG_PATH)
AC_SUBST(NICE_CFLAGS)
AC_SUBST(NICE_LIBS)

AC_SUBST(GLIB2_SUBDIR)
AC_SUBST(GLIB2_PKG_CONFIG_PATH)

AC_SUBST(GETTEXT_SUBDIR)
AC_SUBST(GETTEXT_CPPFLAGS)
AC_SUBST(GETTEXT_LDFLAGS)
AC_SUBST(GETTEXT_PATH)

AC_SUBST(LIBFFI_SUBDIR)
AC_SUBST(LIBFFI_PKG_CONFIG_PATH)

AC_CONFIG_FILES(
        globus-xio-udt-driver.pc
        globus-xio-udt-driver-uninstalled.pc
        gettext/Makefile
        glib2/Makefile
        libffi/Makefile
        libnice/Makefile
        udt/Makefile
	Makefile
        version.h
)
AC_OUTPUT
