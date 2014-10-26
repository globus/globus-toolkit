AC_PREREQ([2.60])

AC_INIT([globus_ftp_client],[8.13],[https://globus.atlassian.net/])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [6])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 15, globus-ftp-control >= 4, globus-gsi-callback >= 4, globus-gsi-credential >= 5, globus-gsi-sysconfig >= 5, globus-gssapi-gsi >= 10, globus-xio >= 3, globus-xio-popen-driver >= 2, openssl >= 0.9.8"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign parallel-tests 1.11 tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)
AC_CANONICAL_HOST
AM_CONDITIONAL([CYGPATH_W_DEFINED], [
    case $host in
        *mingw32*)
        test x"$CYGPATH_W" != x;
        ;;
        *)
        false
        ;;
    esac])

AM_CONDITIONAL([TARGET_MINGW], [
    case $host in
        *mingw*)
            true
            ;;
        *)
            false
            ;;
    esac])

AM_CONDITIONAL([TARGET_HURD], [
    case $host in
        *-linux*|*-k*bsd-gnu*)
            false
            ;;
        *-gnu*)
            true
            ;;
        *)
            false
            ;;
    esac])

GRIDFTP_SERVER_PATH=`pkg-config --variable=path globus-gridftp-server`
AC_SUBST(GRIDFTP_SERVER_PATH)

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)
PKG_CHECK_EXISTS([globus-xio-gsi-driver >= 2], [
    GSI_DRIVER_CFLAGS="$($PKG_CONFIG --cflags globus-xio-gsi-driver)"
    GSI_DRIVER_LIBS="$($PKG_CONFIG --variable=dlopen globus-xio-gsi-driver)"])
if test x"$GSI_DRIVER_LIBS" = x; then
    DLPREOPEN_FORCE="-dlpreopen force"
fi
PKG_CHECK_EXISTS([globus-xio-pipe-driver >= 2], [
    PIPE_DRIVER_LIBS="$($PKG_CONFIG --variable=dlopen globus-xio-pipe-driver)"])
if test x"$PIPE_DRIVER_LIBS" = x; then
    DLPREOPEN_FORCE="-dlpreopen force"
fi
AC_SUBST([GSI_DRIVER_CFLAGS])
AC_SUBST([GSI_DRIVER_LIBS])
AC_SUBST([PIPE_DRIVER_LIBS])
AC_SUBST([DLPREOPEN_FORCE])

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])
AC_CONFIG_FILES(
        globus-ftp-client-uninstalled.pc
        globus-ftp-client.pc
        gridftp-ssh
        Makefile
        Doxyfile
        test/Makefile
	version.h
        test/openssl.cnf)
AC_OUTPUT
