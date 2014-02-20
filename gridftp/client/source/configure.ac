AC_PREREQ([2.60])

AC_INIT([globus_ftp_client],[8.5],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [6])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-ftp-control >= 4, globus-gsi-callback >= 4, globus-gsi-credential >= 5, globus-gsi-sysconfig >= 5, globus-gssapi-gsi >= 10, globus-xio >= 3, globus-xio-popen-driver >= 2"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign parallel-tests 1.11 tar-pax])
LT_INIT([dlopen win32-dll])

m4_include([dirt.sh])
AC_SUBST(DIRT_TIMESTAMP)
AC_SUBST(DIRT_BRANCH_ID)

GSI_DRIVER_LIBDIR=`pkg-config --variable=libdir globus-xio-gsi-driver`
GSI_DRIVER=""
for ext in .la .so .dylib .a; do
    if test -r $GSI_DRIVER_LIBDIR/libglobus_xio_gsi_driver${ext}; then
        GSI_DRIVER=$GSI_DRIVER_LIBDIR/libglobus_xio_gsi_driver${ext} 
        break
    fi
done

AC_SUBST(GLOBUS_XIO_GSI_DRIVER, $GSI_DRIVER)

PIPE_DRIVER_LIBDIR=`pkg-config --variable=libdir globus-xio-pipe-driver`
PIPE_DRIVER=""
for ext in .la .so .dylib .a; do
    if test -r $PIPE_DRIVER_LIBDIR/libglobus_xio_pipe_driver${ext}; then
        PIPE_DRIVER=$PIPE_DRIVER_LIBDIR/libglobus_xio_pipe_driver${ext} 
        break
    fi
done

AC_SUBST(GLOBUS_XIO_PIPE_DRIVER, $PIPE_DRIVER)

GRIDFTP_SBINDIR=`pkg-config --variable=sbindir globus-gridftp-server`
AC_SUBST(GRIDFTP_SBINDIR, $GRIDFTP_SBINDIR)
AM_CONDITIONAL([GRIDFTP_TESTS],
  [ test "$GSI_DRIVER" != "" && \
    test "$PIPE_DRIVER" != "" && \
    test -d "$GRIDFTP_SBINDIR"])

PKG_CHECK_MODULES([PACKAGE_DEP], $PACKAGE_DEPS)

AC_PATH_PROGS([DOXYGEN], doxygen)

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])
AC_CONFIG_FILES(
        globus-ftp-client-uninstalled.pc
        globus-ftp-client.pc
        gridftp-ssh
        Makefile
        Doxyfile
        test/Makefile
	version.h)
AC_OUTPUT
