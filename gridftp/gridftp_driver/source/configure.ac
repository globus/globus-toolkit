AC_PREREQ([2.60])

AC_INIT([globus_xio_gridftp_driver],[2.2],[http://jira.globus.org])
AC_SUBST([MAJOR_VERSION], [${PACKAGE_VERSION%%.*}])
AC_SUBST([MINOR_VERSION], [${PACKAGE_VERSION##*.}])
AC_SUBST([AGE_VERSION], [1])
AC_SUBST([PACKAGE_DEPS], ["globus-common >= 14, globus-xio >= 3, globus-ftp-client >= 7, globus-xio-gsi-driver >= 2"])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign parallel-tests tar-pax])
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
        globus-xio-gridftp-driver-uninstalled.pc
        globus-xio-gridftp-driver.pc
        Makefile
        Doxyfile
	version.h
        test/Makefile)
AC_OUTPUT
