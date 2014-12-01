AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir) -I$(top_builddir) -I$(top_srcdir)/attr -I$(srcdir) -I$(top_srcdir)/xio_driver
LDADD = $(top_builddir)/libglobus_net_manager.la $(PACKAGE_DEP_LIBS)

check_PROGRAMS = attr_test xio_driver_cntl_test
TESTS = $(check_PROGRAMS)
LOG_COMPILER = $(LIBTOOL) --mode=execute \
    -dlopen $(top_builddir)/libglobus_net_manager.la \
    -dlopen $(top_builddir)/xio_driver/libglobus_xio_net_manager_driver.la

