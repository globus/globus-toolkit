AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir) -I$(top_builddir) -I$(top_srcdir)/attr -I$(srcdir) -I$(top_srcdir)/xio_driver
LDADD = $(top_builddir)/libglobus_net_manager.la $(PACKAGE_DEP_LIBS)

check_LTLIBRARIES = \
    libglobus_net_manager_null_module.la \
    libglobus_net_manager_port_plus_one_module.la

libglobus_net_manager_null_module_la_SOURCES = \
        globus_net_manager_null.c \
        globus_net_manager_null.h
libglobus_net_manager_port_plus_one_module_la_SOURCES = \
        globus_net_manager_port_plus_one.c \
        globus_net_manager_port_plus_one.h

check_PROGRAMS = \
    activate_deactivate_test \
    attr_test \
    xio_driver_cntl_test \
    xio_driver_test

TESTS = $(check_PROGRAMS)
LOG_COMPILER = $(LIBTOOL) --mode=execute \
    -dlopen $(top_builddir)/libglobus_net_manager.la \
    -dlopen $(top_builddir)/xio_driver/libglobus_xio_net_manager_driver.la \
    -dlopen $(builddir)/libglobus_net_manager_null_module.la \
    -dlopen $(builddir)/libglobus_net_manager_port_plus_one_module.la

