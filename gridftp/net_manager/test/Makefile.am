AM_CPPFLAGS = \
        -I$(top_srcdir) \
        -I$(top_builddir) \
        -I$(top_srcdir)/attr \
        -I$(srcdir) \
        -I$(top_srcdir)/xio_driver \
        -I$(top_srcdir)/python \
        -I$(top_srcdir)/context \
        $(PACKAGE_DEP_CFLAGS)
LDADD = $(top_builddir)/libglobus_net_manager.la $(PACKAGE_DEP_LIBS)

check_LTLIBRARIES = \
    libglobus_net_manager_null.la

libglobus_net_manager_null_la_SOURCES = \
        globus_net_manager_null.c \
        globus_net_manager_null.h

libglobus_net_manager_null_la_LDFLAGS = \
        -rpath $(abs_builddir) \
        -module \
        -avoid-version \
        -no-undefined
libglobus_net_manager_null_la_LIBADD = $(LDADD)

check_PROGRAMS = \
    activate_deactivate_test \
    attr_test \
    context_test \
    xio_driver_cntl_test \
    xio_driver_test

activate_deactivate_test_SOURCES = activate_deactivate_test.c globus_test_tap.h
attr_test_SOURCES = attr_test.c globus_test_tap.h
context_test_SOURCES = context_test.c globus_test_tap.h
xio_driver_cntl_test_SOURCES = xio_driver_cntl_test.c globus_test_tap.h
xio_driver_cntl_test_LDADD = \
    -dlpreopen ../xio_driver/libglobus_xio_net_manager_driver.la \
    -dlpreopen libglobus_net_manager_null.la $(LDADD) $(LIBLTDL)
xio_driver_test_SOURCES = xio_driver_test.c globus_test_tap.h
xio_driver_test_LDADD = \
    -dlpreopen ../xio_driver/libglobus_xio_net_manager_driver.la \
    -dlpreopen libglobus_net_manager_null.la $(LDADD) $(LIBLTDL)

if ENABLE_PYTHON
check_PROGRAMS += python_test
TESTS_ENVIRONMENT = export \
    PYTHONPATH="$${PYTHONPATH:+$$PYTHONPATH:}$(srcdir)";
endif

EXTRA_DIST = \
             port_minus_one.py \
             port_plus_one.py \
             return_function_called_module.py \
             test_module.py

TESTS = $(check_PROGRAMS)
LOG_COMPILER = $(LIBTOOL) --mode=execute \
    -dlopen $(top_builddir)/libglobus_net_manager.la \
    -dlopen $(top_builddir)/xio_driver/libglobus_xio_net_manager_driver.la \
    -dlopen $(builddir)/libglobus_net_manager_null.la $(VALGRIND)
