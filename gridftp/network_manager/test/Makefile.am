AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) \
        -I$(top_srcdir) \
        -I$(top_builddir) \
        -I$(top_srcdir)/attr \
        -I$(srcdir) \
        -I$(top_srcdir)/xio_driver \
        -I$(top_srcdir)/python \
        -I$(top_srcdir)/context
LDADD = $(top_builddir)/libglobus_net_manager.la $(PACKAGE_DEP_LIBS)

check_LTLIBRARIES = \
    libglobus_net_manager_null_module.la

libglobus_net_manager_null_module_la_SOURCES = \
        globus_net_manager_null.c \
        globus_net_manager_null.h

libglobus_net_manager_null_module_la_LDFLAGS = \
        -rpath $(abs_builddir) \
        -module \
        -avoid-version \
        -no-undefined
libglobus_net_manager_null_module_la_LIBADD = $(LDADD)

check_PROGRAMS = \
    activate_deactivate_test \
    attr_test \
    context_test \
    xio_driver_cntl_test \
    xio_driver_test

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
    -dlopen $(builddir)/libglobus_net_manager_null_module.la
