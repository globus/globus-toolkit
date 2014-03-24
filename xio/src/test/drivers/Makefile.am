noinst_HEADERS = \
	globus_xio_stack_driver.h \
	globus_xio_null_pass.h \
	globus_xio_bounce.h \
	globus_xio_test_transport.h \
	globus_xio_op.h \
	globus_xio_debug.h \
	globus_xio_verify.h \
	globus_xio_smtp.h \
	globus_xio_null.h \
        globus_i_xio_test_drivers.h

check_LTLIBRARIES = libglobus_xio_test_drivers.la

AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(srcdir) $(PACKAGE_DEP_CFLAGS) -DGLOBUS_BUILTIN=1

libglobus_xio_test_drivers_la_SOURCES = \
	globus_xio_test_drivers.c \
	globus_xio_null_pass.c \
	globus_xio_bounce.c \
	globus_xio_test_transport.c \
	globus_xio_op.c \
	globus_xio_debug.c \
	globus_xio_verify.c \
	globus_xio_smtp.c \
	globus_xio_null.c \
	globus_xio_stack_driver.c
libglobus_xio_test_drivers_la_LDFLAGS = \
	$(PACKAGE_DEP_LIBS) \
	-no-undefined -module \
	-avoid-version \
	-rpath $(libdir) \
	$(top_builddir)/libglobus_xio.la
