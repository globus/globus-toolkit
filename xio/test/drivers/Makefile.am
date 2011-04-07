include $(top_srcdir)/globus_automake_pre

SUBDIRS = 

Sources = \
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

include_HEADERS = \
	globus_xio_stack_driver.h \
	globus_xio_null_pass.h \
	globus_xio_bounce.h \
	globus_xio_test_transport.h \
	globus_xio_op.h \
	globus_xio_debug.h \
	globus_xio_verify.h \
	globus_xio_smtp.h \
	globus_xio_null.h

noinst_HEADERS = \
        globus_i_xio_test_drivers.h

INCLUDES = -I$(top_srcdir) $(GPT_INCLUDES)

lib_LTLIBRARIES = libglobus_xio_test_drivers.la

libglobus_xio_test_drivers_la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_xio_test_drivers_la_SOURCES = \
	$(Sources)
libglobus_xio_test_drivers_la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath ${libdir}

include $(top_srcdir)/globus_automake_post
