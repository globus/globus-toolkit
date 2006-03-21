include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

NETLOGGER_PATH=@NETLOGGER_PATH@

SUBDIRS = \
	pkgdata \
	doxygen

flavorinclude_HEADERS = \
    globus_xio_netlogger.h

INCLUDES = $(GPT_INCLUDES) -I $(NETLOGGER_PATH)/include

lib_LTLIBRARIES = libglobus_xio_netlogger_driver_$(GLOBUS_FLAVOR_NAME).la

libglobus_xio_netlogger_driver___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@ $(NETLOGGER_PATH)/lib/libnllite.a
libglobus_xio_netlogger_driver___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_xio_netlogger.c
libglobus_xio_netlogger_driver___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
