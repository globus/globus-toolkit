include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

QUANTA_PATH=@QUANTA_PATH@

SUBDIRS = \
	pkgdata \
	doxygen

flavorinclude_HEADERS = \
    globus_xio_quanta_rbudp.h

INCLUDES = $(GPT_INCLUDES) -I $(QUANTA_PATH)/include

lib_LTLIBRARIES = libglobus_xio_quanta_rbudp_driver_$(GLOBUS_FLAVOR_NAME).la

libglobus_xio_quanta_rbudp_driver___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@ $(QUANTA_PATH)/lib64/libquanta_64.a
libglobus_xio_quanta_rbudp_driver___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_xio_quanta_rbudp.cpp
libglobus_xio_quanta_rbudp_driver___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
