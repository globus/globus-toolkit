include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

UDT_PATH=@UDT_PATH@

SUBDIRS = \
	pkgdata \
	doxygen

flavorinclude_HEADERS = \
    globus_xio_udt_ref.h

INCLUDES = $(GPT_INCLUDES) -I $(UDT_PATH)/src

lib_LTLIBRARIES = libglobus_xio_udt_ref_driver_$(GLOBUS_FLAVOR_NAME).la

libglobus_xio_udt_ref_driver___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@ $(UDT_PATH)/src/libudt.a 
libglobus_xio_udt_ref_driver___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_xio_udt_ref.c
libglobus_xio_udt_ref_driver___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
