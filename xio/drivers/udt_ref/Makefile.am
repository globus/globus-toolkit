include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

UDT_PATH=@UDT_PATH@

SUBDIRS = \
	pkgdata \
	doxygen

include_HEADERS = \
    globus_xio_udt_ref.h

INCLUDES = $(GPT_INCLUDES) 

lib_LTLIBRARIES = libglobus_xio_udt_driver.la

libglobus_xio_udt_driver_la_LIBADD = \
	@GPT_LIB_LINKS@ 
libglobus_xio_udt_driver_la_SOURCES = \
	globus_xio_udt_ref.cpp
libglobus_xio_udt_driver_la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
