include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

include_HEADERS = \
    globus_xio_gsi.h

INCLUDES = $(GPT_INCLUDES)
doc_DATA = GLOBUS_LICENSE

lib_LTLIBRARIES = libglobus_xio_gsi_driver.la

libglobus_xio_gsi_driver_la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_xio_gsi_driver_la_SOURCES = \
	globus_i_xio_gsi.h  globus_xio_gsi.h globus_xio_gsi.c
libglobus_xio_gsi_driver_la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in $(doc_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
