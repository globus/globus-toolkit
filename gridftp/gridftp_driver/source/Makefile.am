include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

doc_DATA = GLOBUS_LICENSE

SUBDIRS = \
	pkgdata \
	doxygen

include_HEADERS = \
    globus_xio_gridftp_driver.h

INCLUDES = $(GPT_INCLUDES)

lib_LTLIBRARIES = libglobus_xio_gridftp_driver.la

libglobus_xio_gridftp_driver_la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_xio_gridftp_driver_la_SOURCES = \
	globus_xio_gridftp_driver.c
libglobus_xio_gridftp_driver_la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in $(doc_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
