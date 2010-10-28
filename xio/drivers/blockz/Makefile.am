include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

LIBZ_PATH=@LIBZ_PATH@

SUBDIRS = \
	pkgdata \
	doxygen

flavorinclude_HEADERS = \
    globus_xio_blockz.h

INCLUDES = $(GPT_INCLUDES) -I $(LIBZ_PATH)/include

lib_LTLIBRARIES = libglobus_xio_blockz_driver.la

libglobus_xio_blockz_driver_la_LIBADD = \
	@GPT_LIB_LINKS@ $(LIBZ_PATH)/lib/liblzo2.la
libglobus_xio_blockz_driver_la_SOURCES = \
	globus_xio_blockz.c
libglobus_xio_blockz_driver_la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib -rpath $(LIBZ_PATH)/lib


EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
