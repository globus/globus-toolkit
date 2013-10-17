include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
        pkgdata \
        doxygen

include_HEADERS = \
    globus_xio_udt_ref.h

AM_CPPFLAGS = $(GPT_INCLUDES) $(UDT_CFLAGS) $(NICE_CFLAGS) $(GLIB_CFLAGS)

lib_LTLIBRARIES = libglobus_xio_udt_driver.la
libglobus_xio_udt_driver_la_LIBADD = \
        @GPT_LIB_LINKS@ $(UDT_LIBS) $(NICE_LIBS) $(GLIB_LIBS) -lstdc++ 
libglobus_xio_udt_driver_la_SOURCES = \
        ice.c ice.h globus_xio_udt_ref.cpp 
libglobus_xio_udt_driver_la_LDFLAGS = \
        @GPT_LDFLAGS@ -module -rpath $(libdir)

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = version.h.in $(doc_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
