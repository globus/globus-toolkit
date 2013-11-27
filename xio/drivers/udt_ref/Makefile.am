SUBDIRS = pkgdata doxygen

include_HEADERS = globus_xio_udt_ref.h
doc_DATA = GLOBUS_LICENSE
lib_LTLIBRARIES = libglobus_xio_udt_driver.la

AM_CPPFLAGS = $(GPT_INCLUDES) $(UDT_CFLAGS) $(NICE_CFLAGS) $(GLIB_CFLAGS)

libglobus_xio_udt_driver_la_LIBADD = \
        $(GPT_LIB_LINKS) $(UDT_LIBS) $(NICE_LIBS) $(GLIB_LIBS) -lstdc++ 
libglobus_xio_udt_driver_la_SOURCES = \
        ice.c ice.h globus_xio_udt_ref.cpp 
libglobus_xio_udt_driver_la_LDFLAGS = \
        $(GPT_LDFLAGS) -module -rpath $(libdir)


EXTRA_DIST = dirt.sh version.h.in $(doc_DATA)
