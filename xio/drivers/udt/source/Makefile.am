SUBDIRS = $(LIBFFI_SUBDIR) $(GETTEXT_SUBDIR) $(GLIB2_SUBDIR) $(LIBNICE_SUBDIR) $(UDT_SUBDIR) .
include_HEADERS = globus_xio_udt_ref.h
doc_DATA = GLOBUS_LICENSE
lib_LTLIBRARIES = libglobus_xio_udt_driver.la

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) $(UDT_CPPFLAGS) $(NICE_CFLAGS) $(GLIB_CFLAGS)

libglobus_xio_udt_driver_la_LIBADD = \
        $(GPT_LIB_LINKS) $(UDT_LDFLAGS) $(NICE_LIBS) $(GLIB_LIBS) -lstdc++ 
libglobus_xio_udt_driver_la_SOURCES = \
        globus_xio_udt_ref.cpp  \
        globus_xio_udt_ref.h  \
	ice.c ice.h
libglobus_xio_udt_driver_la_LDFLAGS = \
        $(UDT_LIBS) -module -rpath $(libdir)

EXTRA_DIST = dirt.sh version.h.in $(doc_DATA) empty.xz
