SUBDIRS = pkgdata doxygen

LIBZ_PATH=@LIBZ_PATH@

flavorinclude_HEADERS = globus_xio_blockz.h
lib_LTLIBRARIES = libglobus_xio_blockz_driver.la

AM_CPPFLAGS = $(GPT_INCLUDES) -I$(LIBZ_PATH)/include

libglobus_xio_blockz_driver_la_LIBADD = \
	$(GPT_LIB_LINKS) $(LIBZ_PATH)/lib/liblzo2.la
libglobus_xio_blockz_driver_la_SOURCES = \
	globus_xio_blockz.c
libglobus_xio_blockz_driver_la_LDFLAGS = \
	$(GPT_LDFLAGS) -module \
        -rpath $(GLOBUS_LOCATION)/lib -rpath $(LIBZ_PATH)/lib

EXTRA_DIST = dirt.sh version.h.in
