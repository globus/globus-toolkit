include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

flavorinclude_HEADERS = \
    globus_xio_token_bucket_driver.h

INCLUDES = $(GPT_INCLUDES)

lib_LTLIBRARIES = libglobus_xio_token_bucket_driver_$(GLOBUS_FLAVOR_NAME).la

libglobus_xio_token_bucket_driver___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_xio_token_bucket_driver___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_xio_token_bucket_driver.c
libglobus_xio_token_bucket_driver___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
