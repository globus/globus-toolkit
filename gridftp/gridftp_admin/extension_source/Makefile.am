include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

flavorinclude_HEADERS = \
    gridftp_admin.h

Sources= \
    gridftp_admin.c     \
    resource_setup.c


INCLUDES = $(GPT_INCLUDES)
LDFLAGS =  -L $(GLOBUS_LOCATION)/lib/globus_service_modules/wsrf/services

lib_LTLIBRARIES = libgridftp_admin.la

libgridftp_admin_la_CFLAGS = $(GPT_CFLAGS)

libgridftp_admin_la_LIBADD = \
	@GPT_LIB_LINKS@
libgridftp_admin_la_SOURCES = $(Sources)
libgridftp_admin_la_LDFLAGS = \
 -L $(GLOBUS_LOCATION)/lib/globus_service_modules/wsrf/services \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
