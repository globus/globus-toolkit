include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

flavorinclude_HEADERS = \
    gridftp_server_info.h

Sources= \
    gridftp_server_info.c


INCLUDES = $(GPT_INCLUDES)
LDFLAGS =  -L $(GLOBUS_LOCATION)/lib/globus_service_modules/wsrf/services

lib_LTLIBRARIES = libgridftp_server_info_$(GLOBUS_FLAVOR_NAME).la

libgridftp_server_info___GLOBUS_FLAVOR_NAME__la_CFLAGS = $(GPT_CFLAGS)

libgridftp_server_info___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@
libgridftp_server_info___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libgridftp_server_info___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
 -L $(GLOBUS_LOCATION)/lib/globus_service_modules/wsrf/services \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
