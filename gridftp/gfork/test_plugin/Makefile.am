include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

lib_LTLIBRARIES = libglobus_gfork_test_plugin_$(GLOBUS_FLAVOR_NAME).la

libglobus_gfork_test_plugin___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_gfork_test_plugin___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_gfork_test_plugin.c
libglobus_gfork_test_plugin___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib


Test_Sources = gfork_test_ap.c

bin_PROGRAMS= \
    gfork-test-ap

gfork_test_ap_CFLAGS = $(GPT_CFLAGS)
gfork_test_ap_SOURCES = $(Test_Sources)
gfork_test_ap_LDFLAGS = $(GPT_LDFLAGS)
gfork_test_ap_LDADD = \
    $(GPT_PGM_LINKS)


EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
