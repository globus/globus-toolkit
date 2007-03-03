include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

lib_LTLIBRARIES = libglobus_gfs_acl_example_$(GLOBUS_FLAVOR_NAME).la

libglobus_gfs_acl_example___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_gfs_acl_example___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_i_gfs_acl_example.c
libglobus_gfs_acl_example___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
