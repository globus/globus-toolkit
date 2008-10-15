include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= pkgdata 

Sources= seg_fake_module.c

AM_CPPFLAGS = $(GPT_INCLUDES) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_fake_$(GLOBUS_FLAVOR_NAME).la

libglobus_seg_fake___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_seg_fake___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS) -module
libglobus_seg_fake___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

EXTRA_DIST= version.h.in pkgdata/MyFilelists.pm

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

