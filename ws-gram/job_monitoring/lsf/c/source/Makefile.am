include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top


SUBDIRS= \
	doxygen \
	pkgdata 

Sources= seg_lsf_module.c

AM_CPPFLAGS = $(GPT_INCLUDES) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_lsf.la

libglobus_seg_lsf_la_SOURCES = $(Sources)
libglobus_seg_lsf_la_LDFLAGS = $(GPT_LDFLAGS) -module
libglobus_seg_lsf_la_LIBADD = $(GPT_LIB_LINKS)

EXTRA_DIST= version.h.in pkgdata/MyFilelists.pm

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

