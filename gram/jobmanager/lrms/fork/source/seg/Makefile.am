include $(top_srcdir)/globus_automake_pre

AM_CPPFLAGS = $(GPT_INCLUDES) -I.. -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_fork.la

libglobus_seg_fork_la_SOURCES = seg_fork_module.c
libglobus_seg_fork_la_LDFLAGS = $(GPT_LDFLAGS) -module
libglobus_seg_fork_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
