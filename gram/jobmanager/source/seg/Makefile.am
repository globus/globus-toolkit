include $(top_srcdir)/globus_automake_pre

AM_CPPFLAGS = $(GPT_INCLUDES) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_job_manager.la

libglobus_seg_job_manager_la_SOURCES = $(Sources)
libglobus_seg_job_manager_la_LDFLAGS = $(GPT_LDFLAGS) -module
libglobus_seg_job_manager_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
