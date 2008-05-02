include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	doxygen \
	pkgdata 

Sources= seg_job_manager_module.c

AM_CPPFLAGS = $(GPT_INCLUDES) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_job_manager_$(GLOBUS_FLAVOR_NAME).la

libglobus_seg_job_manager___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_seg_job_manager___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
		$(GPT_LDFLAGS) -module
libglobus_seg_job_manager___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)
sbin_SCRIPTS = globus-job-manager-event-generator

EXTRA_DIST= version.h.in $(sbin_SCRIPTS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

