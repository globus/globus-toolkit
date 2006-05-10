include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

EXTRA_DIST = 

lib_LTLIBRARIES = libglobus_gram_job_manager_callout_$(GLOBUS_FLAVOR_NAME).la

libglobus_gram_job_manager_callout___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_gram_job_manager_callout___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_gram_jobmanager_callout.c
libglobus_gram_job_manager_callout___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
