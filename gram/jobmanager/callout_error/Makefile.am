include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

flavorinclude_HEADERS= \
	globus_gram_jobmanager_callout_error.h

lib_LTLIBRARIES = libglobus_gram_job_manager_callout_error_$(GLOBUS_FLAVOR_NAME).la

libglobus_gram_job_manager_callout_error___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_gram_job_manager_callout_error___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_i_gram_jobmanager_callout_error.c \
	globus_gram_jobmanager_callout_error.h
libglobus_gram_job_manager_callout_error___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@

EXTRA_DIST=

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
