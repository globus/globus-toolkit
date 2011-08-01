include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

doc_DATA = GLOBUS_LICENSE

include_HEADERS= \
	globus_gram_jobmanager_callout_error.h

lib_LTLIBRARIES = libglobus_gram_job_manager_callout_error.la

libglobus_gram_job_manager_callout_error_la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_gram_job_manager_callout_error_la_SOURCES = \
	globus_i_gram_jobmanager_callout_error.c \
	globus_gram_jobmanager_callout_error.h
libglobus_gram_job_manager_callout_error_la_LDFLAGS = \
	@GPT_LDFLAGS@

EXTRA_DIST=$(doc_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
