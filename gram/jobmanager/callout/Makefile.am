include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

# Extra directories we install files into
confdir = $(datadir)/$(PACKAGE)

Data = \
	gsi-authz.conf

conf_DATA = $(Data)


EXTRA_DIST = $(Data)

INCLUDES += $(GPT_INCLUDES)

lib_LTLIBRARIES = libglobus_gram_jobmanager_callout_$(GLOBUS_FLAVOR_NAME).la

libglobus_gram_jobmanager_callout___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_gram_jobmanager_callout___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_gram_jobmanager_callout.c
libglobus_gram_jobmanager_callout___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
