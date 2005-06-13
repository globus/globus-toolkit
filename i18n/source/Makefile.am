include $(top_srcdir)/globus_automake_pre

SUBDIRS= \
        pkgdata 

Sources= \
	globus_i18n.c \
	globus_i18n.h

bin_SCRIPTS= \
	 globus-i18n-resource-create


flavorinclude_HEADERS = \
	globus_i18n.h


lib_LTLIBRARIES = libglobus_i18n_$(GLOBUS_FLAVOR_NAME).la
bin_PROGRAMS = globus-i18n-resource-init

EXTRA_DIST = globus-i18n-resource-create

INCLUDES = @GPT_INCLUDES@

libglobus_i18n___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@

libglobus_i18n___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_i18n___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@ -module 

globus_i18n_resource_init_SOURCES = globus_i18n_resource_init.c
globus_i18n_resource_init_LDFLAGS = @GPT_LDFLAGS@

globus_i18n_resource_init_LDADD = @GPT_PGM_LINKS@

include $(top_srcdir)/globus_automake_post
