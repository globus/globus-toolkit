include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	authtest.c

Callout_sources = authz_test_callout.c

EXTRA_DIST=

INCLUDES = $(GPT_INCLUDES)

authtest_SOURCES = authtest.c
authtest_LDFLAGS = $(GPT_LDFLAGS)
authtest_LDADD = $(GPT_PGM_LINKS)


authz_cred_test_SOURCES = authz_cred_test.c gssapi_test_utils.c gssapi_test_utils.h
authz_cred_test_LDFLAGS = $(GPT_LDFLAGS)
authz_cred_test_LDADD = $(GPT_PGM_LINKS)

lib_LTLIBRARIES = libglobus_authz_test_callout_$(GLOBUS_FLAVOR_NAME).la

libglobus_authz_test_callout___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Callout_sources)

libglobus_authz_test_callout___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libglobus_authz_test_callout___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	$(GPT_LDFLAGS) -module -rpath $(GLOBUS_LOCATION)


test_PROGRAMS=authtest  authz_cred_test

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
