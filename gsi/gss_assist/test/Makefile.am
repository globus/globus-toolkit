include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata

Sources = \
	gss_assist_auth_init.c \
	gss_assist_auth_accept.c \
	gss_assist_impexp_init.c \
	gss_assist_impexp_accept.c \
	gss_assist_gridmap.c

Scripts = \
	TESTS.pl \
	gss-assist-run-tests.pl \
	gss-assist-impexp-test.pl \
	gss-assist-auth-test.pl \
	gss-assist-gridmap-test.pl

Data = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem \
	grid-mapfile

INCLUDES = $(GPT_INCLUDES)

test_SCRIPTS = $(Scripts)

test_DATA = $(Data)

test_PROGRAMS = \
	gss-assist-auth-init \
	gss-assist-auth-accept \
	gss-assist-impexp-init \
	gss-assist-impexp-accept \
	gss-assist-gridmap

gss_assist_auth_init_SOURCES = gss_assist_auth_init.c

gss_assist_auth_init_LDFLAGS = $(GPT_LDFLAGS)

gss_assist_auth_init_LDADD = $(GPT_PGM_LINKS)

gss_assist_auth_accept_SOURCES = gss_assist_auth_accept.c

gss_assist_auth_accept_LDFLAGS = $(GPT_LDFLAGS)

gss_assist_auth_accept_LDADD = $(GPT_PGM_LINKS)

gss_assist_impexp_init_SOURCES = gss_assist_impexp_init.c

gss_assist_impexp_init_LDFLAGS = $(GPT_LDFLAGS)

gss_assist_impexp_init_LDADD = $(GPT_PGM_LINKS)

gss_assist_impexp_accept_SOURCES = gss_assist_impexp_accept.c

gss_assist_impexp_accept_LDFLAGS = $(GPT_LDFLAGS)

gss_assist_impexp_accept_LDADD = $(GPT_PGM_LINKS)

gss_assist_gridmap_SOURCES = gss_assist_gridmap.c

gss_assist_gridmap_LDFLAGS = $(GPT_LDFLAGS)

gss_assist_gridmap_LDADD = $(GPT_PGM_LINKS)

EXTRA_DIST = $(Scripts) $(Data)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
