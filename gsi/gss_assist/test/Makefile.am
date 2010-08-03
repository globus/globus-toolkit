include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata

Scripts = \
	TESTS.pl \
	gss-assist-impexp-test.pl \
	gss-assist-auth-test.pl \
	gss-assist-gridmap-test.pl \
        gridmap-test.pl \
        gridmap-tools-test.pl

Data = grid-mapfile \
       gridmap.empty \
       gridmap.long_line \
       gridmap.multiple-dns \
       gridmap.multiple_lines \
       gridmap.no-local-uid \
       gridmap.no-local-uid2

INCLUDES = $(GPT_INCLUDES)

test_SCRIPTS = $(Scripts)

test_DATA = $(Data)

test_PROGRAMS = \
	gss-assist-auth-init \
	gss-assist-auth-accept \
	gss-assist-impexp-init \
	gss-assist-impexp-accept \
	gss-assist-gridmap \
        gridmap-test \
        gridmap-userok

LDFLAGS += $(GPT_LDFLAGS)
LDADD = $(GPT_PGM_LINKS)

gss_assist_auth_init_SOURCES = gss_assist_auth_init.c
gss_assist_auth_accept_SOURCES = gss_assist_auth_accept.c
gss_assist_impexp_init_SOURCES = gss_assist_impexp_init.c
gss_assist_impexp_accept_SOURCES = gss_assist_impexp_accept.c
gss_assist_gridmap_SOURCES = gss_assist_gridmap.c
gridmap_test_SOURCES = gridmap_test.c
gridmap_userok_SOURCES = gridmap_userok.c

EXTRA_DIST = $(Data) \
	TESTS.pl.in \
	gss-assist-impexp-test.pl \
	gss-assist-auth-test.pl \
	gss-assist-gridmap-test.pl \
        gridmap-test.pl \
        gridmap-tools-test.pl

TESTS.pl: $(srcdir)/TESTS.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = TESTS.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
