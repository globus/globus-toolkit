noinst_LTLIBRARIES = libglobus_rvf.la
sbin_PROGRAMS = globus-rvf-check
sbin_SCRIPTS = globus-rvf-edit
man_MANS = globus-rvf-edit.8 globus-rvf-check.8

libglobus_rvf_la_CPPFLAGS = $(GPT_CFLAGS) -I$(top_srcdir)
libglobus_rvf_la_SOURCES = \
    globus_i_rvf.tab.h globus_i_rvf.tab.c \
    globus_i_rvf.h globus_rvf_parser.h \
    globus_i_rvf_scanner.h lex.globus_i_rvf_.c

globus_rvf_check_SOURCES=globus_rvf_check.c
globus_rvf_check_LDADD=libglobus_rvf.la -lglobus_rsl_assist -lglobus_rsl -lglobus_common

if REBUILD_PARSER
# developed with bison 2.3 and uses some bison-specific features
$(srcdir)/globus_i_rvf.tab.h $(srcdir)/globus_i_rvf.tab.c: $(srcdir)/rvf.y
	rm -f $(srcdir)/globus_i_rvf.tab.h $(srcdir)/globus_i_rvf.tab.c
	bison -d -b $(srcdir)/globus_i_rvf -p globus_i_rvf_ $(srcdir)/rvf.y
endif

if REBUILD_SCANNER
# developed with flex 2.5.35 and uses flex-specific features
$(srcdir)/lex.globus_i_rvf_.c $(srcdir)/globus_i_rvf_scanner.h: $(srcdir)/rvf.l
	rm -f $(srcdir)/globus_i_rvf_scanner.h $(srcdir)/lex.globus_i_rvf_.c
	flex -s -d  \
            -o $(srcdir)/lex.globus_i_rvf_.c \
            --header-file=$(srcdir)/globus_i_rvf_scanner.h \
            $(srcdir)/rvf.l
endif

EXTRA_DIST = rvf.l rvf.y globus-rvf-edit $(man_MANS) \
    globus-rvf-edit-manual.xml globus-rvf-check-manual.xml
