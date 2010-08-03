include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = doxygen pkgdata 

test_SCRIPTS = TESTS.pl test-lsf-seg.pl
test_DATA = test-data.txt

EXTRA_DIST= $(test_DATA) TESTS.pl test-lsf-seg.pl.in
CLEANFILES = test-lsf-seg.pl

test-lsf-seg.pl: $(srcdir)/test-lsf-seg.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
