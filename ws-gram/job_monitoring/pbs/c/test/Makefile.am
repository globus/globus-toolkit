include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = doxygen pkgdata 


test_SCRIPTS = TESTS.pl test-pbs-seg.pl
test_DATA = test-data.txt

EXTRA_DIST= TESTS.pl test-pbs-seg.pl.in

test-pbs-seg.pl: $(srcdir)/test-pbs-seg.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = test-pbs-seg.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
