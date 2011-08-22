include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= seg pkgdata 

test_SCRIPTS = TESTS.pl TESTS-junit.pl

EXTRA_DIST= TESTS.pl.in TESTS-junit.pl.in

test: all
	perl "-I@perlmoduledir@" TESTS.pl

junit: all
	perl "-I@perlmoduledir@" TESTS-junit.pl

.PHONY: junit test

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
