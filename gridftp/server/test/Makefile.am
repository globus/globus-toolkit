include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

globusperldir = $(GLOBUS_LOCATION)/lib/perl/Globus
globusperl_DATA = URL.pm

Scripts= \
	globus-gridftp-dyn-be.pl

test_SCRIPTS = $(Scripts)

Data = \
	gfork_conf.in

test_DATA = $(Data) 

EXTRA_DIST = $(Scripts) $(Data) $(globusperl_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
