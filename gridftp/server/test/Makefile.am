include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata 

globusperldir = $(GLOBUS_LOCATION)/lib/perl/Globus

Scripts= \
	globus-gridftp-dyn-be.pl

test_SCRIPTS = $(Scripts)

Data = \
	gfork_conf.in

test_DATA = $(Data) 

EXTRA_DIST = $(Scripts) $(Data)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
