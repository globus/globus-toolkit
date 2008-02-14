include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata 

globusperldir = $(GLOBUS_LOCATION)/lib/perl/Globus

Scripts= \
    gfs_common.pl \
    globus-gridftp-gfork-mem.pl \
	globus-gridftp-dyn-be.pl \
    globus-gridftp-gfork-fe.pl \
    globus-gridftp-be-gfork.pl

test_SCRIPTS = $(Scripts)

Data = \
    dc31a685.signing_policy \
    dc31a685.0 \
    testcred.pem \
    gfork_mem_conf.in \
	gfork_conf.in \
    gfork_single_conf.in \
	gfork_be_conf.in

test_DATA = $(Data) 

EXTRA_DIST = $(Scripts) $(Data)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
