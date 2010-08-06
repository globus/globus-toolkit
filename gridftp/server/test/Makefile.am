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

EXTRA_DIST = $(Data) \
    gfs_common.pl.in \
    globus-gridftp-gfork-mem.pl.in \
    globus-gridftp-dyn-be.pl.in \
    globus-gridftp-gfork-fe.pl.in \
    globus-gridftp-be-gfork.pl.in

gfs_common.pl: $(srcdir)/gfs_common.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-gridftp-be-gfork.pl: $(srcdir)/globus-gridftp-be-gfork.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-gridftp-dyn-be.pl: $(srcdir)/globus-gridftp-dyn-be.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-gridftp-gfork-fe.pl: $(srcdir)/globus-gridftp-gfork-fe.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-gridftp-gfork-mem.pl: $(srcdir)/globus-gridftp-gfork-mem.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = gfs_common.pl \
             globus-gridftp-be-gfork.pl \
             globus-gridftp-dyn-be.pl \
             globus-gridftp-gfork-fe.pl \
             globus-gridftp-gfork-mem.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
