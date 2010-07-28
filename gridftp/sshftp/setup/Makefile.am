include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

setup_SCRIPTS = \
	setup-globus-gridftp-sshftp \
	setup-globus-gridftp-sshftp.pl

SUBDIRS = pkgdata

EXTRA_DIST = setup-globus-gridftp-sshftp.pl.in setup-globus-gridftp-sshftp.in
CLEANFILES = setup-globus-gridftp-sshftp.pl setup-globus-gridftp-sshftp

setup-globus-gridftp-sshftp.pl: $(srcdir)/setup-globus-gridftp-sshftp.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
setup-globus-gridftp-sshftp: $(srcdir)/setup-globus-gridftp-sshftp.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

