include $(top_srcdir)/globus_automake_pre

EXTRA_DIST= globus-gridftp-server.in globus-gridftp-sshftp.in

varlockdir = ${localstatedir}/lock
varrundir = ${localstatedir}/run

gridftpinitdir = ${sysconfdir}/init.d

gridftpinit_SCRIPTS = globus-gridftp-server globus-gridftp-sshftp

install-data-local:
	mkdir -p $(DESTDIR)$(varlockdir)
	mkdir -p $(DESTDIR)$(varrundir)

include $(top_srcdir)/globus_automake_post
