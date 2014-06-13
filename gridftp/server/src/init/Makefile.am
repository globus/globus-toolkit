varlockdir = ${localstatedir}/lock
varrundir = ${localstatedir}/run

gridftpinitdir = ${sysconfdir}/init.d

gridftpinit_SCRIPTS = globus-gridftp-server globus-gridftp-sshftp

install-data-local:
	mkdir -p $(DESTDIR)$(varlockdir)
	mkdir -p $(DESTDIR)$(varrundir)
