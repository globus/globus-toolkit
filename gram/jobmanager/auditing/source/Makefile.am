SUBDIRS = schemas

globusconfdir = $(sysconfdir)/globus
crondir = $(sysconfdir)/cron.hourly

sbin_SCRIPTS = globus-gram-audit
man_MANS = globus-gram-audit.8
globusconf_DATA = gram-audit.conf
cron_SCRIPTS = globus-gram-audit.cron
doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = \
        globus-gram-audit.txt \
        $(man_MANS) \
        $(doc_DATA)

if BUILD_MANPAGES
SUFFIXES = .txt .8

.txt.8:
	$(A2X) -d manpage -f manpage $<

MAINTAINERCLEANFILES = $(man_MANS)
endif

install-data-hook:
	mkdir -p -m 01733 $(DESTDIR)$(localstatedir)/lib/globus/gram-audit

distuninstallcheck:
	@:
