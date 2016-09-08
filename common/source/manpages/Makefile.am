man_MANS = \
    globus-domainname.1 \
    globus-hostname.1 \
    globus-sh-exec.1 \
    globus-version.1

man_source = \
    globus-domainname.txt \
    globus-hostname.txt \
    globus-sh-exec.txt \
    globus-version.txt

EXTRA_DIST = $(man_MANS) $(man_source)

if BUILD_MANPAGES
SUFFIXES = .txt .1

.txt.1:
	$(A2X) -d manpage -f manpage $<
MAINTAINERCLEANFILES = $(man_MANS)
endif
