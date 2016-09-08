SUBDIRS = . test
bin_SCRIPTS = grid-ca-sign grid-ca-create grid-ca-package
doc_DATA = GLOBUS_LICENSE
man_MANS = grid-ca-create.1 grid-ca-package.1 grid-ca-sign.1

MANUALS_SOURCE = \
    grid-ca-create.txt \
    grid-ca-package.txt \
    grid-ca-sign.txt

EXTRA_DIST = \
        dirt.sh \
        ca-signing-policy.tmpl \
        grid-ca-ssl.conf.tmpl \
        grid-security.conf.tmpl \
        $(doc_DATA) \
        $(man_MANS) \
        $(MANUALS_SOURCE)

if BUILD_MANPAGES
SUFFIXES = .txt .1

.txt.1:
	$(A2X) -f manpage -d manpage $<

MAINTAINERCLEANFILES = $(man_MANS)
endif

distuninstallcheck:
	@:
