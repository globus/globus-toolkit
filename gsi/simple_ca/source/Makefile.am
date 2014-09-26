SUBDIRS = . test
bin_SCRIPTS = grid-ca-sign grid-ca-create grid-ca-package
doc_DATA = GLOBUS_LICENSE
man_MANS = grid-ca-create.1 grid-ca-package.1 grid-ca-sign.1

MANUALS_SOURCE = \
    grid-ca-create.txt \
    grid-ca-package.txt \
    grid-ca-sign.txt \
    grid-ca-create.xml \
    grid-ca-package.xml \
    grid-ca-sign.xml

EXTRA_DIST = \
        dirt.sh \
        ca-signing-policy.tmpl \
        grid-ca-ssl.conf.tmpl \
        grid-security.conf.tmpl \
        $(doc_DATA) \
        $(man_MANS) \
        $(MANUALS_SOURCE)

if BUILD_MANPAGES
SUFFIXES = .xml .1

if HAVE_A2X
SUFFIXES += .txt
.txt.xml:
	$(A2X) -f docbook -d manpage $<
endif

.xml.1:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) `test -f $< && echo $< || echo $(srcdir)/$<` > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) `test -f $< && echo $< || echo $(srcdir)/$<`

MAINTAINERCLEANFILES = $(man_MANS)
endif

distuninstallcheck:
	@:
