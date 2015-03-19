ACLOCAL_AMFLAGS=-I m4
pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = connection_driver transfer_driver . test
doc_DATA = GLOBUS_LICENSE

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -DGLOBUS_BUILTIN=1

EXTRA_DIST = dirt.sh $(doc_DATA) globus-vararg-enums-doxygen-filter.pl

DOC_STAMPS =
if ENABLE_DOXYGEN
DOC_STAMPS += doc-stamp

doc-stamp: Doxyfile index.md
	rm -rf doc
	$(DOXYGEN)
	touch $@

clean-local:
	rm -rf doc doc-stamp
endif

all-local: $(DOC_STAMPS)

install-data-local: $(DOC_STAMPS)
	if test -d doc/man/man3; then \
		install -d -m 755 $(DESTDIR)$(mandir)/man3; \
		$(INSTALL) -m 644 doc/man/man3/[Gg][Ll][Oo][Bb][Uu][Ss]*.3 $(DESTDIR)$(mandir)/man3 ; \
        fi
	if test -d doc/html; then \
		for dir in `(cd doc; find html -type d)`; do \
			install -d -m 755 $(DESTDIR)$(docdir)/$$dir; \
		done ; \
		for f in `(cd doc; find html -type f)`; do \
			$(INSTALL) -m 644 doc/$$f $(DESTDIR)$(docdir)/$$f ; \
		done ; \
	fi

distuninstallcheck:
	@:
