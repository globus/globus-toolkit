SUBDIRS = . test
pkgconfigdir = $(libdir)/pkgconfig

doc_DATA = GLOBUS_LICENSE
man_MANS = globus-url-copy.1
include_HEADERS = \
	globus_gass_copy.h \
	globus_url_copy.h
lib_LTLIBRARIES = libglobus_gass_copy.la
bin_PROGRAMS = globus-url-copy 
pkgconfig_DATA = globus-gass-copy.pc

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)

libglobus_gass_copy_la_SOURCES = \
	globus_gass_copy.c   \
	globus_gass_copy_glob.c \
	globus_i_gass_copy.h \
	globus_url_copy.h \
	globus_gass_copy.h 
libglobus_gass_copy_la_LDFLAGS = \
        -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined
libglobus_gass_copy_la_LIBADD = $(PACKAGE_DEP_LIBS)

globus_url_copy_SOURCES = globus_url_copy.c
globus_url_copy_LDFLAGS = -export-dynamic
globus_url_copy_LDADD = ./libglobus_gass_copy.la \
			$(PACKAGE_DEP_LIBS)

if BUILD_MANPAGES
SUFFIXES = .xml .1

.xml.1:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
CLEANFILES = $(man_MANS)
endif

DOC_STAMPS =
if ENABLE_DOXYGEN
DOC_STAMPS += doc-stamp

doc-stamp: Doxyfile $(libglobus_gass_copy_la_SOURCES)
	$(DOXYGEN)
	touch $@

clean-local:
	rm -rf doc doc-stamp
endif

all-local: $(DOC_STAMPS)

install-data-local: $(DOC_STAMPS)
	if test -d doc/man/man3; then \
		install -d -m 755 $(DESTDIR)$(mandir)/man3; \
		$(INSTALL) -m 644 doc/man/man3/globus*.3 $(DESTDIR)$(mandir)/man3 ; \
	fi
	if test -d doc/html; then \
		for dir in `(cd doc; find html -type d)`; do \
			install -d -m 755 $(DESTDIR)$(docdir)/$$dir; \
		done ; \
		for f in `(cd doc; find html -type f)`; do \
			$(INSTALL) -m 644 doc/$$f $(DESTDIR)$(docdir)/$$f ; \
		done ; \
	fi

dist-hook: $(DOC_STAMPS)
	if test -d doc; then \
		cp -R doc $(distdir)/doc ; \
	fi ;

EXTRA_DIST = \
	dirt.sh \
	version.h.in \
	$(doc_DATA) \
        $(man_MANS) \
        globus-url-copy.xml


distuninstallcheck:
	@:
