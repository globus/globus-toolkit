SUBDIRS = test

pkgconfigdir = $(libdir)/pkgconfig

include_HEADERS = \
	globus_io.h \
	globus_io_error_hierarchy.h
lib_LTLIBRARIES = libglobus_io.la
doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-io.pc

libglobus_io_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)

libglobus_io_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_io_la_LDFLAGS = \
        -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined
libglobus_io_la_SOURCES = \
	globus_io.h \
	globus_io_error_hierarchy.c \
	globus_io_error_hierarchy.h \
	globus_io_xio_compat.c

EXTRA_DIST = dirt.sh version.h.in $(doc_DATA)

DOC_STAMPS =
if ENABLE_DOXYGEN
DOC_STAMPS += doc-stamp

doc-stamp: Doxyfile $(libglobus_io_la_SOURCES)
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

distuninstallcheck:
	@:
