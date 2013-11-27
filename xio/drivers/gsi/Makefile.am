AUTOMAKE_OPTIONS = foreign

pkgconfigdir = $(libdir)/pkgconfig
include_HEADERS = globus_xio_gsi.h
doc_DATA = GLOBUS_LICENSE
lib_LTLIBRARIES = libglobus_xio_gsi_driver.la
pkgconfig_DATA = globus-xio-gsi-driver.pc

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)

libglobus_xio_gsi_driver_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_xio_gsi_driver_la_SOURCES = \
	globus_i_xio_gsi.h  globus_xio_gsi.h globus_xio_gsi.c
libglobus_xio_gsi_driver_la_LDFLAGS = \
	-version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -module -rpath $(GLOBUS_LOCATION)/lib \
        -no-undefined

EXTRA_DIST = dirt.sh version.h.in $(doc_DATA)

DOC_STAMPS =
if ENABLE_DOXYGEN
DOC_STAMPS += doc-stamp

doc-stamp: Doxyfile $(libglobus_xio_gsi_driver_la_SOURCES)
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
