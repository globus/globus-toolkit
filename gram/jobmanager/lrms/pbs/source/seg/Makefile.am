AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_builddir) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_pbs.la

libglobus_seg_pbs_la_SOURCES = seg_pbs_module.c
libglobus_seg_pbs_la_LDFLAGS = \
        -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined \
        -module
libglobus_seg_pbs_la_LIBADD = $(LTLIBOBJS) $(PACKAGE_DEP_LIBS)

## seglrms = [ DATA ]
seglrmsdir=${sysconfdir}/globus/scheduler-event-generator/available

seglrms_DATA = pbs

$(seglrms_DATA):
	touch $@


if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(seglrmsdir)/..; ln -sf available/pbs .
endif

DOC_STAMPS =
if ENABLE_DOXYGEN
DOC_STAMPS += doc-stamp

doc-stamp: Doxyfile $(libglobus_seg_pbs_la_SOURCES)
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
