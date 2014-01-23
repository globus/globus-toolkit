PKG_CONFIG_PATH = $(GT_PKGCONFIG_DIRS)

@TARGETS_FILE@

$(GT_TARGETS_CLEAN):
	@if [ -f $($@_stamp) ]; then \
		export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) ; cd $($@_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) clean ; \
	fi
	@rm -f $($@_stamp)
$(GT_TARGETS_INSTALL):
	@export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) ; cd $($@_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) install
$(GT_TARGETS_DISTCLEAN):
	@export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) ; cd $($@_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) distclean
$(GT_TARGETS_DIST):
	@$(MKDIR_P) package-output
	@export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) ; cd $($@_SUBDIR) && MAKEFLAGS= $(MAKE) $(AM_MAKEFLAGS) dist
	@cp $($@_SUBDIR)/$($@-tarball) package-output

$(GT_ALL_STAMPS):
	@export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) ; ( (cd $($@-all_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) all) && touch $@) || exit 1

$(GT_ONLY):
	@export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) ; cd $($@-all_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) all

RPMDIRS = BUILD BUILDROOT RPMS SOURCES SPECS SRPMS

$(GT_TARGETS_RPM):
	@for d in $(RPMDIRS); do mkdir -p rpmbuild/$$d; done
	@cp $($@_SOURCE) rpmbuild/SOURCES
	@HOME=$$(pwd) rpmbuild -ba $($@_SPECFILE)

$(GT_TARGETS_DEB):
	@rm -rf debbuild/$($@_PACKAGE_NAME)
	@mkdir -p debbuild/$($@_PACKAGE_NAME)
	@cp $($@_SOURCE) $($@_TARBALL)
	@cp -R $(srcdir)/packaging/debian/$($@_PACKAGE_NAME) debbuild
	@sed -e 's/@distro@/$(shell lsb_release -cs)/g' <  $(srcdir)/packaging/debian/$($@_PACKAGE_NAME)/debian/changelog.in > debbuild/$($@_PACKAGE_NAME)/debian/changelog
	@tar --strip 1 -zxf $($@_SOURCE) -C debbuild/$($@_PACKAGE_NAME)
	@cd debbuild/$($@_PACKAGE_NAME) && dpkg-buildpackage -uc -us $(DPKG_BUILDPACKAGE_OPTS)

DOC_STAMPS =
DOC_PHONY = 
DOC_CLEAN = 
if ENABLE_DOXYGEN
DOC_STAMPS += doc-stamp
DOC_CLEAN += doc-clean

doc: doc-stamp
doc-stamp: Doxyfile $(GT_ALL_STAMPS) doxygen/index.dox
	@$(DOXYGEN)
	@touch $@
doc-clean:
	@rm -rf doc doc-stamp
DOC_PHONY += doc doc-clean
endif

install-data-local: $(DOC_STAMPS)
	@if test -d doc/man/man3; then \
		install -d -m 755 $(DESTDIR)$(mandir)/man3; \
		$(INSTALL) -m 644 doc/man/man3/globus*.3 $(DESTDIR)$(mandir)/man3 ; \
	fi
	@if test -d doc/html; then \
		for dir in `(cd doc; find html -type d)`; do \
			install -d -m 755 $(DESTDIR)$(docdir)/$$dir; \
		done ; \
		for f in `(cd doc; find html -type f)`; do \
			$(INSTALL) -m 644 doc/$$f $(DESTDIR)$(docdir)/$$f ; \
		done ; \
	fi


EXTRA_DIST=doxygen/index.dox globus-vararg-enums-doxygen-filter.pl 

all-local: $(GT_ALL_STAMPS) $(DOC_STAMPS)
clean-local: $(GT_TARGETS_CLEAN) $(DOC_CLEAN)
distclean-local: $(GT_TARGETS_DISTCLEAN)
dist-hook: $(GT_TARGETS_DIST)

.PHONY: $(GT_TARGETS_ALL) $(GT_TARGETS_ONLY) $(GT_TARGETS_CLEAN) $(GT_TARGETS_INSTALL) $(GT_TARGETS_DISTCLEAN) $(GT_TARGETS_DIST) $(DOC_PHONY) $(GT_TARGETS_RPM) $(GT_TARGETS_DEB)
