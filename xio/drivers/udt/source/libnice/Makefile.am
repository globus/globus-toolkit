libnice_version = 0.1.4
libnice_tarball = libnice-$(libnice_version).tar.gz
libnice_tarball_url = http://nice.freedesktop.org/releases/$(libnice_tarball)

all-local: libnice

$(libnice_tarball):
	@$(DOWNLOAD_TO_STDOUT) $(libnice_tarball_url) > $(libnice_tarball).download; \
	mv $(libnice_tarball).download $(libnice_tarball)

libnice-unpack-stamp: $(libnice_tarball)
	$(MKDIR_P) source
	$(AMTAR) -zxf $(libnice_tarball) -C source --strip 1
	touch $@

libnice-configure-stamp: libnice-unpack-stamp
	export PKG_CONFIG_PATH="$(PKG_CONFIG_PATH):$(GLIB2_PKG_CONFIG_PATH)"; \
        cd source && ./configure --prefix=$(abs_builddir) --disable-shared --disable-dependency-tracking --enable-static CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS)" LDFLAGS="$(LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$(host_triplet)"
	touch $@

libnice: libnice-configure-stamp
	export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH); \
	cd source && $(MAKE) $(AM_MAKEFLAGS) install
	touch $@

CLEANFILES = libnice libnice-configure-stamp
DISTCLEANFILES = $(libnice_tarball) libnice-unpack-stamp

clean-local:
	test -d source && (cd source && $(MAKE) $(AM_MAKEFLAGS) distclean) || true
distclean-local:
	rm -rf source
