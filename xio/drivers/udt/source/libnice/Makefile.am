libnice_version = 0.1.5
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
	case $(host_triplet) in \
	    *mingw*) \
	       EXTRA_CPPFLAGS=-D_SSIZE_T_=1; \
	       ;; \
	    *) \
	       EXTRA_CPPFLAGS=; \
	       ;; \
	esac; \
        cd source && ./configure --prefix=$(abs_builddir) --disable-shared --disable-dependency-tracking --enable-static --enable-compile-warnings=no CFLAGS="$(CFLAGS) $(lt_prog_compiler_pic)" CPPFLAGS="$(CPPFLAGS) $${EXTRA_CPPFLAGS}" LDFLAGS="$(LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$(host_triplet)"
	touch $@

if HOST_OSX
link_with_frameworks=LIBS="-framework CoreFoundation -framework Cocoa"
endif
libnice: libnice-configure-stamp
	export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH); \
	cd source && $(MAKE) $(link_with_frameworks) $(AM_MAKEFLAGS) install
	touch $@

CLEANFILES = libnice libnice-configure-stamp
DISTCLEANFILES = $(libnice_tarball) libnice-unpack-stamp

clean-local:
	test -d source && (cd source && $(MAKE) $(AM_MAKEFLAGS) distclean) || true
distclean-local:
	rm -rf source
