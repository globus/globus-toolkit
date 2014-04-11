libnice_version = 0.1.5
libnice_tarball = libnice-$(libnice_version).tar.gz
libnice_tarball_url = http://nice.freedesktop.org/releases/$(libnice_tarball)

all-local: libnice

EXTRA_DIST = globus_libnice_mingw.h

$(libnice_tarball):
	@$(DOWNLOAD_TO_STDOUT) $(libnice_tarball_url) > $(libnice_tarball).download; \
	mv $(libnice_tarball).download $(libnice_tarball)

libnice-unpack-stamp: $(libnice_tarball)
	$(MKDIR_P) source
	$(AMTAR) -zxf $(libnice_tarball) -C source --strip 1
	touch $@

libnice-configure-stamp: libnice-unpack-stamp
	export PKG_CONFIG_PATH="$(PKG_CONFIG_PATH):$(GLIB2_PKG_CONFIG_PATH)"; \
        case $(host_os) in \
            *mingw*) \
                libtool_opts="--enable-shared --disable-static"; \
                ;; \
            *) \
                libtool_opts="--disable-shared --enable-static"; \
                ;; \
        esac; \
        cd source && ./configure --prefix=$(prefix) $${libtool_opts} --disable-dependency-tracking --enable-compile-warnings=no CFLAGS="$(CFLAGS) $(lt_prog_compiler_pic)" CPPFLAGS="$(CPPFLAGS) -include $(abs_srcdir)/globus_libnice_mingw.h" LDFLAGS="$(LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$(host_triplet)"
	touch $@

if HOST_OSX
link_with_frameworks=LIBS="-framework CoreFoundation -framework Cocoa"
endif
libnice: libnice-configure-stamp
	export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH); \
	cd source && $(MAKE) $(link_with_frameworks) $(AM_MAKEFLAGS) install DESTDIR=$(abs_builddir)
	touch $@

CLEANFILES = libnice libnice-configure-stamp libnice-unpack-stamp
DISTCLEANFILES = $(libnice_tarball) 

install-exec-local:
	case $(host_os) in \
            *mingw*) \
                cd source && $(MAKE) $(AM_MAKEFLAGS) install DESTDIR=$(DESTDIR); \
                ;; \
        esac;
clean-local:
	rm -rf source $(abs_builddir)$(prefix)
