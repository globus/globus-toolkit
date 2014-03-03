glib2_short_version = 2.32
glib2_version = $(glib2_short_version).4
glib2_tarball = glib-$(glib2_version).tar.xz
glib2_tarball_url = http://ftp.gnome.org/pub/gnome/sources/glib/$(glib2_short_version)/$(glib2_tarball)

all-local: glib2

$(glib2_tarball):
	@$(DOWNLOAD_TO_STDOUT) $(glib2_tarball_url) > $(glib2_tarball).download; \
	mv $(glib2_tarball).download $(glib2_tarball)

glib2-unpack-stamp: $(glib2_tarball)
	$(MKDIR_P) source
if XZ_WORKS
	$(XZ) -dc < $(glib2_tarball) | $(AMTAR) -xf- -C source --strip 1
else
	echo "Unable to extract .xz archive. Please install xz" 1>&2; exit 1
endif
	export PKG_CONFIG_PATH="$(PKG_CONFIG_PATH):$(LIBFFI_PKG_CONFIG_PATH)"; \
	export PATH="$${PATH}:$(GETTEXT_PATH)"; \
	case $(host_os) in \
		*darwin*) \
			next_arch=""; \
			for flag in $(CFLAGS); do \
			    if [ X"$$flag" = X"-arch" ]; then \
				next_arch=1; \
			    elif [ X"$$next_arch" = X1 ]; then \
			        next_arch=0; \
			    else \
				other_flags="$${other_flags:+$$other_flags }$$flag" ; \
			    fi; \
			done ; \
			next_arch=""; \
			for flag in $(LDFLAGS); do \
			    if [ X"$$flag" = X"-arch" ]; then \
				next_arch=1; \
			    elif [ X"$$next_arch" = X1 ]; then \
			        next_arch=0; \
			    else \
				other_ldflags="$${other_ldflags:+$$other_ldflags }$$flag" ; \
			    fi; \
			done ; \
			    $(MKDIR_P) build/$(build_triplet); \
			    cd build/$(build_triplet); \
			    ../../source/configure --prefix=$(abs_builddir)/$(build_triplet) --disable-shared --enable-static CFLAGS="$$other_flags" CPPFLAGS="$(CPPFLAGS) $(GETTEXT_CPPFLAGS)" LDFLAGS="$$other_ldflags $(GETTEXT_LDFLAGS)" CC="$(CC)" LD="$(LD)" --disable-dependency-tracking -q || exit 1; \
			    $(MAKE) $(AM_MAKEFLAGS) install ; \
			;; \
	esac;
	touch $@

glib2-configure-stamp: glib2-unpack-stamp
	export PKG_CONFIG_PATH="$(PKG_CONFIG_PATH):$(LIBFFI_PKG_CONFIG_PATH)"; \
	export PATH="$${PATH}:$(GETTEXT_PATH)"; \
	case $(host_os) in \
		*darwin*) \
			export PATH="$(abs_builddir)/$(host_triplet)/bin:$${PATH}"; \
			export glib_cv_stack_grows=no; \
			export glib_cv_uscore=no; \
			export ac_cv_func_posix_getpwuid_r=yes; \
			export ac_cv_func_posix_getgrgid_r=yes; \
			arches=""; \
			next_arch=""; \
			for flag in $(CFLAGS); do \
			    if [ X"$$flag" = X"-arch" ]; then \
				next_arch=1; \
			    elif [ X"$$next_arch" = X1 ]; then \
			        arches="$${arches:+$$arches }$$flag"; \
			        next_arch=0; \
			    else \
				other_flags="$${other_flags:+$$other_flags }$$flag" ; \
			    fi; \
			done ; \
			next_arch=""; \
			for flag in $(LDFLAGS); do \
			    if [ X"$$flag" = X"-arch" ]; then \
				next_arch=1; \
			    elif [ X"$$next_arch" = X1 ]; then \
			        next_arch=0; \
			    else \
				other_ldflags="$${other_ldflags:+$$other_ldflags }$$flag" ; \
			    fi; \
			done ; \
			if test "x$$arches" = "x"; then \
			    cd source && ./configure --prefix=$(abs_builddir) --disable-shared --enable-static CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS) $(GETTEXT_CPPFLAGS)" LDFLAGS="$(LDFLAGS) $(GETTEXT_LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$(host_triplet)" --disable-dependency-tracking -q || exit 1; \
			else \
			    for arch in $$arches; do \
				$(MKDIR_P) build/$$arch; \
				cd build/$$arch; \
				../../source/configure --prefix=$(abs_builddir) --disable-shared --enable-static CFLAGS="-arch $$arch $$other_flags" CPPFLAGS="$(CPPFLAGS) $(GETTEXT_CPPFLAGS)" LDFLAGS="-arch $$arch $$other_ldflags $(GETTEXT_LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$$arch-$(host_vendor)-$(host_os)" --disable-dependency-tracking -q || exit 1; \
				cd "$$OLDPWD"; \
			    done; \
			fi ; \
			;; \
		*) \
		    cd source && ./configure --prefix=$(abs_builddir) --disable-shared --enable-static CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS) $(GETTEXT_CPPFLAGS)" LDFLAGS="$(LDFLAGS) $(GETTEXT_LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$(host_triplet)" --disable-dependency-tracking || exit 1; \
		    ;; \
	esac;
	touch $@

glib2: glib2-configure-stamp
	export PKG_CONFIG_PATH="$(PKG_CONFIG_PATH):$(LIBFFI_PKG_CONFIG_PATH)"; \
	case $(host_os) in \
		*darwin*) \
			arches=""; \
			next_arch=""; \
			for flag in $(CFLAGS); do \
			    if [ X"$$flag" = X"-arch" ]; then \
				next_arch=1; \
			    elif [ X"$$next_arch" = X1 ]; then \
			        arches="$${arches:+$$arches }$$flag"; \
			        next_arch=0; \
			    else \
				other_flags="$${other_flags:+$$other_flags }$$flag" ; \
			    fi; \
			done ; \
			if test "x$$arches" = "x"; then \
			    cd source && $(MAKE) $(AM_MAKEFLAGS) install; \
			else \
			    for arch in $$arches; do \
				firstarch="$$arch"; \
				echo "Making $$arch"; \
				cd build/$$arch; \
				$(MAKE) $(AM_MAKEFLAGS) install; \
				cd "$$OLDPWD"; \
				$(MKDIR_P) $$arch/lib; \
				for lib in lib/*.a; do \
				    libs="$$libs $${lib##*/}"; \
				done; \
				mv lib/*.a $$arch/lib; \
			    done; \
			    echo "Creating fat binaries"; \
			    for lib in $$libs; do \
				lipo_arches=""; \
				for arch in $$arches; do \
				    lipo_arches="$${lipo_arches} -arch $$arch $$arch/lib/$$lib"; \
				done; \
				lipo -create $$lipo_arches -output lib/$$lib; \
			    done; \
			fi ; \
			;; \
		*) \
		    cd source && ./configure --prefix=$(abs_builddir) --disable-shared --enable-static CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS)" LDFLAGS="$(LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$(host_triplet)"; \
		    ;; \
	esac;
	touch $@

CLEAN_FILES = glib2 
DISTCLEANFILES = $(glib2_tarball) glib2-unpack-stamp glib2-configure-stamp
clean-local:
	test -d source && (cd source && $(MAKE) $(AM_MAKEFLAGS) clean) || true
distclean-local:
	rm -rf source
