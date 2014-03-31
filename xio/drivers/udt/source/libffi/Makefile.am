libffi_version = 3.0.13
libffi_tarball = libffi-$(libffi_version).tar.gz
libffi_tarball_url = ftp://sourceware.org/pub/libffi/$(libffi_tarball)

all-local: libffi

$(libffi_tarball):
	@$(DOWNLOAD_TO_STDOUT) $(libffi_tarball_url) > $(libffi_tarball).download; \
	mv $(libffi_tarball).download $(libffi_tarball)

libffi-unpack-stamp: $(libffi_tarball)
	$(MKDIR_P) source
	$(AMTAR) -zxf $(libffi_tarball) -C source --strip 1
	touch $@

libffi-configure-stamp: libffi-unpack-stamp
	export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH); \
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
			    cd source && ./configure --prefix=$(abs_builddir) --disable-shared --enable-static CFLAGS="$(CFLAGS) $(lt_prog_compiler_pic)" CPPFLAGS="$(CPPFLAGS)" LDFLAGS="$(LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$(host_triplet)"; \
			else \
			    for arch in $$arches; do \
				$(MKDIR_P) source/build/$$arch; \
				cd source/build/$$arch; \
				../../configure --prefix=$(abs_builddir) --disable-shared --enable-static CFLAGS="-arch $$arch $$other_flags $(lt_prog_compiler_pic)" CPPFLAGS="$(CPPFLAGS)" LDFLAGS="$(LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$$arch-$(host_vendor)-$(host_os)"; \
				cd "$$OLDPWD"; \
			    done; \
			fi ; \
			;; \
		*) \
		    cd source && ./configure --prefix=$(abs_builddir) --disable-shared --enable-static CFLAGS="$(CFLAGS) $(lt_prog_compiler_pic)" CPPFLAGS="$(CPPFLAGS)" LDFLAGS="$(LDFLAGS)" CC="$(CC)" LD="$(LD)" --host="$(host_triplet)"; \
		    ;; \
	esac;
	touch $@

libffi: libffi-configure-stamp
	@export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH); \
	case $(host_os) in \
		*darwin*) \
			arches=""; \
			next_arch=""; \
			for flag in $(CFLAGS); do \
			    if [ X"$$flag" = X"-arch" ]; then \
				next_arch=1; \
			    elif [ X"$$next_arch" = X1 ]; then \
			        arches="$${arches:+$$arches }$$flag"; \
				lipo_arches="$${lipo_arches:+$$lipo_arches }-arch $$flag $$flag/lib/libffi.a"; \
			        next_arch=0; \
			    else \
				other_flags="$${other_flags:+$$other_flags }$$flag" ; \
			    fi; \
			done ; \
			if test "x$$arches" = "x"; then \
			    cd source && $(MAKE) $(AM_MAKEFLAGS) install; \
			else \
			    for arch in $$arches; do \
				echo "Making $$arch"; \
				cd source/build/$$arch; \
				$(MAKE) $(AM_MAKEFLAGS) install; \
				cd "$$OLDPWD"; \
				$(MKDIR_P) $$arch/lib; \
				mv lib/libffi.a $$arch/lib; \
			    done; \
			    echo "Creating fat binary"; \
			    lipo -create $$lipo_arches -output lib/libffi.a; \
			fi ; \
			;; \
		*) \
		    cd source && env toolexeclibdir='$${libdir}' $(MAKE) MAKEFLAGS=-e $(AM_MAKEFLAGS) -e install; \
		    ;; \
	esac;
	touch $@

CLEANFILES = libffi libffi-unpack-stamp libffi-configure-stamp 
DISTCLEANFILES = $(libffi_tarball)

clean-local:
	rm -rf source bin lib share
	case $(host_os) in \
		*darwin*) \
			arches=""; \
			next_arch=""; \
			for flag in $(CFLAGS); do \
			    if [ X"$$flag" = X"-arch" ]; then \
				next_arch=1; \
			    elif [ X"$$next_arch" = X1 ]; then \
			        arches="$${arches:+$$arches }$$flag"; \
				lipo_arches="$${lipo_arches:+$$lipo_arches }-arch $$flag $$flag/lib/libffi.a"; \
			        next_arch=0; \
			    else \
				other_flags="$${other_flags:+$$other_flags }$$flag" ; \
			    fi; \
			done ; \
			if test "x$$arches" != "x"; then \
	                    rm -rf $$arches; \
                        fi; \
                        ;; \
        esac
