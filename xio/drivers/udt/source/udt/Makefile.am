udt_version = 4.11
udt_tarball = udt.sdk.$(udt_version).tar.gz
udt_tarball_url = http://downloads.sourceforge.net/project/udt/udt/$(udt_version)/$(udt_tarball)

all-local: include/udt.h lib/libudt.a

clean-local:
	rm -f include/udt.h lib/libudt.a
	$(MAKE) MAKEFLAGS=-e $(AM_MAKEFLAGS) os=OSX arch=$(host_cpu) -C udt/source/src clean

$(udt_tarball):
	@$(DOWNLOAD_TO_STDOUT) $(udt_tarball_url) > $(udt_tarball).download; \
	mv $(udt_tarball).download $(udt_tarball)

udt-unpack-stamp: $(udt_tarball)
	$(MKDIR_P) udt/source
	$(AMTAR) -zxf $(udt_tarball) -C udt/source --strip 2
	touch $@

include/udt.h: udt-unpack-stamp
	$(MKDIR_P) include
	cp udt/source/src/udt.h include/udt.h

lib/libudt.a: udt-unpack-stamp
	$(MKDIR_P) lib
	export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH); \
	case $(host_os) in \
		*darwin*) \
			next_arch=0; \
			other_flags=""; \
			lipo_arches=""; \
			for flag in $(CXXFLAGS); do \
			    if [ X"$$flag" = X"-arch" ]; then \
				next_arch=1; \
			    elif [ X"$$next_arch" = X1 ]; then \
			        arches="$${arches:+$$arches }$$flag"; \
				lipo_arches="$${lipo_arches:+$$lipo_arches }-arch $$flag libudt-$$flag.a"; \
			        next_arch=0; \
			    else \
				other_flags="$${other_flags:+$$other_flags }$$flag" ; \
			    fi; \
			done; \
                        if [ "$$arches" = "" ]; then \
                            lipo_arches="-arch $(host_cpu) libudt-$(host_cpu).a"; \
                            arches="$(host_cpu)"; \
                        fi ; \
			for arch in $$arches; do \
			    case $$arch in \
			    	x86_64) \
				    udtarch=AMD64; \
				    ;; \
				i386) \
				    udtarch=IA32; \
				    ;; \
				*) \
				    udtarch=$$arch; \
			    esac; \
			    env C++="$(CXX) $(CPPFLAGS) $${other_flags} -arch $${arch}" $(MAKE) -e MAKEFLAGS=-e $(AM_MAKEFLAGS) os=OSX arch=$$udtarch -C udt/source/src clean all; \
			    mv udt/source/src/libudt.a libudt-$${arch}.a; \
			done; \
			lipo -create $${lipo_arches} -output lib/libudt.a; \
			;; \
		*linux*) \
			case $(host_cpu) in \
				x86_64) \
					udtarch="AMD64"; \
					;; \
				i386) \
					udtarch="IA32"; \
					;; \
			esac; \
			env C++="$(CXX) $(CPPFLAGS) $(CXXFLAGS)" $(MAKE) -e MAKEFLAGS=-e $(AM_MAKEFLAGS) os=LINUX arch=$$udtarch -C udt/source/src clean all; \
			mv udt/source/src/libudt.a lib/libudt.a; \
			;; \
		*cygwin*) \
			env C++="$(CXX) $(CPPFLAGS) $(CXXFLAGS)" $(MAKE) -e MAKEFLAGS=-e $(AM_MAKEFLAGS) os=CYGWIN arch=$$udtarch -C udt/source/src clean all; \
			mv udt/source/src/libudt.a lib/libudt.a; \
			;; \
		*mingw*) \
			env C++="$(CXX) $(CPPFLAGS) $(CXXFLAGS) -DUDT_EXPORTS" $(MAKE) -e MAKEFLAGS=-e $(AM_MAKEFLAGS) os=WIN32 arch=$$udtarch -C udt/source/src clean all; \
			mv udt/source/src/libudt.a lib/libudt.a; \
			;; \
	esac
