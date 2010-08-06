include $(top_srcdir)/aclocal/automake_targets
libexec_SCRIPTS = \
	globus-build-env-$(GLOBUS_FLAVOR_NAME).sh \
	globus-bootstrap.sh

globus-build-env-$(GLOBUS_FLAVOR_NAME).sh: $(srcdir)/globus-build-env.sh.in
	$(REWRITE_SCRIPT_PREFIXES) < $< | \
        sed > $@ \
        -e 's|$(AT)MP$(AT)|@MP@|g' \
	-e 's|$(AT)MP_INCLUDES$(AT)|@MP_INCLUDES@|g' \
	-e 's|$(AT)MP_LIBS$(AT)|@MP_LIBS@|g' \
	-e 's|$(AT)CC$(AT)|@CC@|g' \
	-e 's|$(AT)CPP$(AT)|@CPP@|g' \
	-e 's|$(AT)CPPFLAGS$(AT)|@CPPFLAGS@|g' \
	-e 's|$(AT)CFLAGS$(AT)|@CFLAGS@|g' \
	-e 's|$(AT)LDFLAGS$(AT)|@LDFLAGS@|g' \
	-e 's|$(AT)LIBS$(AT)|@LIBS@|g' \
	-e 's|$(AT)STATIC_LDFLAGS$(AT)|@STATIC_LDFLAGS@|g' \
	-e 's|$(AT)CXX$(AT)|@CXX@|g' \
	-e 's|$(AT)CXXCPP$(AT)|@CXXCPP@|g' \
	-e 's|$(AT)CXXFLAGS$(AT)|@CXXFLAGS@|g' \
	-e 's|$(AT)F77$(AT)|@F77@|g' \
	-e 's|$(AT)F77FLAGS$(AT)|@F77FLAGS@|g' \
	-e 's|$(AT)F90$(AT)|@F90@|g' \
	-e 's|$(AT)F90FLAGS$(AT)|@F90FLAGS@|g' \
	-e 's|$(AT)AR$(AT)|@AR@|g' \
	-e 's|$(AT)ARFLAGS$(AT)|@ARFLAGS@|g' \
	-e 's|$(AT)RANLIB$(AT)|@RANLIB@|g' \
	-e 's|$(AT)NM$(AT)|@NM@|g' \
	-e 's|$(AT)PERL$(AT)|@PERL@|g' \
	-e 's|$(AT)OBJEXT$(AT)|@OBJEXT@|g' \
	-e 's|$(AT)EXEEXT$(AT)|@EXEEXT@|g' \
	-e 's|$(AT)OBJECT_MODE$(AT)|@OBJECT_MODE@|g' \
	-e 's|$(AT)CROSS$(AT)|@CROSS@|g' \
	-e 's|$(AT)cross_compiling$(AT)|@cross_compiling@|g' \
	-e 's|$(AT)GLOBUS_THREADS$(AT)|@GLOBUS_THREADS@|g' \
	-e 's|$(AT)GLOBUS_HOST$(AT)|@GLOBUS_HOST@|g' \
	-e 's|$(AT)GLOBUS_DEBUG$(AT)|@GLOBUS_DEBUG@|g'

CLEANFILES=globus-build-env-$(GLOBUS_FLAVOR_NAME).sh

EXTRA_DIST = \
	globus-build-env.sh.in \
	globus-bootstrap.sh
