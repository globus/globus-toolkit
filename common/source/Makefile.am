include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	library \
	programs \
	scripts \
	pkgdata \
	config \
	doxygen

sbin_SCRIPTS= \
	config.guess

data_DATA= \
	globus_common_root.res

EXTRA_DIST = \
	version.h.in\
	globus_common.txt

RESNAME=globus_common
GENRB= if [ x$(LD_LIBRARY_PATH) = "x" ]; then\
	LD_LIBRARY_PATH=$(GLOBUS_LOCATION)/lib; \
	else \
	LD_LIBRARY_PATH=$(GLOBUS_LOCATION)/lib:$(LD_LIBRARY_PATH); \
	fi; \
	export LD_LIBRARY_PATH; \
	$(GLOBUS_LOCATION)/bin/genrb
GENRBOPT=--package-name $(RESNAME)
$(RESNAME)_root.res: $(RESNAME).txt
	@echo "generating $@"
	$(GENRB) $(GENRBOPT) $^

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
