include $(top_srcdir)/globus_automake_targets

SUBDIRS= \
	library \
	tests


if WITHOUT_FLAVORS
else
pkg_DATA = build_parameters_$(GLOBUS_FLAVOR_NAME) \
	$(GLOBUS_FLAVOR_NAME).filelist
endif

include $(top_srcdir)/globus_automake_rules