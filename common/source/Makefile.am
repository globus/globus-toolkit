include $(top_srcdir)/globus_automake_targets

SUBDIRS= \
	library \
	tests


if WITHOUT_FLAVORS
else
pkg_DATA = build_parameters_$(FL)
endif

include $(top_srcdir)/globus_automake_rules