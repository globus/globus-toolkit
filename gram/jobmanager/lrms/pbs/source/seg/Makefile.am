AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_builddir) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_pbs.la

libglobus_seg_pbs_la_SOURCES = seg_pbs_module.c
libglobus_seg_pbs_la_LDFLAGS = \
        -avoid-version \
        -no-undefined \
        -module
libglobus_seg_pbs_la_LIBADD = $(LTLIBOBJS) $(PACKAGE_DEP_LIBS)

## seglrms = [ DATA ]
seglrmsdir=${sysconfdir}/globus/scheduler-event-generator/available

seglrms_DATA = pbs

$(seglrms_DATA):
	touch $@

CLEANFILES = $(seglrms_DATA)

if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(seglrmsdir)/..; ln -sf available/pbs .
endif
