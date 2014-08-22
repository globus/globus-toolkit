AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_builddir) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_lsf.la

libglobus_seg_lsf_la_SOURCES = seg_lsf_module.c
libglobus_seg_lsf_la_LDFLAGS = $(PACKAGE_DEP_CFLAGS) -module \
        -avoid-version \
        -no-undefined
libglobus_seg_lsf_la_LIBADD = $(PACKAGE_DEP_LIBS)

## seglrms = [ DATA ]
seglrmsdir=${sysconfdir}/globus/scheduler-event-generator/available

seglrms_DATA = lsf

$(seglrms_DATA):
	touch $@

CLEANFILES = $(seglrms_DATA)

if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(seglrmsdir)/..; ln -sf available/lsf .
endif
