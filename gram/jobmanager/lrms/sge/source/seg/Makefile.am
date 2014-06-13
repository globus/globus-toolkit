
seglrmsdir=${sysconfdir}/globus/scheduler-event-generator/available

lib_LTLIBRARIES = libglobus_seg_sge.la
seglrms_DATA = sge

$(seglrms_DATA):
	touch $@

CLEANFILES = $(seglrms_DATA)

libglobus_seg_sge_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I.. -DGLOBUS_BUILTIN=1
libglobus_seg_sge_la_SOURCES = seg_sge_module.c
libglobus_seg_sge_la_LDFLAGS = \
        -avoid-version \
        -no-undefined \
        -module 
libglobus_seg_sge_la_LIBADD = $(PACKAGE_DEP_LIBS)

if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(seglrmsdir)/..; ln -sf available/sge .
endif
