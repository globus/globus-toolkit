lib_LTLIBRARIES = libglobus_seg_fork.la

## seglrms = [ DATA ]
seglrmsdir=${sysconfdir}/globus/scheduler-event-generator/available

seglrms_DATA = fork

$(seglrms_DATA):
	touch $@

CLEANFILES = $(seglrms_DATA)

libglobus_seg_fork_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -DGLOBUS_BUILTIN=1 -I..
libglobus_seg_fork_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_seg_fork_la_LDFLAGS = \
        -avoid-version \
        -no-undefined \
        -module \
        -rpath $(libdir)
libglobus_seg_fork_la_SOURCES = seg_fork_module.c

if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(seglrmsdir)/..; ln -sf available/fork .
endif
