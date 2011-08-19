include $(top_srcdir)/globus_automake_pre

Sources= seg_pbs_module.c

AM_CPPFLAGS = $(GPT_INCLUDES) -I$(top_builddir) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_pbs.la

libglobus_seg_pbs_la_SOURCES = $(Sources)
libglobus_seg_pbs_la_LDFLAGS = $(GPT_LDFLAGS) -module
libglobus_seg_pbs_la_LIBADD = $(GPT_LIB_LINKS)

## seglrms = [ DATA ]
seglrmsdir=${sysconfdir}/globus/scheduler-event-generator/available

seglrms_DATA = pbs

$(seglrms_DATA):
	touch $@


if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(seglrmsdir)/..; ln -sf available/pbs .
endif

include $(top_srcdir)/globus_automake_post
