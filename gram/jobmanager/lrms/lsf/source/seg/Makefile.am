include $(top_srcdir)/globus_automake_pre

Sources= seg_lsf_module.c

AM_CPPFLAGS = $(GPT_INCLUDES) -I$(top_builddir) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_lsf.la

libglobus_seg_lsf_la_SOURCES = $(Sources)
libglobus_seg_lsf_la_LDFLAGS = $(GPT_LDFLAGS) -module
libglobus_seg_lsf_la_LIBADD = $(GPT_LIB_LINKS)

## seglrms = [ DATA ]
seglrmsdir=${sysconfdir}/globus/scheduler-event-generator/available

seglrms_DATA = lsf

$(seglrms_DATA):
	touch $@


if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(seglrmsdir)/..; ln -sf available/lsf .
endif

include $(top_srcdir)/globus_automake_post
