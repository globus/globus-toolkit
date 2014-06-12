# Compiler flags
AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) \
        -I$(top_builddir) \
        -I$(top_srcdir) \
        -I$(top_srcdir)/rvf \
        $(XML_CPPFLAGS) \
	-DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_job_manager.la

libglobus_seg_job_manager_la_SOURCES = seg_job_manager_module.c
libglobus_seg_job_manager_la_LDFLAGS = -module -no-undefined -avoid-version 
libglobus_seg_job_manager_la_LIBADD = $(PACKAGE_DEP_LIBS)
