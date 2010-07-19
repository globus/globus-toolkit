include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	doxygen \
	pkgdata 

Sources= seg_job_manager_module.c

AM_CPPFLAGS = $(GPT_INCLUDES) -DGLOBUS_BUILTIN=1

lib_LTLIBRARIES = libglobus_seg_job_manager_$(GLOBUS_FLAVOR_NAME).la

libglobus_seg_job_manager___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_seg_job_manager___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
		$(GPT_LDFLAGS) -module
libglobus_seg_job_manager___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)
sbin_SCRIPTS = globus-job-manager-event-generator

man8datadir = $(GLOBUS_LOCATION)/man/man8
man8data_DATA = globus-job-manager-event-generator.8

MANUAL_SOURCE = manual.xml globus-job-manager-event-generator-manual.xml

EXTRA_DIST= version.h.in $(sbin_SCRIPTS) $(MANUAL_SOURCE) $(man8data_DATA)

if GENERATE_MANPAGES
export XML_CATALOG_FILES := $(XML_CATALOG_PATH)
$(man8data_DATA): $(MANUAL_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl manual.xml
endif

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

