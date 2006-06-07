include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= pkgdata

# Where targets are installed
libexec_SCRIPTS = globus-gram-audit
pkgdata_DATA = log4j.properties

# Files which we want to put in the source package
EXTRA_DIST = $(libexec_SCRIPTS) $(pkgdata_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
