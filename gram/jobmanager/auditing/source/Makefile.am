include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= pkgdata

# Where targets are installed
libexec_SCRIPTS = globus-gram-audit

pkgdata_DATA = 
pkgdocdir = $(GLOBUS_LOCATION)/share/doc/$(PACKAGE)

pkgdoc_DATA = globus-gram-audit.html

# Files which we want to put in the source package
EXTRA_DIST = $(libexec_SCRIPTS) $(pkgdata_DATA)

globus-gram-audit.html: globus-gram-audit
	pod2html --noindex globus-gram-audit | \
	    sed -e 's,</HEAD>,<LINK REL="stylesheet" HREF="../../../../doxygen/globus.css"></HEAD>,' > $@

CLEANFILES=globus-gram-audit.html

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
