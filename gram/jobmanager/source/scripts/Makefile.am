include $(top_srcdir)/globus_automake_pre

# Extra directories we install files into
globusperldir=$(GLOBUS_LOCATION)/lib/perl/Globus/GRAM
perldocdir=$(GLOBUS_LOCATION)/share/doc/perl/Globus/GRAM

# Not handled by automake, because of :: in the destination file names
MAN_DIR=$(GLOBUS_LOCATION)/man/man3

# Where targets are installed
globusperl_DATA = \
    JobDescription.pm \
    JobManager.pm \
    StdioMerger.pm \
    ExtensionsHandler.pm
perldoc_DATA = JobManager.html JobDescription.html
noinst_DATA = JobManager.3 JobDescription.3

# Files which we want to put in the source package
EXTRA_DIST = $(globusperl_DATA) $(perldoc_DATA) $(noinst_DATA)\
	     create_rsl_documentation.pl

SUFFIXES = .pm .html .3

.pm.html:
	pod2html --noindex $*.pm | \
	    sed -e 's,</HEAD>,<LINK REL="stylesheet" HREF="../../../../doxygen/globus.css"></HEAD>,' > $*.html


.pm.3:
	pod2man --section=3 $*.pm > $*.3

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(MAN_DIR)
	for manpage in $(noinst_DATA); do \
	    $(INSTALL_DATA) $$manpage $(DESTDIR)$(MAN_DIR)/Globus::GRAM::$$manpage; \
	done

# The default filelist-noinstDATA rule will list each of the man pages
# in the filelist in the root directory. This added dependency will add those
# files in the correct place as well.
filelist-noinstDATA: filelist-man

filelist-man:
	@list='$(noinst_DATA)'; for p in $$list; do \
		echo "$(DESTDIR)$(MAN_DIR)/Globus::GRAM::$$p" >> $(FILELIST_FILE); \
	done

MAINTAINERCLEANFILES = $(perldoc_DATA) $(noinst_DATA)

include $(top_srcdir)/globus_automake_post
