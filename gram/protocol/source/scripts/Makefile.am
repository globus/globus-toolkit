include $(top_srcdir)/globus_automake_pre

# Extra directories into which we install files
globusperldir=$(GLOBUS_LOCATION)/lib/perl/Globus/GRAM
perldocdir=$(GLOBUS_LOCATION)/share/doc/perl/Globus/GRAM

# Not handled by automake, because of :: in the destination file names
MAN_DIR=$(GLOBUS_LOCATION)/man/man3

# What gets installed where
globusperl_DATA = Error.pm JobSignal.pm JobState.pm
perldoc_DATA = Error.html JobSignal.html JobState.html
noinst_DATA = Error.3 JobSignal.3 JobState.3

BUILT_SOURCES = $(globusperl_DATA)

EXTRA_DIST = $(globusperl_DATA) $(perldoc_DATA) $(noinst_DATA) \
	     create_protocol_constants.pl

SUFFIXES = .pm .html .3

$(globusperl_DATA): ../globus-gram-protocol-constants.sh
	$(RM) $(globusperl_DATA)
	@PERL@ $(srcdir)/create_protocol_constants.pl -perl \
		../globus-gram-protocol-constants.sh
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
