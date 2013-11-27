# Extra directories into which we install files
globusperldir=$(perlmoduledir)/Globus/GRAM
perldocdir=$(docdir)/perl/Globus/GRAM

# Not handled by automake, because of :: in the destination file names
MAN_DIR=${mandir}/man3

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
	$(PERL) $< -perl \
		$(srcdir)/../globus-gram-protocol-constants.sh
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

# The default filelist rule will list each of the man pages
# in the filelist in the root directory. This added dependency will add those
# files in the correct place as well.
filelist: filelist-man

filelist-man:
	@filelistdir="`echo $(FILELIST_FILE) | sed -e 's!/[^/]*$$!!'`"; \
	list='$(noinst_DATA)'; for p in $$list; do \
	    p="`echo $(MAN_DIR) | sed -e 's!^$(prefix)!!' -e 's!$$!/Globus::GRAM::'$$p'!'`"; \
	    echo "$$p" >> $$filelistdir/noflavor_doc.filelist; \
	done

MAINTAINERCLEANFILES = $(perldoc_DATA) $(noinst_DATA)
