include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= pkgdata doxygen rvf scripts seg

# Extra directories we install files into
validationdir = $(datadir)/globus/$(PACKAGE)

## globusconfig = [ DATA ]
globusconfigdir = ${sysconfdir}/globus
globusconfig_DATA = globus-gram-job-manager.conf

logrotatedir = ${sysconfdir}/logrotate.d

# Where targets are installed
noinst_LTLIBRARIES = libglobus_gram_job_manager.la
sbin_PROGRAMS = globus-job-manager globus-gram-streamer

bin_SCRIPTS = globus-personal-gatekeeper
validation_DATA = globus-gram-job-manager.rvf

# Mapping of source files to libraries and executables
libglobus_gram_job_manager_la_SOURCES = \
	globus_gram_job_manager.h \
        globus_gram_job_manager_config.c \
        globus_gram_job_manager.c \
	globus_gram_job_manager_auditing.c \
	globus_gram_job_manager_contact.c \
	globus_gram_job_manager_gsi.c \
	globus_gram_job_manager_history_file.c \
	globus_gram_job_manager_query.c \
	globus_gram_job_manager_request.c \
	globus_gram_job_manager_rsl.c \
	globus_gram_job_manager_script.c \
	globus_gram_job_manager_seg.c \
	globus_gram_job_manager_staging.c \
	globus_gram_job_manager_state.c \
	globus_gram_job_manager_state_file.c \
	globus_gram_job_manager_validate.c \
        globus_gram_job_manager_usagestats.c \
        logging.c \
        startup_socket.c \
        tg_gateway.c

globus_job_manager_SOURCES = main.c

# Compiler flags
INCLUDES = $(GPT_INCLUDES) -I$(top_srcdir) -I$(top_builddir) -I$(top_srcdir)/rvf $(XML_CPPFLAGS)

globus_job_manager_LDFLAGS = $(GPT_LDFLAGS)
globus_job_manager_LDADD = \
	./libglobus_gram_job_manager.la \
	./rvf/libglobus_rvf.la \
	$(GPT_PGM_LINKS) $(XML_LIBS)

globus_gram_streamer_LDFLAGS = $(GPT_LDFLAGS)
globus_gram_streamer_LDADD = \
	./libglobus_gram_job_manager.la \
	./rvf/libglobus_rvf.la \
	$(GPT_PGM_LINKS) $(XML_LIBS)

## man1dir = [ DOC ]
man1_MANS = globus-personal-gatekeeper.1

## man3dir = [ DOC ]
man8_MANS = globus-job-manager.8

## man8dir = [ DOC ]
man5_MANS = rsl.5

MANUAL_SOURCE = globus-personal-gatekeeper-manual.xml \
                globus-job-manager-manual.xml \
                manual.xml \
                rsl.xml

doc_DATA = GLOBUS_LICENSE

# Files which we want to put in the source package
EXTRA_DIST = globus-personal-gatekeeper.in \
	     $(validation_DATA) \
	     version.h.in \
	     configuration.dox \
	     globus_gram_job_manager_rsl.dox \
	     globus_gram_job_manager_script_interface.dox \
	     globus_gram_job_manager_script_tutorial.dox \
	     globus_job_manager_rsl_validation.dox \
	     job_execution_environment.dox \
             $(MANUAL_SOURCE) \
             $(man1_MANS) \
             $(man5_MANS) \
             $(man8_MANS) \
	     $(doc_DATA) \
	     main.dox \
	     dirt.sh \
	     globus-gram-job-manager.conf.in \
             gram.logrotate.in \
             libxml.m4

all: $(BUILT_SOURCES)

globus_gram_job_manager_rsl.dox: globus-gram-job-manager.rvf
	perl $(top_srcdir)/scripts/create_rsl_documentation.pl < $< > $@
rsl.xml: globus-gram-job-manager.rvf
	perl $(top_srcdir)/scripts/create_rsl_documentation.pl -x < $< > $@

install-data-hook:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/globus/gram_job_state
	chmod 1777 $(DESTDIR)$(localstatedir)/lib/globus/gram_job_state
	mkdir -p $(DESTDIR)$(logrotatedir)
	cp $(srcdir)/gram.logrotate $(DESTDIR)$(logrotatedir)/globus-job-manager
	mkdir -p $(DESTDIR)@LOGDIR@
	chmod 1777 $(DESTDIR)@LOGDIR@
	mkdir -p $(DESTDIR)$(sysconfdir)/globus/gram

CLEANFILES = \
    globus-personal-gatekeeper \
    globus_gram_job_manager_rsl.dox

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man1_MANS) $(man5_MANS) $(man8_MANS): $(MANUAL_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl manual.xml
endif
include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
