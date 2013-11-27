AUTOMAKE_OPTIONS = foreign

DIST_SUBDIRS = config init

if BUILD_GATEKEEPER
SUBDIRS = $(DIST_SUBDIRS)

logdir = ${localstatedir}/log
logrotatedir = ${sysconfdir}/logrotate.d

sbin_PROGRAMS = \
	globus-gatekeeper \
	globus-k5
man_MANS = globus-gatekeeper.8 globus-k5.8
doc_DATA = GLOBUS_LICENSE

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)

globus_gatekeeper_LDADD = $(PACKAGE_DEP_LIBS) 
globus_gatekeeper_CPPFLAGS = \
    $(AM_CPPFLAGS) \
    -DGLOBUS_LOCATION=\"$(prefix)\" -DGLOBUS_LOG_DIR=\"$(localstatedir)\"
globus_gatekeeper_SOURCES = \
	globus_gatekeeper.c \
	globus_gatekeeper_utils.h \
	globus_gatekeeper_utils.c

globus_k5_LDADD = $(PACKAGE_DEP_LIBS) 
globus_k5_CPPFLAGS = $(AM_CPPFLAGS)
globus_k5_SOURCES = globus_k5.c globus_gatekeeper_utils.c

install-data-hook: gatekeeper.logrotate
	mkdir -p $(DESTDIR)$(logdir)
	mkdir -p $(DESTDIR)$(logrotatedir)
	cp gatekeeper.logrotate $(DESTDIR)$(logrotatedir)/globus-gatekeeper

SUFFIXES = .logrotatein .logrotate
.logrotatein.logrotate:
	sed -e 's|@LOGDIR@|${localstatedir}/log|' < $< > $@

EXTRA_DIST=$(doc_DATA) $(man8_MANS) \
        manual.xml \
        globus-gatekeeper.xml \
        globus-k5.xml \
        gatekeeper.logrotatein

if BUILD_MANPAGES
SUFFIXES += .xml .8

.xml.8:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
CLEANFILES = $(man_MANS)
endif
endif
