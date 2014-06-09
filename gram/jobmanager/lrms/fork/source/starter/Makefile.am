man_MANS = globus-fork-starter.8
sbin_PROGRAMS = globus-fork-starter

globus_fork_starter_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
globus_fork_starter_LDADD = $(PACKAGE_DEP_LIBS)
globus_fork_starter_SOURCES = fork_starter.c

EXTRA_DIST = $(man_MANS) globus-fork-starter.xml

if BUILD_MANPAGES
SUFFIXES = .xml .8

.xml.8:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
MAINTAINERCLEANFILES = $(man_MANS)
endif
