man_MANS = globus-fork-starter.8
sbin_PROGRAMS = globus-fork-starter

globus_fork_starter_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
globus_fork_starter_LDADD = $(PACKAGE_DEP_LIBS)
globus_fork_starter_SOURCES = fork_starter.c

EXTRA_DIST = $(man_MANS) globus-fork-starter.txt

if BUILD_MANPAGES
SUFFIXES = .txt .8

.txt.8:
	$(A2X) -d manpage -f manpage $<

MAINTAINERCLEANFILES = $(man_MANS)
endif
