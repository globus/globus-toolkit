include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

bin_SCRIPTS = \
	globus-gass-cache \
	globus-gass-cache-destroy
libexec_SCRIPTS = \
	globus-gass-cache-util.pl
bin_PROGRAMS = \
	globus-gass-cache-util

doc_DATA = GLOBUS_LICENSE

globus_gass_cache_util_LDFLAGS = $(GPT_LDFLAGS)
globus_gass_cache_util_LDADD = $(GPT_PGM_LINKS)
globus_gass_cache_util_SOURCES = globus_gass_cache.c

EXTRA_DIST = globus-gass-cache.in \
	     globus-gass-cache-util.pl.in \
	     globus-gass-cache-destroy.in \
	     GLOBUS_LICENSE \
	     version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
