include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata \
	doxygen

INCLUDES += $(GPT_INCLUDES)

bin_SCRIPTS = \
	globus-job-run \
	globus-job-status \
	globus-job-clean \
	globus-job-get-output \
	globus-job-submit \
	globus-job-cancel

# EXTRA_DIST is used to include files in
# a source distribution that automake fails to detect.
EXTRA_DIST = globus-job-run.in \
	     globus-job-status.in \
	     globus-job-clean.in \
	     globus-job-get-output.in \
	     version.h.in \
	     dirt.sh

bin_PROGRAMS = globusrun

globusrun_SOURCES = globusrun.c

globusrun_LDFLAGS = $(GPT_LDFLAGS)
globusrun_LDADD = $(GPT_PGM_LINKS)

globus-job-cancel: globus-job-clean
	cp globus-job-clean globus-job-cancel

globus-job-submit: globus-job-run
	cp globus-job-run globus-job-submit

CLEANFILES=globus-job-submit globus-job-cancel

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

