include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata

globustestingperldir = $(GLOBUS_LOCATION)/lib/perl/Globus/Testing
globustestingperl_DATA = \
    Comm.pm \
    Gram.pm \
    Host.pm \
    HostDB.pm \
    Startup.pm \
    Timer.pm

EXTRA_DIST += $(globustestingperl_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
