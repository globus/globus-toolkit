include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=pkgdata

bin_PROGRAMS = globus-grim

INCLUDES =  -I$(top_srdir) $(GPT_INCLUDES) 

globus_grim_SOURCES = grim.c
globus_grim_LDADD =  @GPT_PGM_LINKS@
globus_grim_LDFLAGS = @GPT_LDFLAGS@ 

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
