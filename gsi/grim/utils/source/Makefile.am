include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=pkgdata

bin_PROGRAMS = grim

INCLUDES =  -I$(top_srdir) $(GPT_INCLUDES) 

grim_SOURCES = grim.c
grim_LDADD =  @GPT_PGM_LINKS@
grim_LDFLAGS = @GPT_LDFLAGS@ 

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
