include $(top_srcdir)/globus_automake_pre

Admin_Scripts = \
	grid-mapfile-add-entry \
	grid-mapfile-delete-entry \
	grid-mapfile-check-consistency

Dist_Scripts = \
        grid-mapfile-add-entry.in \
        grid-mapfile-delete-entry.in \
        grid-mapfile-check-consistency.in

sbin_SCRIPTS = $(Admin_Scripts)

EXTRA_DIST = $(Dist_Scripts)

INCLUDES =  -I$(top_srdir) $(GPT_INCLUDES) 

include $(top_srcdir)/globus_automake_post
