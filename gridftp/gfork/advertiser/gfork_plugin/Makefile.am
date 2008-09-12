include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
    doxygen \
	pkgdata 

flavorinclude_HEADERS = \
    gfs_advertiser.h

libexec_PROGRAMS= \
    gfs-advertiser

INCLUDES = $(GPT_INCLUDES)
LDFLAGS =  -L$(GLOBUS_LOCATION)/lib/globus_service_modules/wsrf/services

gfs_advertiser_SOURCES =  \
    gfs_advertiser.c        \
    gfs_advertiser.h 
gfs_advertiser_LDFLAGS =  $(GPT_LDFLAGS) \
 -L$(GLOBUS_LOCATION)/lib/globus_service_modules/wsrf/services \
    @GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib
gfs_advertiser_LDADD =  $(GPT_PGM_LINKS)  @GPT_LIB_LINKS@

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
