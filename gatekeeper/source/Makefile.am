include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

INCLUDES += $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS) @LIBOBJS@ @UNICOS_LIBS@

sbin_PROGRAMS= \
	globus-gatekeeper

libexec_PROGRAMS = \
	globus-k5

globus_gatekeeper_SOURCES = \
	globus_gatekeeper.c \
	unicos.c \
	globus_gatekeeper_utils.h \
	globus_gatekeeper_utils.c
globus_gatekeeper_LDFLAGS = $(GPT_LDFLAGS)

globus_k5_SOURCES = globus_k5.c unicos.c globus_gatekeeper_utils.c
globus_k5_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

