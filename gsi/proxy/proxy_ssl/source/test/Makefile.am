include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

test_PROGRAMS= \
	test_pci

INCLUDES += $(GPT_INCLUDES)

LDADD = $(GPT_PGM_LINKS)

test_pci_SOURCES = test_proxycertinfo.c
test_pci_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
include $(top_srcdir)/globus_automake_pre
