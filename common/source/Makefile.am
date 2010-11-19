include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	library \
	programs \
	scripts \
	pkgdata \
	config \
	doxygen

libexec_SCRIPTS= \
	config.guess

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = \
	version.h.in\
	globus_common.txt \
	$(doc_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
