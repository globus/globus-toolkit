
include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	library \
	programs \
	pkgdata \
	doxygen

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST= \
        version.h \
        dirt.sh \
	$(doc_DATA)

distclean-local: 
	-rm -f stamp-h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top





