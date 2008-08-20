
include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	library \
	programs \
	pkgdata \
	doxygen

EXTRA_DIST= \
        version.h \
        dirt.sh

distclean-local: 
	-rm -f stamp-h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top





