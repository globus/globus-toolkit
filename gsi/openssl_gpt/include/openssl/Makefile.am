include $(top_srcdir)/globus_automake_pre

all-local:
	@for i in crypto ssl; do \
		(cd $(top_srcdir)/$${i};$(MAKE) $(AM_MAKEFLAGS) links); \
	done;

include $(top_srcdir)/globus_automake_post





