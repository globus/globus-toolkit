include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	des-586.pl \
	crypt586.pl \
	desboth.pl

clean-local:
	rm -f *.s *.cpp

EXTRA_DIST = $(Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
