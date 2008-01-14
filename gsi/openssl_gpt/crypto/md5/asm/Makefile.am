include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	md5-586.pl \
	md5-sparcv9.S

clean-local:
	rm -f *.s *.cpp

EXTRA_DIST = $(Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
