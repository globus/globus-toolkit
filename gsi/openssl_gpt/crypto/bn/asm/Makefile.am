include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources = \
	bn-586.pl \
	co-586.pl \
	sparcv8.S \
	sparcv8plus.S \
	ia64.S \
	mips3.s \
	x86_64-gcc.c

clean-local:
	rm -f *86*.s *.cpp

EXTRA_DIST = $(Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
