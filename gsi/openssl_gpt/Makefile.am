
include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	include \
	util \
	tools \
	aclocal \
	crypto \
	ssl \
	apps \
	test \
	certs \
	pkgdata 


rehash: rehash.time
rehash.time: certs
	@(OPENSSL="`pwd`/apps/openssl"; export OPENSSL; $(PERL) tools/c_rehash certs)
	touch rehash.time

test:   tests

tests: rehash
	@(cd test && echo "testing..." && $(MAKE) tests );
	@apps/openssl version -a

report:
	@$(PERL) util/selftest.pl


EXTRA_DIST = globus_openssl_post globus_openssl_pre CHANGES CHANGES.gpt

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top





