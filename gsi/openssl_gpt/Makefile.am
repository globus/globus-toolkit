
include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top
include $(top_srcdir)/globus_openssl_pre

SUBDIRS = \
	include \
	util \
	tools \
	aclocal \
	crypto \
	ssl \
	certs \
	pkgdata 

if ENABLE_PROGRAMS
SUBDIRS += apps test
endif

opensslinclude_HEADERS = \
	e_os2.h

noinst_HEADERS = \
	e_os.h

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


EXTRA_DIST = \
	globus_openssl_post \
	globus_openssl_pre \
	CHANGES \
	CHANGES.gpt \
	LICENSE



links: $(opensslinclude_HEADERS)
	@if test -n "$(opensslinclude_HEADERS)"; then \
		$(PERL) $(top_builddir)/util/mklink.pl \
			$(top_builddir)/include/openssl/  \
			$(opensslinclude_HEADERS); \
	fi;
	@for i in crypto ssl; do \
		(cd $$i; $(MAKE) links ); \
	done;


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top





