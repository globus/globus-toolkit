check_SCRIPTS = \
	gss-assist-impexp-test.pl \
	gss-assist-auth-test.pl \
	gss-assist-gridmap-test.pl \
        gridmap-test.pl \
        gridmap-tools-test.pl

check_DATA_DIST = grid-mapfile \
       gridmap.blank_line \
       gridmap.empty \
       gridmap.long_line \
       gridmap.multiple-dns \
       gridmap.multiple_lines \
       gridmap.no-local-uid \
       gridmap.no-local-uid2

check_DATA = $(check_DATA_DIST) \
        testcred.key \
        testcred.cert \
        testcredlink

check_PROGRAMS = \
	gss-assist-auth-init \
	gss-assist-auth-accept \
	gss-assist-impexp-init \
	gss-assist-impexp-accept \
	gss-assist-gridmap \
        gridmap-test \
        gridmap-userok

AM_CPPFLAGS = -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS)
LDADD = ../libglobus_gss_assist.la $(PACKAGE_DEP_LIBS)

if CYGPATH_W_DEFINED
X509_CERT_DIR=$$($(CYGPATH_W) $(abs_builddir))
TEST_GRIDMAP_DIR=$$($(CYGPATH_W) $(srcdir))
else
X509_CERT_DIR=$(abs_builddir)
TEST_GRIDMAP_DIR=$(srcdir)
endif

TESTS = $(check_SCRIPTS)
TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(X509_CERT_DIR) \
    TEST_GRIDMAP_DIR=$(TEST_GRIDMAP_DIR);

testcred.key:
	umask 077 ; openssl genrsa 1024 > $@.tmp; mv $@.tmp $@

testcred.req: testcred.key
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< -config openssl.cnf > $@.tmp; mv $@.tmp $@

testcred.cert: testcred.req testcred.key
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key > $@.tmp; mv $@.tmp $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname"; \
	echo "$$linkname" > $@

CLEAN_FILES = testcred.req testcred.key testcred.cert
clean-local:
	@if [ -f testcredlink ]; then \
	    rm -f `cat testcredlink` testcredlink; \
	fi

gss_assist_auth_init_SOURCES = gss_assist_auth_init.c tokens_bsd.c tokens_bsd.h
gss_assist_auth_accept_SOURCES = gss_assist_auth_accept.c tokens_bsd.c tokens_bsd.h
gss_assist_impexp_init_SOURCES = gss_assist_impexp_init.c tokens_bsd.c tokens_bsd.h
gss_assist_impexp_accept_SOURCES = gss_assist_impexp_accept.c tokens_bsd.c tokens_bsd.h
gss_assist_gridmap_SOURCES = gss_assist_gridmap.c
gridmap_test_SOURCES = gridmap_test.c
gridmap_userok_SOURCES = gridmap_userok.c

EXTRA_DIST = \
        $(check_DATA_DIST) \
        $(check_SCRIPTS)
