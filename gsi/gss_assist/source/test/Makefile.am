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

TESTS = $(check_SCRIPTS)
TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(abs_builddir)

testcred.key:
	umask 077 ; openssl genrsa -out $@ 1024

testcred.req: testcred.key
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< -out $@

testcred.cert: testcred.req testcred.key
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	ln -s testcred.cert "$$linkname"

gss_assist_auth_init_SOURCES = gss_assist_auth_init.c
gss_assist_auth_accept_SOURCES = gss_assist_auth_accept.c
gss_assist_impexp_init_SOURCES = gss_assist_impexp_init.c
gss_assist_impexp_accept_SOURCES = gss_assist_impexp_accept.c
gss_assist_gridmap_SOURCES = gss_assist_gridmap.c
gridmap_test_SOURCES = gridmap_test.c
gridmap_userok_SOURCES = gridmap_userok.c

EXTRA_DIST = \
        $(check_DATA_DIST) \
        $(check_SCRIPTS)

.PHONY: test junit
