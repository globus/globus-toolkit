check_DATA = $(Data)
check_SCRIPTS = $(Scripts)
check_PROGRAMS = globus_openssl_error_test

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I.. -I$(top_srcdir)/library
AM_LDFLAGS = $(PACKAGE_DEP_LIBS)
LDADD = ../library/libglobus_openssl_error.la

TESTS = globus-openssl-error-test.pl

Scripts = \
	TESTS.pl \
	TESTS-junit.pl \
	globus-openssl-error-test.pl

Data = globus_openssl_error_test.stdout


test:
	chmod a+x $(Scripts)
	perl ./TESTS.pl

junit:
	chmod a+x $(Scripts)
	perl ./TESTS-junit.pl


EXTRA_DIST = $(Scripts) $(Data)
CLEANFILES = \
        globus_openssl_error_test.log.stdout \
        globus_openssl_error_test.log.stderr
