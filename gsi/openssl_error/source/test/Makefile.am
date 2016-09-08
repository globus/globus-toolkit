check_DATA = $(Data)
check_SCRIPTS = $(Scripts)
check_PROGRAMS = globus_openssl_error_test

AM_CPPFLAGS = -I.. -I$(top_srcdir)/library $(PACKAGE_DEP_CFLAGS) $(OPENSSL_CFLAGS)
AM_LDFLAGS = $(PACKAGE_DEP_LIBS) $(OPENSSL_LIBS)
LDADD = ../library/libglobus_openssl_error.la

TESTS = globus-openssl-error-test.pl

Scripts = \
	globus-openssl-error-test.pl

Data = globus_openssl_error_test.stdout

EXTRA_DIST = $(Scripts) $(Data)
CLEANFILES = \
        globus_openssl_error_test.log.stdout \
        globus_openssl_error_test.log.stderr
