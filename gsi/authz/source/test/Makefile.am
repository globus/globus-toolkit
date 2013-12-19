check_PROGRAMS = authtest authz_cred_test
check_LTLIBRARIES = libglobus_authz_test_callout.la

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) $(GLOBUS_GSS_ASSIST_CFLAGS) -I$(top_srcdir)
LDADD = $(PACKAGE_DEP_LIBS) $(GLOBUS_GSS_ASSIST_LIBS)

authtest_LDADD = ../libglobus_authz.la $(LDADD)
authtest_SOURCES = authtest.c

authz_cred_test_LDADD = ../libglobus_authz.la $(LDADD)
authz_cred_test_SOURCES = \
    authz_cred_test.c \
    gssapi_test_utils.c \
    gssapi_test_utils.h

libglobus_authz_test_callout_la_SOURCES = authz_test_callout.c
libglobus_authz_test_callout_la_LIBADD = $(GPT_LIB_LINKS)

libglobus_authz_test_callout_la_LDFLAGS = \
	-module \
        -no-undefined \
        -rpath $(abs_builddir)


