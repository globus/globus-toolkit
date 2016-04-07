check_DATA = test.conf

check_PROGRAMS = \
	callout_test \
        callout_chain_test

TESTS = $(check_PROGRAMS)
LOG_COMPILER = $(LIBTOOL) --mode=execute -dlopen libchaina_test.la

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir)/library -I.
LDADD = ../library/libglobus_callout.la $(PACKAGE_DEP_LIBS)

checkdir=${abs_top_builddir}/test
check_LTLIBRARIES = libtest.la \
                   libchaina_test.la \
                   libchainb_test.la \
                   libchainc_test.la

callout_test_LDADD = -dlpreopen libtest.la $(LDADD)
callout_chain_test_LDADD = \
    -dlpreopen libtest.la \
    -dlpreopen libchaina_test.la \
    -dlpreopen libchainb_test.la \
    -dlpreopen libchainc_test.la $(LDADD)

libtest_la_LDFLAGS = \
    -module \
    -export-dynamic \
    -no-undefined \
    -avoid-version \
    -rpath ${abs_top_builddir}/test
libtest_la_LIBADD = $(PACKAGE_DEP_LIBS)
libchaina_test_la_LDFLAGS = \
    -module \
    -export-dynamic \
    -no-undefined \
    -avoid-version \
    -rpath ${abs_top_builddir}/test
libchaina_test_la_LIBADD = $(PACKAGE_DEP_LIBS)
libchainb_test_la_LDFLAGS = \
    -module \
    -export-dynamic \
    -no-undefined \
    -avoid-version \
    -rpath ${abs_top_builddir}/test
libchainb_test_la_LIBADD = $(PACKAGE_DEP_LIBS)
libchainc_test_la_LDFLAGS = \
    -module \
    -export-dynamic \
    -no-undefined \
    -avoid-version \
    -rpath ${abs_top_builddir}/test
libchainc_test_la_LIBADD = $(PACKAGE_DEP_LIBS)

EXTRA_DIST = $(check_DATA)
