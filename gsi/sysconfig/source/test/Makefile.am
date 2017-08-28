check_PROGRAMS = system-config-test
check_SCRIPTS = system-config-test.pl

TESTS = $(check_SCRIPTS)

AM_CPPFLAGS = -I$(srcdir)/../library $(PACKAGE_DEP_CFLAGS)
LDADD = ../library/libglobus_gsi_sysconfig.la $(PACKAGE_DEP_LIBS)

EXTRA_DIST = $(check_SCRIPTS)
