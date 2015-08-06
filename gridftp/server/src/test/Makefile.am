check_PROGRAMS = \
        sharing_allowed_test

TESTS = sharing_allowed_test
LOG_COMPILER = ../libtool --mode=execute $(preload_links)

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(srcdir)/..
LDADD = ../libglobus_gridftp_server.la \
        $(preload_links) $(PACKAGE_DEP_LIBS) -lltdl

