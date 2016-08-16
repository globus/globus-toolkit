check_PROGRAMS = \
		handle-attrs-test \
		proxy-core-test \
		proxy-handle-compat-test \
		proxy-handle-test

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir)/library -I..
LDADD = ../library/libglobus_gsi_proxy_core.la $(PACKAGE_DEP_LIBS) 
AM_LDFLAGS = $(GPT_LDFLAGS)

TESTS = \
	handle-attrs-test \
	proxy-core-test \
	proxy-handle-compat-test \
	proxy-handle-test

LOG_COMPILER = $(LIBTOOL)
AM_LOG_FLAGS = --mode=execute $(VALGRIND)
