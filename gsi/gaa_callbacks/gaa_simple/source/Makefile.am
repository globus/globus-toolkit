include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	conditions.c \
	cred_assertion.c \
	parse_eacl_str.c \
	read_eacl.c \
	read_saml.c \
	parse_saml_assertion.c \
	xml_sig.c \
	saml.h \
	xml_sig.h \
	gaa_simple.h 

INCLUDES = $(GPT_INCLUDES) $(XMLSEC1_CFLAGS)


include_HEADERS= \
	gaa_simple.h saml.h

lib_LTLIBRARIES = libglobus_gaa_simple.la

libglobus_gaa_simple_la_SOURCES = $(Sources)

libglobus_gaa_simple_la_LDFLAGS = $(GPT_LDFLAGS) $(XMLSEC1_LDFLAGS)

libglobus_gaa_simple_la_LIBADD = $(GPT_LIB_LINKS) $(XMLSEC1_LIBS)

#xml_sig_test_SOURCES = xml_sig_test.c
#xml_sig_test_LDFLAGS = $(GPT_LDFLAGS)
#xml_sig_test_LDADD = \
#		libglobus_gaa_simple.la \
#		$(GPT_PGM_LINKS)
#
#nametest_SOURCES = nametest.c
#nametest_LDFLAGS = $(GPT_LDFLAGS)
#nametest_LDADD = \
#		libglobus_gaa_simple.la \
#		$(GPT_PGM_LINKS)
#
#
#test_PROGRAMS=xml_sig_test nametest

EXTRA_DIST = \
	RSA.LICENSE

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
