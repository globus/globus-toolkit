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
	saml.h \
	gaa_simple.h 

INCLUDES += $(GPT_INCLUDES) -I/usr/include/libxml2

flavorinclude_HEADERS= \
	gaa_simple.h saml.h

lib_LTLIBRARIES = libglobus_gaa_simple_$(GLOBUS_FLAVOR_NAME).la

libglobus_gaa_simple___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gaa_simple___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gaa_simple___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libglobus_gaa_simple___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDADD) -lxml2

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
