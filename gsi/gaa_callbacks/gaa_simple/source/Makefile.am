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
	gaa_simple.h 

INCLUDES += $(GPT_INCLUDES)

flavorinclude_HEADERS= \
	gaa_simple.h

lib_LTLIBRARIES = libglobus_gaa_simple_$(GLOBUS_FLAVOR_NAME).la

libglobus_gaa_simple___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gaa_simple___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gaa_simple___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
