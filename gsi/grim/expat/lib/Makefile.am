
include $(top_srcdir)/globus_automake_pre

Sources= \
	ascii.h \
	asciitab.h \
	expat.h \
	iasciitab.h \
	internal.h \
	latin1tab.h \
	nametab.h \
	utf8tab.h \
	winconfig.h \
	xmlparse.c \
	xmlrole.c \
	xmlrole.h \
	xmltok.c \
	xmltok.h \
	xmltok_impl.h

EXTRA_DIST= \
        xmltok_impl.c \
	xmltok_ns.c

flavorinclude_HEADERS = \
	expat.h

lib_LTLIBRARIES = libglobus_expat_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(srcdir)/lib -I.

libglobus_expat___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_expat___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@

libglobus_expat___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
