include $(top_srcdir)/globus_automake_pre

Sources= \
	proxycertinfo.c \
	proxycertinfo.h \
	proxypolicy.c \
	proxypolicy.h

flavorinclude_HEADERS= \
	proxycertinfo.h \
	proxypolicy.h

lib_LTLIBRARIES = libglobus_proxy_ssl_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES) -I.

libglobus_proxy_ssl___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_proxy_ssl___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libglobus_proxy_ssl___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post