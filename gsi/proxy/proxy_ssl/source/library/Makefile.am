include $(top_srcdir)/globus_automake_pre

Sources= \
	signature.c \
	signature.h \
	proxycertinfo.c \
	proxycertinfo.h \
	proxygroup.c \
	proxygroup.h \
	proxyrestriction.c \
	proxyrestriction.h

flavorinclude_HEADERS= \
	signature.h \
	proxycertinfo.h \
	proxygroup.h \
	proxyrestriction.h

lib_LTLIBRARIES = libglobus_proxy_ssl_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES) -I.

libglobus_proxy_ssl___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_proxy_ssl___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libglobus_proxy_ssl___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post