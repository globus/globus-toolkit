include $(top_srcdir)/globus_automake_pre

Sources= \
	proxycertinfo.c \
	proxycertinfo.h \
	proxypolicy.c \
	proxypolicy.h

include_HEADERS= \
	proxycertinfo.h \
	proxypolicy.h

lib_LTLIBRARIES = libglobus_proxy_ssl.la

INCLUDES = $(GPT_INCLUDES) -I.

libglobus_proxy_ssl_la_SOURCES = $(Sources)

libglobus_proxy_ssl_la_LIBADD = $(GPT_LIB_LINKS)

libglobus_proxy_ssl_la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
