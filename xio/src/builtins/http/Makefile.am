include $(top_srcdir)/globus_automake_pre

Sources= \
    globus_xio_http.c \
    globus_xio_http_attr.c \
    globus_xio_http_client.c \
    globus_xio_http_handle.c \
    globus_xio_http_header.c \
    globus_xio_http_header_info.c \
    globus_xio_http_request.c \
    globus_xio_http_response.c \
    globus_xio_http_rfc2616.c \
    globus_xio_http_server.c \
    globus_xio_http_target.c \
    globus_xio_http_transform.c \
    globus_i_xio_http_responses.h \
    globus_i_xio_http.h \
    globus_xio_http.h

flavorinclude_HEADERS = \
    globus_xio_http.h

noinst_HEADERS = \
    globus_i_xio_http.h \
    globus_i_xio_http_responses.h

noinst_LTLIBRARIES = libglobus_xio_http_driver_$(GLOBUS_FLAVOR_NAME).la 

INCLUDES = -I$(top_srcdir) $(GPT_INCLUDES)

libglobus_xio_http_driver___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_xio_http_driver___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_xio_http_driver___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
