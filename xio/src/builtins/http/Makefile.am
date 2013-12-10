include_HEADERS = \
    globus_xio_http.h
noinst_HEADERS = \
    globus_i_xio_http.h \
    globus_i_xio_http_responses.h
noinst_LTLIBRARIES = libglobus_xio_http_driver.la 

AM_CPPFLAGS = -I$(top_srcdir) -DGLOBUS_BUILTIN=1 $(PACKAGE_DEP_CFLAGS)
AM_LDFLAGS = $(PACKAGE_DEP_LIBS)
libglobus_xio_http_driver_la_SOURCES = \
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
