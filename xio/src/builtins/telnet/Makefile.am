include $(top_srcdir)/globus_automake_pre

Sources= \
    globus_xio_telnet.c

flavorinclude_HEADERS = \
    globus_xio_telnet.h


noinst_LTLIBRARIES = libglobus_xio_telnet_driver_$(GLOBUS_FLAVOR_NAME).la 

INCLUDES = -I$(top_srcdir) $(GPT_INCLUDES)

libglobus_xio_telnet_driver___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_xio_telnet_driver___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_xio_telnet_driver___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
