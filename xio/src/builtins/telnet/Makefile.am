include $(top_srcdir)/globus_automake_pre

Sources= \
    globus_xio_telnet.c

include_HEADERS = \
    globus_xio_telnet.h


noinst_LTLIBRARIES = libglobus_xio_telnet_driver.la 

INCLUDES = -I$(top_srcdir) $(GPT_INCLUDES)

libglobus_xio_telnet_driver_la_SOURCES = $(Sources)
libglobus_xio_telnet_driver_la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_xio_telnet_driver_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
