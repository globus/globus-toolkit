include $(top_srcdir)/globus_automake_pre

Sources= \
    globus_xio_mode_e_driver.c

include_HEADERS = \
    globus_xio_mode_e_driver.h    

noinst_LTLIBRARIES = libglobus_xio_mode_e_driver.la 

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/builtins/udp \
-I$(top_srcdir)/builtins/tcp $(GPT_INCLUDES)

libglobus_xio_mode_e_driver_la_SOURCES = $(Sources)
libglobus_xio_mode_e_driver_la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_xio_mode_e_driver_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
