include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

include_HEADERS = \
    globus_xio_netlogger.h

INCLUDES = $(GPT_INCLUDES) 

lib_LTLIBRARIES = libglobus_xio_netlogger_driver.la \
               libclient_netlogger_plugin.la

libclient_netlogger_plugin_la_LIBADD = \
    @GPT_LIB_LINKS@ 
libclient_netlogger_plugin_la_SOURCES = \
    globus_ftp_client_nl_plugin.c
libclient_netlogger_plugin_la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib 


libglobus_xio_netlogger_driver_la_LIBADD = \
	@GPT_LIB_LINKS@ 
libglobus_xio_netlogger_driver_la_SOURCES = \
	globus_xio_netlogger.c
libglobus_xio_netlogger_driver_la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib 

EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
