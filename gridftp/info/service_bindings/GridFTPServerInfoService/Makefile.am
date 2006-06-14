include $(top_srcdir)/globus_automake_pre

NULL=

INCLUDES=-I.. -I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)/wsrf/services 



GridFTPServerInfoServicelibdir = $(GLOBUS_LOCATION)/lib/globus_service_modules/wsrf/services
## GridFTPServerInfoServicelib = [ LTLIBRARIES ]

built_ServiceSources = \
        GridFTPServerInfoService_module.c \
        $(NULL)
ServiceSources = \
       GridFTPServerInfoService_skeleton.c \
    $(NULL)


# This is the version of the service implementation which will be dynamic
# loaded at runtime by the service container
GridFTPServerInfoServicelib_LTLIBRARIES = libGridFTPServerInfoService_$(GLOBUS_FLAVOR_NAME).la


nodist_libGridFTPServerInfoService___GLOBUS_FLAVOR_NAME__la_SOURCES = \
        $(built_ServiceSources)
libGridFTPServerInfoService___GLOBUS_FLAVOR_NAME__la_SOURCES = \
        $(ServiceSources)

libGridFTPServerInfoService___GLOBUS_FLAVOR_NAME__la_LIBADD = \
        ../libgridftp_server_info_types_$(GLOBUS_FLAVOR_NAME).la  @GPT_LIB_LINKS@ 

libGridFTPServerInfoService___GLOBUS_FLAVOR_NAME__la_LDFLAGS =  @GPT_LDFLAGS@ -module -rpath $(GridFTPServerInfoServicelibdir)

include $(top_srcdir)/globus_automake_post
