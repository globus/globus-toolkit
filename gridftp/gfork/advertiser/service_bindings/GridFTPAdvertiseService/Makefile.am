include $(top_srcdir)/globus_automake_pre

AM_CPPFLAGS = -I.. -I$(top_srcdir) $(GPT_INCLUDES) 

AM_CFLAGS = -DGLOBUS_BUILTIN=1 $(GPT_CFLAGS)



GridFTPAdvertiseServicelibdir = $(GLOBUS_LOCATION)/lib/globus_service_modules/wsrf/services
## GridFTPAdvertiseServicelib = [ LTLIBRARIES ]


ServiceSources = skeleton.c 

# This is the version of the service implementation which will be dynamic
# loaded at runtime by the service container
GridFTPAdvertiseServicelib_LTLIBRARIES = libGridFTPAdvertiseService_$(GLOBUS_FLAVOR_NAME).la


nodist_libGridFTPAdvertiseService___GLOBUS_FLAVOR_NAME__la_SOURCES = \
        $(built_ServiceSources)
libGridFTPAdvertiseService___GLOBUS_FLAVOR_NAME__la_SOURCES = \
        $(ServiceSources)

libGridFTPAdvertiseService___GLOBUS_FLAVOR_NAME__la_LIBADD = \
        ../libgridftp_server_advertiser_service_types_$(GLOBUS_FLAVOR_NAME).la  @GPT_LIB_LINKS@ 

libGridFTPAdvertiseService___GLOBUS_FLAVOR_NAME__la_LDFLAGS =  @GPT_LDFLAGS@ -module -rpath $(GridFTPAdvertiseServicelibdir)


@INCLUDE_MAKEFILE_SOURCES@


include $(top_srcdir)/globus_automake_post
