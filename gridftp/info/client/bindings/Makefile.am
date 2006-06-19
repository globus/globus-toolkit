include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

gridftp_server_info_clientincludedir = $(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)/
## gridftp_server_info_clientinclude = [ HEADERS ]

gridftp_server_info_clientschemadir = $(GLOBUS_LOCATION)/share/schema/
## gridftp_server_info_clientschema = [ DATA ]

NULL=


CGEN=$(GLOBUS_LOCATION)/bin/globus-wsrf-cgen
CGENARGS=-np -nk $(GLOBUS_LOCATION)/share/schema/gridftp/server/info/gridftp_server_info_service.wsdl


EXTRA_DIST=dirt.sh version.h groups.dox

SUBDIRS=. doxygen pkgdata



INCLUDES=-I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)/wsrf/services
AM_CPPFLAGS=-I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)/wsrf/services

Types_Sources = \
         backendPool.c \
         backendPoolType.c \
         GridFTPServerInfoPortTypeGTWSDLResourceProperties.c \
         GridFTPServerInfoPortTypeGTWSDLResourcePropertiesType.c \
         frontendInfo.c \
         frontendInfoType.c \
         backendInfo.c \
         backendInfoType.c \
         GridFTPServerInfoService_type_registry.c \
       $(NULL)


Client_Sources = \
        GridFTPServerInfoService_client.c \
        $(NULL)



lib_LTLIBRARIES = libgridftp_server_info_client_types_$(GLOBUS_FLAVOR_NAME).la \
                  libgridftp_server_info_client_client_bindings_$(GLOBUS_FLAVOR_NAME).la \
                  $(NULL)

nodist_libgridftp_server_info_client_types___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Types_Sources)
libgridftp_server_info_client_types___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@
libgridftp_server_info_client_types___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@



nodist_libgridftp_server_info_client_client_bindings___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Client_Sources)
libgridftp_server_info_client_client_bindings___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@
libgridftp_server_info_client_client_bindings___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@


nodist_gridftp_server_info_clientinclude_HEADERS = \
        backendPool.h \
        backendPoolType.h \
        backendPoolType_array.h \
        GridFTPServerInfoPortTypeGTWSDLResourceProperties.h \
        GridFTPServerInfoPortTypeGTWSDLResourcePropertiesType.h \
        GridFTPServerInfoPortTypeGTWSDLResourcePropertiesType_array.h \
        frontendInfo.h \
        frontendInfoType.h \
        frontendInfoType_array.h \
        backendInfo.h \
        backendInfoType.h \
        backendInfoType_array.h \
        GridFTPServerInfoService.h \
        GridFTPServerInfoService_client.h \
        $(NULL)


BUILT_SOURCES=$(Types_Sources) $(Client_Sources) $(nodist_gridftp_server_info_clientinclude_HEADERS) $(AllServiceSources)
$(BUILT_SOURCES): $(SCHEMA)
	$(CGEN) $(CGENARGS)
CLEANFILES=$(BUILT_SOURCES)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
