include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

gridftp_server_infoincludedir = $(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)/
## gridftp_server_infoinclude = [ HEADERS ]

gridftp_server_infoschemadir = $(GLOBUS_LOCATION)/share/schema/
## gridftp_server_infoschema = [ DATA ]

NULL=


CGEN=$(GLOBUS_LOCATION)/bin/globus-wsrf-cgen
CGENARGS=-np -nk /home/bresnaha/Dev/Globus/GL/share/schema/gridftp/server/info/gridftp_server_info_service.wsdl


EXTRA_DIST=dirt.sh version.h groups.dox

SUBDIRS=. doxygen pkgdata


SUBDIRS += \
        GridFTPServerInfoService \
        $(NULL)
AllServiceSources = \
                undefined/GridFTPServerInfoService_module.c \
                    $(NULL)
        

INCLUDES=-I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)/wsrf/services
AM_CPPFLAGS=-I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)/wsrf/services

Types_Sources = \
         backendPool.c \
         backendInfo.c \
         GridFTPServerInfoPortTypeGTWSDLResourceProperties.c \
         GridFTPServerInfoPortTypeGTWSDLResourcePropertiesType.c \
         frontendInfo.c \
         frontendInfoType.c \
         GridFTPServerInfoService_type_registry.c \
       $(NULL)




lib_LTLIBRARIES = libgridftp_server_info_types_$(GLOBUS_FLAVOR_NAME).la \
                  $(NULL)

nodist_libgridftp_server_info_types___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Types_Sources)
libgridftp_server_info_types___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@
libgridftp_server_info_types___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@




nodist_gridftp_server_infoinclude_HEADERS = \
        backendPool.h \
        backendInfo.h \
        backendInfo_array.h \
        GridFTPServerInfoPortTypeGTWSDLResourceProperties.h \
        GridFTPServerInfoPortTypeGTWSDLResourcePropertiesType.h \
        GridFTPServerInfoPortTypeGTWSDLResourcePropertiesType_array.h \
        frontendInfo.h \
        frontendInfoType.h \
        frontendInfoType_array.h \
        GridFTPServerInfoService.h \
        GridFTPServerInfoService_skeleton.h \
        GridFTPServerInfoService_internal_skeleton.h \
        $(NULL)


BUILT_SOURCES=$(Types_Sources) $(Client_Sources) $(nodist_gridftp_server_infoinclude_HEADERS) $(AllServiceSources)
$(BUILT_SOURCES): $(SCHEMA)
	$(CGEN) $(CGENARGS)
CLEANFILES=$(BUILT_SOURCES)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
