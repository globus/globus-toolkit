include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

gridftp_server_advertiser_serviceincludedir = $(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)/
## gridftp_server_advertiser_serviceinclude = [ HEADERS ]
nodist_gridftp_server_advertiser_serviceincludedir = $(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)/

gridftp_server_advertiser_serviceschemadir = $(GLOBUS_LOCATION)/share/schema/
## gridftp_server_advertiser_serviceschema = [ DATA ]


CGEN=$(GLOBUS_LOCATION)/bin/globus-wsrf-cgen
CGENARGS=-np -nk -s gridftp_server_advertiser_service -p NStoP.properties -n NF $(GLOBUS_LOCATION)/share/schema/gridftp/info/gridftp_advertise_service.wsdl


EXTRA_DIST=dirt.sh version.h groups.dox

SUBDIRS=. doxygen pkgdata


SUBDIRS += \
        GridFTPAdvertiseService 
AllServiceSources = \
        GridFTPAdvertiseService/GridFTPAdvertiseService_module.c 

AM_CPPFLAGS = $(GPT_INCLUDES) 
AM_CFLAGS = $(GPT_CFLAGS)

Types_Sources = 


lib_LTLIBRARIES = libgridftp_server_advertiser_service_types_$(GLOBUS_FLAVOR_NAME).la 

nodist_libgridftp_server_advertiser_service_types___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Types_Sources)
libgridftp_server_advertiser_service_types___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@
libgridftp_server_advertiser_service_types___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@




nodist_gridftp_server_advertiser_serviceinclude_HEADERS = 
@INCLUDE_MAKEFILE_SOURCES@
BUILT_SOURCES=Makefile.sources  $(Types_Sources) $(Client_Sources) $(nodist_gridftp_server_advertiser_serviceinclude_HEADERS) $(AllServiceSources)
$(BUILT_SOURCES): $(SCHEMA)
	$(CGEN) $(CGENARGS)
CLEANFILES=$(BUILT_SOURCES)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
