include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SRB_CLIENT_PATH= @SRB_PATH@
SRB_CFLAGS=@SRB_CFLAGS@

SUBDIRS = \
	pkgdata \
    doxygen

CFLAGS+=${SRB_CFLAGS}
INCLUDES= $(GPT_INCLUDES) -I $(SRB_CLIENT_PATH)/src/include -I $(SRB_CLIENT_PATH)/src/catalog/include
#CFLAGS+= -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -DPORTNAME_linux -DPARA_OPR=1 -DFED_MCAT

lib_LTLIBRARIES = libglobus_gridftp_server_srb_$(GLOBUS_FLAVOR_NAME).la

libglobus_gridftp_server_srb___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@ $(SRB_CLIENT_PATH)/obj/libSrbClient.a 
libglobus_gridftp_server_srb___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_gridftp_server_srb.c  globus_srb_options.c
libglobus_gridftp_server_srb___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib

noinst_HEADERS = \
    globus_srb_config.h  \
    globus_srb_options.h \
    version.h


EXTRA_DIST = version.h.in README.txt globus_srb_config.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
