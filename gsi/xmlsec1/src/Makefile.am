include $(top_srcdir)/globus_automake_pre

NULL =

SUBDIRS = . $(XMLSEC_CRYPTO_LIST)


INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-DGLOBUS_FLAVOR_NAME=\"@GLOBUS_FLAVOR_NAME@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include \
	-I$(GLOBUS_LOCATION)/include/libxml2 \
        $(GPT_INCLUDES) \
	$(XMLSEC_DEFINES) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

CFLAGS = $(GPT_CFLAGS)
LDFLAGS = $(GPT_LDFLAGS)
LIBADD = $(GPT_LIB_LINKS)

EXTRA_DIST = \
	globals.h \
	ltdl.h ltdl.c \
	xmlsec-ltdl.h xmlsec-ltdl.c xmlsec-ltdl.patch \
	skeleton \
	mscrypto \
	$(XMLSEC_CRYPTO_DISABLED_LIST) \
	$(NULL)

lib_LTLIBRARIES = \
	libxmlsec1_$(GLOBUS_FLAVOR_NAME).la \
	$(NULL)

libxmlsec1___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	$(LTDL_SOURCE_FILES) \
	app.c \
	base64.c \
	bn.c \
	buffer.c \
	c14n.c \
	dl.c \
	enveloped.c \
	errors.c \
	io.c \
	keyinfo.c \
	keys.c \
	keysdata.c \
	keysmngr.c \
	list.c \
	membuf.c \
	nodeset.c \
	parser.c \
	strings.c \
	templates.c \
	transforms.c \
	x509.c \
	xkms.c \
	xmldsig.c \
	xmlenc.c \
	xmlsec.c \
	xmltree.c \
	xpath.c \
	xslt.c \
	$(NULL)

libxmlsec1___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@ \
	$(LIBXSLT_LIBS) \
#	$(LIBXML_LIBS) \
	$(XMLSEC_DL_LIBS) \
	$(NULL)
        
libxmlsec1___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)

if XMLSEC_NO_CRYPTO_DYNAMIC_LOADING
LTDL_SOURCE_FILES = \
	$(NULL)
else 
LTDL_SOURCE_FILES = \
	xmlsec-ltdl.c \
	$(NULL)

LTDL_PARSE = \
	sed s/ltdl.h/xmlsec-ltdl.h/g | \
	sed s/lt_/xmlsec_lt_/g | \
	sed s/ltdl_/xmlsec_ltdl_/g \
	$(NULL)	

xmlsec-ltdl.c: xmlsec-ltdl.h 

xmlsec-ltdl.h: ltdl.c ltdl.h xmlsec-ltdl.patch
	@(cat ltdl.c | $(LTDL_PARSE) > xmlsec-ltdl.c && \
	  cat ltdl.h | $(LTDL_PARSE) > xmlsec-ltdl.h && \
	  patch -p0 < xmlsec-ltdl.patch)

endif


include $(top_srcdir)/globus_automake_post
