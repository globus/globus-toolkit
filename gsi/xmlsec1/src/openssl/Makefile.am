NULL =

EXTRA_DIST = \
	globals.h \
	README \
	$(NULL)

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
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

lib_LTLIBRARIES = \
	libxmlsec1_openssl_$(GLOBUS_FLAVOR_NAME).la \
	$(NULL)

libxmlsec1_openssl___GLOBUS_FLAVOR_NAME__la_SOURCES =\
	app.c \
	bn.c \
	ciphers.c \
	crypto.c \
	digests.c \
	evp.c \
	hmac.c \
	kw_aes.c \
	kw_des.c \
	kt_rsa.c \
	signatures.c \
	symkeys.c \
	x509.c \
	x509vfy.c \
	$(NULL)

libxmlsec1_openssl___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@ \
	$(OPENSSL_LIBS) \
	$(LIBXSLT_LIBS) \
#	$(LIBXML_LIBS) \
	$(NULL)


libxmlsec1_openssl___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(GPT_LDFLAGS) \
	$(NULL)
