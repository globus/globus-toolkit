NULL =

EXTRA_DIST = \
	globals.h \
	README \
	$(NULL)

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include \
        $(GPT_INCLUDES) \
	$(XMLSEC_DEFINES) \
	$(XMLSEC_SKELETON_DEFINES) \
	$(SKELETON_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

CFLAGS = $(GPT_CFLAGS)
LDFLAGS = $(GPT_LDFLAGS)
LIBADD = $(GPT_LIB_LINKS)

lib_LTLIBRARIES = \
	libxmlsec1-skeleton.la \
	$(NULL)

libxmlsec1_skeleton_la_SOURCES =\
	app.c \
	crypto.c \
	$(NULL)

libxmlsec1_skeleton_la_LIBADD = \
	../libxmlsec1.la \
	$(SKELETON_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(NULL)
        
libxmlsec1_skeleton_la_LDFLAGS = \
	-version-info @XMLSEC_VERSION_INFO@ \
	$(NULL)
