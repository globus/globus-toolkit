include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	aes128-ctr-cipher.h \
	s2_meth.c s2_srvr.c s2_clnt.c s2_lib.c s2_enc.c s2_pkt.c \
	s3_meth.c s3_srvr.c s3_clnt.c s3_lib.c s3_enc.c s3_pkt.c s3_both.c \
	s23_meth.c s23_srvr.c s23_clnt.c s23_lib.c s23_pkt.c \
	t1_meth.c t1_srvr.c t1_clnt.c t1_lib.c t1_enc.c \
	ssl_lib.c ssl_err2.c ssl_cert.c ssl_sess.c \
	ssl_ciph.c ssl_stat.c ssl_rsa.c \
	ssl_asn1.c ssl_txt.c ssl_algs.c \
	bio_ssl.c ssl_err.c kssl.c

Test_Sources = \
	ssltest.c

opensslinclude_HEADERS= \
	ssl.h \
	ssl2.h \
	ssl3.h \
	ssl23.h \
	tls1.h \
	kssl.h

noinst_HEADERS = \
	ssl_locl.h \
	kssl_lcl.h

lib_LTLIBRARIES = libssl_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libssl___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libssl___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	$(GPT_LIB_LINKS) \
	../crypto/libcrypto_$(GLOBUS_FLAVOR_NAME).la

libssl___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
