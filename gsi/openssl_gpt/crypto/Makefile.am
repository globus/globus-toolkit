include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

AUTOHEADER = /bin/true

SUBDIRS = \
	md5 sha mdc2 hmac \
	des bf cast      \
	bn rsa dso buffer bio      \
	stack lhash rand err objects      \
	evp asn1 pem x509 x509v3 conf     \
	txt_db pkcs7 pkcs12 comp          \
	perlasm ec engine ocsp   \
	ui

Sources = \
	cryptlib.c \
	mem.c \
	mem_clr.c \
	mem_dbg.c \
	cversion.c \
	ex_data.c \
	tmdiff.c \
	cpt_err.c \
	ebcdic.c \
	uid.c \
	o_time.c

opensslinclude_HEADERS= \
	crypto.h \
	tmdiff.h \
	opensslv.h \
	opensslconf.h \
	ebcdic.h \
	symhacks.h \
	ossl_typ.h

noinst_HEADERS= \
	cryptlib.h \
	md32_common.h \
	o_time.h


lib_LTLIBRARIES = libcrypto_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libcrypto___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libcrypto___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	$(GPT_LIB_LINKS) \
	md5/libmd5_$(GLOBUS_FLAVOR_NAME).la \
	sha/libsha_$(GLOBUS_FLAVOR_NAME).la \
	mdc2/libmdc2_$(GLOBUS_FLAVOR_NAME).la \
	hmac/libhmac_$(GLOBUS_FLAVOR_NAME).la \
	des/libdes_$(GLOBUS_FLAVOR_NAME).la \
	bf/libbf_$(GLOBUS_FLAVOR_NAME).la \
	cast/libcast_$(GLOBUS_FLAVOR_NAME).la \
	bn/libbn_$(GLOBUS_FLAVOR_NAME).la \
	rsa/librsa_$(GLOBUS_FLAVOR_NAME).la \
        dso/libdso_$(GLOBUS_FLAVOR_NAME).la \
	buffer/libbuffer_$(GLOBUS_FLAVOR_NAME).la \
	bio/libbio_$(GLOBUS_FLAVOR_NAME).la \
	stack/libstack_$(GLOBUS_FLAVOR_NAME).la \
	lhash/liblhash_$(GLOBUS_FLAVOR_NAME).la \
	rand/librand_$(GLOBUS_FLAVOR_NAME).la \
	err/liberr_$(GLOBUS_FLAVOR_NAME).la \
	objects/libobjects_$(GLOBUS_FLAVOR_NAME).la \
	evp/libevp_$(GLOBUS_FLAVOR_NAME).la \
	asn1/libasn1_$(GLOBUS_FLAVOR_NAME).la \
	pem/libpem_$(GLOBUS_FLAVOR_NAME).la \
	x509/libx509_$(GLOBUS_FLAVOR_NAME).la \
	x509v3/libx509v3_$(GLOBUS_FLAVOR_NAME).la \
	conf/libconf_$(GLOBUS_FLAVOR_NAME).la \
	txt_db/libtxt_db_$(GLOBUS_FLAVOR_NAME).la \
	pkcs7/libpkcs7_$(GLOBUS_FLAVOR_NAME).la \
	pkcs12/libpkcs12_$(GLOBUS_FLAVOR_NAME).la \
	comp/libcomp_$(GLOBUS_FLAVOR_NAME).la \
	ec/libec_$(GLOBUS_FLAVOR_NAME).la \
	engine/libengine_$(GLOBUS_FLAVOR_NAME).la \
	ocsp/libocsp_$(GLOBUS_FLAVOR_NAME).la \
	ui/libui_$(GLOBUS_FLAVOR_NAME).la

libcrypto___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

if !MINIMAL_SSL
SUBDIRS += idea aes rc2 rc4 rc5 md2 md4 ripemd dsa krb5 dh
libcrypto___GLOBUS_FLAVOR_NAME__la_LIBADD += \
	idea/libidea_$(GLOBUS_FLAVOR_NAME).la \
	aes/libaes_$(GLOBUS_FLAVOR_NAME).la \
	rc2/librc2_$(GLOBUS_FLAVOR_NAME).la \
	rc4/librc4_$(GLOBUS_FLAVOR_NAME).la \
	rc5/librc5_$(GLOBUS_FLAVOR_NAME).la \
	md2/libmd2_$(GLOBUS_FLAVOR_NAME).la \
	dh/libdh_$(GLOBUS_FLAVOR_NAME).la \
	md4/libmd4_$(GLOBUS_FLAVOR_NAME).la \
	ripemd/libripemd_$(GLOBUS_FLAVOR_NAME).la \
	dsa/libdsa_$(GLOBUS_FLAVOR_NAME).la \
	krb5/libkrb5_$(GLOBUS_FLAVOR_NAME).la
endif


EXTRA_DIST = buildinf.h.in opensslconf.h.in

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
