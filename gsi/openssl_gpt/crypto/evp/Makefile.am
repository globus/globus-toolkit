include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	encode.c \
	digest.c \
	evp_enc.c \
	evp_acnf.c \
	evp_key.c \
	e_des.c \
	e_bf.c \
	e_des3.c \
	names.c \
	e_xcbc_d.c \
	e_cast.c \
	m_null.c \
	m_sha1.c \
	m_dss.c \
	m_dss1.c \
	m_mdc2.c \
	p_open.c \
	p_seal.c \
	p_sign.c \
	p_verify.c \
	p_lib.c \
	p_enc.c \
	p_dec.c \
	bio_md.c \
	bio_b64.c \
	bio_enc.c \
	evp_err.c \
	e_null.c \
	c_all.c \
	c_allc.c \
	c_alld.c \
	evp_lib.c \
	bio_ok.c \
	evp_pkey.c \
	evp_pbe.c \
	p5_crpt.c \
	p5_crpt2.c

if !MINIMAL_SSL
    Sources += e_idea.c \
	e_rc4.c \
	e_rc2.c \
	e_rc5.c \
	e_aes.c \
	m_md2.c \
	m_md4.c \
	m_md5.c \
	m_ripemd.c \
	m_sha.c
endif

opensslinclude_HEADERS= \
	evp.h

noinst_HEADERS = \
	evp_locl.h

Test_Sources = \
	evp_test.c \
	evptests.txt

noinst_LTLIBRARIES = libevp_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libevp___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libevp___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libevp___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
