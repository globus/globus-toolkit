include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

AM_CFLAGS = -DMONOLITH

Certs = \
	ca-key.pem \
	ca-req.pem \
	cert.pem \
	client.pem \
	dh1024.pem \
	dh2048.pem \
	dh4096.pem \
	dh512.pem \
	dsa-ca.pem \
	dsa-pca.pem \
	dsa1024.pem \
	dsa512.pem \
	dsap.pem \
	pca-key.pem \
	pca-req.pem \
	privkey.pem \
	req.pem \
	rsa8192.pem \
	s1024key.pem \
	s1024req.pem \
	s512-key.pem \
	s512-req.pem \
	server.pem \
	server2.pem \
	testCA.pem

Scripts = \
	CA.sh \
	CA.pl \
	der_chop

Modules = \
	verify.c \
	asn1pars.c \
	req.c \
	dgst.c \
	dh.c \
	dhparam.c \
	enc.c \
	passwd.c \
	gendh.c \
	errstr.c \
	ca.c \
	pkcs7.c \
	crl2p7.c \
	crl.c \
	rsa.c \
	rsautl.c \
	dsa.c \
	dsaparam.c \
	x509.c \
	genrsa.c \
	gendsa.c \
	s_server.c \
	s_client.c \
	speed.c \
	s_time.c \
	apps.c \
	s_cb.c \
	s_socket.c \
	app_rand.c \
	version.c \
	sess_id.c \
	ciphers.c \
	nseq.c \
	pkcs12.c \
	pkcs8.c \
	spkac.c \
	smime.c \
	rand.c \
	engine.c \
	ocsp.c

Subprograms = \
	verify \
	asn1pars \
	req \
	dgst \
	dh \
	dhparam \
	enc \
	passwd \
	gendh \
	errstr \
	ca \
	crl \
	rsa \
	rsautl \
	dsa \
	dsaparam \
	x509 \
	genrsa \
	gendsa \
	s_server \
	s_client \
	speed \
	s_time \
	version \
	pkcs7 \
	crl2pkcs7 \
	sess_id \
	ciphers \
	nseq \
	pkcs12 \
	pkcs8 \
	spkac \
	smime \
	rand \
	engine \
	ocsp

noinst_HEADERS = \
	apps.h \
	s_apps.h \
	testdsa.h \
	testrsa.h

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

bin_PROGRAMS = \
	openssl

bin_SCRIPTS = $(Scripts)

openssl_SOURCES = openssl.c $(Modules) 

openssl_LDADD = ../ssl/libssl_$(GLOBUS_FLAVOR_NAME).la \
		../crypto/libcrypto_$(GLOBUS_FLAVOR_NAME).la \
		@GPT_PGM_LINKS@

openssl_LDFLAGS = @GPT_LDFLAGS@

openssl.o: progs.h openssl.c
	$(COMPILE) -c openssl.c

progs.h: progs.pl
	$(PERL) progs.pl $(Subprograms) >progs.h

EXTRA_DIST = progs.pl openssl.cnf $(Scripts) $(Certs) CA.pl.in

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post












