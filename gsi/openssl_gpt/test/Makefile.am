include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Test_Sources = \
	pkcs7-1.pem \
	pkcs7.pem \
	testcrl.pem \
	testp7.pem \
	testreq2.pem \
	testrsa.pem \
	testsid.pem \
	testx509.pem \
	v3-cert1.pem \
	v3-cert2.pem \
	CAss.cnf \
	CAssdh.cnf \
	CAssdsa.cnf \
	CAssrsa.cnf \
	Sssdsa.cnf \
	Sssrsa.cnf \
	Uss.cnf \
	test.cnf \
	tx509 \
	trsa \
	tcrl \
	tsid \
	treq \
	testreq2.pem \
	tpkcs7 \
	tpkcs7d \
	bctest \
	testenc \
	testgen \
	testss \
	testssl \
	testca

Test_Programs = \
	exptest \
	bntest \
	ideatest \
	shatest \
	sha1test \
	mdc2test \
	rmdtest \
	md2test \
	md4test \
	md5test \
	hmactest \
	rc2test \
	rc4test \
	rc5test \
	bftest \
	casttest \
	destest \
	randtest \
	dhtest \
	dsatest \
	ssltest \
	rsa_test \
	evp_test \
	ectest \
	enginetest \
	dummytest 

Test_Targets = \
	test_des \
	test_idea \
	test_sha \
	test_md4 \
	test_md5 \
	test_hmac \
	test_md2 \
	test_mdc2 \
	test_rmd \
	test_rc2 \
	test_rc4 \
	test_rc5 \
	test_bf \
	test_cast \
	test_rand \
	test_bn \
	test_enc \
	test_x509 \
	test_rsa \
	test_crl \
	test_sid \
	test_gen \
	test_req \
	test_pkcs7 \
	test_verify \
	test_dh \
	test_dsa \
	test_ss \
	test_ca \
	test_ssl \
	test_ec \
	test_engine \
	test_evp

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

LDADD = $(top_srcdir)/ssl/libssl_$(GLOBUS_FLAVOR_NAME).la $(top_srcdir)/crypto/libcrypto_$(GLOBUS_FLAVOR_NAME).la $(GPT_LIB_LINKS)

LDFLAGS = $(GPT_LDFLAGS)

noinst_PROGRAMS = $(Test_Programs)

nodist_exptest_SOURCES = exptest.c
nodist_bntest_SOURCES = bntest.c
nodist_ideatest_SOURCES = ideatest.c
nodist_shatest_SOURCES = shatest.c
nodist_sha1test_SOURCES = sha1test.c
nodist_mdc2test_SOURCES = mdc2test.c
nodist_rmdtest_SOURCES = rmdtest.c
nodist_md2test_SOURCES = md2test.c
nodist_md4test_SOURCES = md4test.c
nodist_md5test_SOURCES = md5test.c
nodist_hmactest_SOURCES = hmactest.c
nodist_rc2test_SOURCES = rc2test.c
nodist_rc4test_SOURCES = rc4test.c
nodist_rc5test_SOURCES = rc5test.c
nodist_bftest_SOURCES = bftest.c
nodist_casttest_SOURCES = casttest.c
nodist_destest_SOURCES = destest.c
nodist_randtest_SOURCES = randtest.c
nodist_dhtest_SOURCES = dhtest.c
nodist_dsatest_SOURCES = dsatest.c
nodist_ssltest_SOURCES = ssltest.c
nodist_rsa_test_SOURCES = rsa_test.c
nodist_ectest_SOURCES = ectest.c
nodist_enginetest_SOURCES = enginetest.c
nodist_evp_test_SOURCES = evp_test.c
dummytest_SOURCES = dummytest.c

tests: $(Test_Programs) $(Test_Targets)

test_des:
	./destest

test_idea:
	./ideatest

test_sha:
	./shatest
	./sha1test

test_mdc2:
	./mdc2test

test_md5:
	./md5test

test_md4:
	./md4test

test_hmac:
	./hmactest

test_md2:
	./md2test

test_rmd:
	./rmdtest

test_bf:
	./bftest

test_cast:
	./casttest

test_rc2:
	./rc2test

test_rc4:
	./rc4test

test_rc5:
	./rc5test

test_rand:
	./randtest

test_ec:
	./ectest

test_engine:
	./enginetest

test_evp:
	./evp_test evptests.txt

test_enc:
	@sh ./testenc

test_x509:
	echo test normal x509v1 certificate
	sh ./tx509 2>/dev/null
	echo test first x509v3 certificate
	sh ./tx509 v3-cert1.pem 2>/dev/null
	echo test second x509v3 certificate
	sh ./tx509 v3-cert2.pem 2>/dev/null

test_rsa:
	@sh ./trsa 2>/dev/null
	./rsa_test

test_crl:
	@sh ./tcrl 2>/dev/null

test_sid:
	@sh ./tsid 2>/dev/null

test_req:
	@sh ./treq 2>/dev/null
	@sh ./treq testreq2.pem 2>/dev/null

test_pkcs7:
	@sh ./tpkcs7 2>/dev/null
	@sh ./tpkcs7d 2>/dev/null

test_bn:
	@echo starting big number library test, could take a while...
	@./bntest >tmp.bntest
	@echo quit >>tmp.bntest
	@echo "running bc"
	@<tmp.bntest sh -c "`sh ./bctest ignore`" | $(PERL) -e '$$i=0; while (<STDIN>) {if (/^test (.*)/) {print STDERR "\nverify $$1";} elsif (!/^0$$/) {die "\nFailed! bc: $$_";} else {print STDERR "."; $$i++;}} print STDERR "\n$$i tests passed\n"'
	@echo 'test a^b%c implementations'
	./exptest

test_verify:
	@echo "The following command should have some OK's and some failures"
	@echo "There are definitly a few expired certificates"
	../apps/openssl verify -CApath ../certs ../certs/*.pem

test_dh:
	@echo "Generate a set of DH parameters"
	./dhtest

test_dsa:
	@echo "Generate a set of DSA parameters"
	./dsatest
	./dsatest -app2_1

test_gen:
	@echo "Generate and verify a certificate request"
	@sh ./testgen

test_ss keyU.ss certU.ss certCA.ss: testss
	@echo "Generate and certify a test certificate"
	@sh ./testss

test_ssl: keyU.ss certU.ss certCA.ss
	@echo "test SSL protocol"
	@sh ./testssl keyU.ss certU.ss certCA.ss

test_ca:
	@if ../apps/openssl no-rsa; then \
	  echo "skipping CA.sh test -- requires RSA"; \
	else \
	  echo "Generate and certify a test certificate via the 'ca' program"; \
	  sh ./testca; \
	fi

clean-local:
	rm -f .rnd tmp.bntest tmp.bctest *.old *.bak fluff *.ss log

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_openssl_post


