check_PROGRAMS = \
        cmp_alias_ent_test \
        ipc-test \
        sharing_allowed_test

check_DATA = \
        testcred.key \
        testcred.cert \
        testcred.cakey \
        testcred.cacert \
        testcred.link \
        testcred.signing_policy \
        testcred.srl

check_SCRIPTS = setup-chroot-test

TESTS = \
	cmp_alias_ent_test\
	ipc-test \
	setup-chroot-test \
	sharing_allowed_test
TESTS_ENVIRONMENT = \
	export X509_CERT_DIR="$(abs_builddir)/certificates" \
	       PATH="$(abs_srcdir)/..:$$PATH";
LOG_COMPILER = $(FAKEROOT) ../libtool --mode=execute $(MODULE_DLOPEN)

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(srcdir)/..
LDADD = ../libglobus_gridftp_server.la \
        $(MODULE_DLPREOPEN) $(PACKAGE_DEP_LIBS) -lltdl

AM_LDFLAGS = -dlpreopen force

# Test CA
.cnf.cacert:
	umask 077; openssl req -passout pass:globus -subj "/CN=ca" -new -x509 -extensions v3_ca -keyout $*.cakey -out $@ -config $<
.cacert.cakey:

.cacert.link:
	linkname="`openssl x509 -hash -noout -in $<`.0"; \
	rm -f "$$linkname"; \
	cp $< "$$linkname"; \
        echo "$$linkname" > $@; \
	$(MKDIR_P) certificates; \
	cp $${linkname} certificates

.link.signing_policy:
	linkname=`cat $<`; \
	policyfile=$${linkname%.0}.signing_policy; \
	echo "access_id_CA      X509         '/CN=ca'" > $${policyfile}; \
	echo "pos_rights        globus        CA:sign" >> $${policyfile}; \
	echo "cond_subjects     globus       '\"/*\"'" >> $${policyfile}; \
	echo $${policyfile} >> $@; \
	$(MKDIR_P) certificates; \
	cp $${policyfile} certificates

.signing_policy.srl:
	echo 01 > $@

# Test Cert/Key
.srl.key:
	umask 077; openssl genrsa -out $@ 1024
.key.req:
	openssl req -subj "/CN=test" -new -key $< -out $@ -config $*.cnf

.req.cert:
	umask 022; openssl x509 -passin pass:globus -req -days 365 -in testcred.req -CA $*.cacert -CAkey $*.cakey -out $@


SUFFIXES = .key .req .cert .srl .link .signing_policy .cacert .cakey

CLEANFILES = testcred.key testcred.cert testcred.req \
	     testcred.cacert testcred.srl \
	     testcred.cakey

clean-local:
	if [ -f testcred.link ]; then \
            rm -f "$$(cat testcred.link)" testcred.link; \
        fi
	if test -f testcred.signing_policy; then \
	    rm -f $$(cat testcred.signing_policy) testcred.signing_policy; \
	fi
	rm -rf certificates

EXTRA_DIST = $(check_SCRIPTS)
