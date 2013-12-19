SUBDIRS = pkgdata 

globustestingperldir = $(perlmoduledir)/Globus/Testing

globustestingperl_DATA = Utilities.pm 
test_SCRIPTS = \
	test-toolkit testcred.pem b38b4d8c.0 \
	test-package b38b4d8c.signing_policy \
	global_security_descriptor.xml.in \
        5dda73d8.0 5dda73d8.signing_policy \
	usercert.pem userkey.pem \
        testcred-env.sh testcred-setup.sh

EXTRA_DIST = \
        dirt.sh \
        Utilities.pm.in \
	test-toolkit.in \
        testcred.pem \
        b38b4d8c.0 \
	test-package.in \
        b38b4d8c.signing_policy \
        5dda73d8.0 \
        5dda73d8.signing_policy \
	global_security_descriptor.xml.in \
	usercert.pem userkey.pem \
        testcred-env.sh.in testcred-setup.sh.in
