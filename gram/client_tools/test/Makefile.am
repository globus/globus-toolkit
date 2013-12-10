SUBDIRS = pkgdata 

ScriptsIn = \
	TESTS.pl.in \
	globus-gram-client-tools-local-test.pl.in \
	globus-gram-client-tools-remote-test.pl.in

test_SCRIPTS = \
	TESTS.pl \
	globus-gram-client-tools-local-test.pl \
	globus-gram-client-tools-remote-test.pl


test_DATA = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem

EXTRA_DIST = dirt.sh $(ScriptsIn) $(test_Data)
