AUTOMAKE_OPTIONS=foreign

INCLUDES=-I../source
CFLAGS=-g -O0
LDADD=../source/libxacml.la -lgsoap++ -lpthread -ldl

testdir = $(exec_prefix)/test/@PACKAGE@

test_PROGRAMS = xacml-request-test \
                xacml-resource-attribute-test \
                xacml-obligation-test \
                xacml-response-test \
                xacml-server-test \
                xacml-client-test \
                xacml-io-test

test_SCRIPTS = TESTS.pl \
               xacml-request-test.pl \
               xacml-resource-attribute-test.pl \
               xacml-response-test.pl \
               xacml-obligation-test.pl \
               xacml-server-test.pl \
               xacml-client-test.pl \
               xacml-io-test.pl

EXTRA_DIST = $(test_SCRIPTS)
