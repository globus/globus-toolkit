## Process this file with automake to produce Makefile.in.

all:

MY_TESTS = simple_dep.sh

EXTRA_DIST = ${MY_TESTS} generate_parameter_files.sh

noinst_SCRIPTS = ${MY_TESTS}

TESTS_ENVIRONMENT = GLOBUS_INSTALL_PATH="$(top_builddir)/tests/globus"

TESTS = ${MY_TESTS}

clean-local:
	rm -r ./globus
