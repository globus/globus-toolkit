include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

Scripts = \
	setup-ssl-utils \
	setup-ssl-utils.pl \
	setup-gsi \
	setup-gsi.pl \
	grid-cert-request-config.in \
        grid-security-config.in \
	setup-ssl-utils-sh-scripts


setup_SCRIPTS = $(Scripts)

setup_DATA = \
	globus-ssl.conf \
	grid-security.conf.42864e48 \
	42864e48.0 \
	42864e48.signing_policy

CONFIG_FILES = \
        setup-ssl-utils-sh-scripts.in \
        grid-cert-request-config.in \
        grid-security-config.in 

SUBDIRS = pkgdata

EXTRA_DIST = \
	$(Scripts) \
	grid-security.conf.42864e48 \
	globus-ssl.conf \
	42864e48.0 \
	42864e48.signing_policy \
        $(CONFIG_FILES)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
