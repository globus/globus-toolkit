include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

secsysconfdir = /etc/grid-security
## secsysconf = [ DATA ]

cacertdir = /etc/grid-security/certificates
## cacert = [ DATA ]

setup_SCRIPTS = \
	setup-ssl_utils-sh-scripts \
	setup-ssl_utils \
	setup-ssl_utils.pl

setup_DATA = \
	grid-cert-request-config.in \
	grid-security-config.in \
	globus-ssl.conf

secsysconf_DATA = \
	grid-security.conf 

cacert_DATA = \
	42864e48.0 \
	42864e48.signing_policy

SUBDIRS = pkgdata

EXTRA_DIST = \
	setup-ssl_utils-sh-scripts \
	setup-ssl_utils \
	setup-ssl_utils.pl \
	grid-cert-request-config.in \
	grid-security-config.in \
	grid-security.conf

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top



