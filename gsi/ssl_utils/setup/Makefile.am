include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

#stu commented out
#secsysconfdir = /etc/grid-security
## secsysconf = [ DATA ]

#stu commented out
#cacertdir = /etc/grid-security/certificates
## cacert = [ DATA ]

Scripts = \
	setup-ssl-utils-sh-scripts \
	setup-ssl-utils \
	setup-ssl-utils.pl \
	setup-gsi \
	setup-gsi.pl \
	grid-cert-request-config.in \
	grid-security-config.in


setup_SCRIPTS = $(Scripts)

setup_DATA = \
	globus-ssl.conf \
	grid-security.conf \
	42864e48.0 \
	42864e48.signing_policy

#stu commented out
#secsysconf_DATA = \
#	grid-security.conf 

#stu commented out
#cacert_DATA = \
#	42864e48.0 \
#	42864e48.signing_policy

SUBDIRS = pkgdata

EXTRA_DIST = \
	$(Scripts) \
	grid-security.conf \
	globus-ssl.conf \
	42864e48.0 \
	42864e48.signing_policy

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
