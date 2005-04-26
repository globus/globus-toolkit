include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# the value of this variable gets replace when a specific
# ca package is generated
CACERT_HASH=b38b4d8c

gcs_setupdir = ${GLOBUS_LOCATION}/setup/globus_gcs_${CACERT_HASH}_setup
## gcs_setup = [ SCRIPTS DATA ]

Scripts = \
	setup-ssl-utils-sh-scripts \
	setup-ssl-utils \
	setup-ssl-utils.pl \
	setup-gsi \
	setup-gsi.pl \
	grid-cert-request-config.in \
	grid-security-config.in \
	setup-ssl-utils-sh-scripts.in

Data = \
	grid-security.conf.$(CACERT_HASH) \
	globus-ssl.conf \
	directions \
	$(CACERT_HASH).0 \
	$(CACERT_HASH).signing_policy

gcs_setup_SCRIPTS = $(Scripts)

gcs_setup_DATA = $(Data)

setup_SCRIPTS = setup-ssl-utils.$(CACERT_HASH)

SUBDIRS = pkgdata

EXTRA_DIST = \
	$(Scripts) \
        $(Data) \
	setup-ssl-utils.$(CACERT_HASH) 

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
