include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# the value of this variable gets replace when a specific
# ca package is generated
CACERT_HASH=__CACERT_HASH__

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
	$(CACERT_HASH).0 \
	$(CACERT_HASH).signing_policy

bin_SCRIPTS = \
        grid-default-ca

setup_SCRIPTS = $(Scripts)

setup_DATA = $(Data)

SUBDIRS = pkgdata

EXTRA_DIST = \
	$(Scripts) \
	$(Data) \
	grid-default-ca

TAR=@TAR@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
