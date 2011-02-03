pkg_confdir = @pkg_confdir@
aclocaldir = @aclocaldir@

pkg_conf_DATA = \
    globus_flavor_labels.conf \
    globus_core-src.tar.gz \
    gpt_rpm.spec

gpt_rpm.spec: gpt_rpm.spec.template
	cp $(srcdir)/gpt_rpm.spec.template gpt_rpm.spec

aclocal_DATA = gpt_autoconf_macros.m4

libexec_SCRIPTS = gpt-bootstrap.sh

EXTRA_DIST = \
    globus_flavor_labels.conf \
    globus_core-src.tar.gz \
    gpt_rpm.spec.template \
    $(aclocal_DATA) \
    $(libexec_SCRIPTS) 
