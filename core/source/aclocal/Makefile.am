aclocaldir = $(GLOBUS_INSTALL_PATH)/share/globus_aclocal

aclocal_DATA = globus_package.m4 \
	automake_targets

EXTRA_DIST = $(aclocal_DATA)

install-data-local:
	touch $(aclocaldir)/automake_rules