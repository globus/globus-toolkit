include $(top_srcdir)/aclocal/automake_targets
aclocaldir = $(GLOBUS_INSTALL_PATH)/share/globus_aclocal

aclocal_DATA = globus_package.m4 \
	automake_targets \
	automake_top_rules \
	automake_rules \
	automake_config

EXTRA_DIST = $(aclocal_DATA) \
	create_automake_rules.pl \
	data.am \
	filelist.am \
	header.am \
	libs.am \
	ltlib.am \
	progs.am \
	scripts.am \
	subdirs.am

include $(top_srcdir)/aclocal/automake_rules
