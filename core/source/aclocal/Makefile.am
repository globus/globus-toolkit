include $(top_srcdir)/aclocal/automake_targets
aclocaldir = $(GLOBUS_LOCATION)/share/globus_aclocal

aclocal_DATA = globus_package.m4 \
	acnetworking.m4 \
	acdoxygen.m4 \
	automake_targets \
	automake_top_rules \
	automake_rules \
	automake_doxygen_rules \
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

install-data-local:
	@if test ! -f "$(GLOBUS_LOCATION)/share/globus_aclocal/gpt_autoconf_macros.m4"; then \
		echo "linking GPT macros into Globus Installation"; \
		ln -s "$(GPT_LOCATION)/share/globus_aclocal/gpt_autoconf_macros.m4" \
		"$(GLOBUS_LOCATION)/share/globus_aclocal/gpt_autoconf_macros.m4"; \
	fi

include $(top_srcdir)/aclocal/automake_rules
