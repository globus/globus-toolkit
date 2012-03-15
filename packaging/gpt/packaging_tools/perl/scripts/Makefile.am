documented_scripts = \
	gpt-build \
	gpt-bundle \
	gpt-install \
	gpt-pkg \
	gpt-postinstall \
	gpt-query \
	gpt-uninstall \
	gpt-verify \
	gpt_build_config \
	gpt_extract_data

undocumented_scripts = \
	gpt_create_automake_rules \
	gpt_generate_bin_pkg_data \
	gpt_get_lib_names \
	gpt_save_flavor \
	gpt_sort_filelist \
	gpt-to-pkgconfig \
	gpt_version

sbin_SCRIPTS = $(documented_scripts) $(undocumented_scripts)

man8_MANS = 

if INSTALL_MANS
man8_MANS += \
    gpt-build.8 \
    gpt-bundle.8 \
    gpt-install.8 \
    gpt-pkg.8 \
    gpt-postinstall.8 \
    gpt-query.8 \
    gpt-uninstall.8 \
    gpt-verify.8 \
    gpt_build_config.8 \
    gpt_extract_data.8
endif

%.8: %
	$(POD2MAN) --section 8 $< > $@;

EXTRA_DIST = gpt-to-pkgconfig $(man8_MANS)

DISTCLEANFILES = $(man8_MANS)
