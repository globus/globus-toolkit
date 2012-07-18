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

builddir = $(top_builddir)/$(subdir)

if INSTALL_MANS
man8_MANS += \
    $(builddir)/gpt-build.8 \
    $(builddir)/gpt-bundle.8 \
    $(builddir)/gpt-install.8 \
    $(builddir)/gpt-pkg.8 \
    $(builddir)/gpt-postinstall.8 \
    $(builddir)/gpt-query.8 \
    $(builddir)/gpt-uninstall.8 \
    $(builddir)/gpt-verify.8 \
    $(builddir)/gpt_build_config.8 \
    $(builddir)/gpt_extract_data.8
endif

$(builddir)/%.8: $(srcdir)/%
	$(POD2MAN) --section 8 $< > $@;

EXTRA_DIST = gpt-to-pkgconfig $(man8_MANS)

DISTCLEANFILES = $(man8_MANS)
