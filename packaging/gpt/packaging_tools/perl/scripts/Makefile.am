sbin_SCRIPT_sources = 	\
        gpt-build.in \
        gpt-bundle.in \
        gpt-install.in \
        gpt-pkg.in \
        gpt-postinstall.in \
        gpt-query.in \
        gpt-uninstall.in \
        gpt-verify.in \
        gpt_build_config.in \
        gpt_create_automake_rules.in \
        gpt_extract_data.in \
        gpt_generate_bin_pkg_data.in \
	gpt_get_lib_names.in \
        gpt_save_flavor.in \
        gpt_sort_filelist.in \
	gpt-to-pkgconfig \
        gpt_version.in

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

sbin_SCRIPTS = 	$(documented_scripts) $(undocumented_scripts)

EXTRA_DIST = $(sbin_SCRIPT_sources)

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

$(man8_MANS): $(documented_scripts)
	list='$(documented_scripts)'; for p in $$list; do \
            $(POD2MAN) $(srcdir)/$$p > $(builddir)/`basename $$p`.8; \
        done
endif

if INSTALL_MANS
EXTRA_DIST += $(man8_MANS)
install-data-hook: install-man
endif
