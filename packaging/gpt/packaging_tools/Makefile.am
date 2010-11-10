sbin_SCRIPT_sources = 	\
        perl/scripts/gpt-build.in \
        perl/scripts/gpt-bundle.in \
        perl/scripts/gpt-config.in \
        perl/scripts/gpt-install.in \
        perl/scripts/gpt-pkg.in \
        perl/scripts/gpt-postinstall.in \
        perl/scripts/gpt-query.in \
        perl/scripts/gpt-uninstall.in \
        perl/scripts/gpt-verify.in \
        perl/scripts/gpt_build_config.in \
        perl/scripts/gpt_create_automake_rules.in \
        perl/scripts/gpt_extract_data.in \
        perl/scripts/gpt_generate_bin_pkg_data.in \
        perl/scripts/gpt_save_flavor.in \
        perl/scripts/gpt_sort_filelist.in \
        perl/scripts/gpt_version.in

sbin_SCRIPT_nosources =
	perl/scripts/gpt_get_lib_names \
        perl/scripts/gpt-perl-version

documented_scripts = \
	perl/scripts/gpt-build \
        perl/scripts/gpt-bundle \
        perl/scripts/gpt-config \
        perl/scripts/gpt-install \
        perl/scripts/gpt-pkg \
        perl/scripts/gpt-postinstall \
        perl/scripts/gpt-query \
        perl/scripts/gpt-uninstall \
        perl/scripts/gpt-verify \
        perl/scripts/gpt_build_config \
        perl/scripts/gpt_extract_data

undocumented_scripts = \
        perl/scripts/gpt-perl-version \
        perl/scripts/gpt_create_automake_rules \
        perl/scripts/gpt_generate_bin_pkg_data \
        perl/scripts/gpt_get_lib_names \
        perl/scripts/gpt_save_flavor \
        perl/scripts/gpt_sort_filelist \
        perl/scripts/gpt_version

man8_MANS = 
if INSTALL_MANS
man8_MANS += \
    $(builddir)/gpt-build.8 \
    $(builddir)/gpt-bundle.8 \
    $(builddir)/gpt-config.8 \
    $(builddir)/gpt-install.8 \
    $(builddir)/gpt-pkg.8 \
    $(builddir)/gpt-postinstall.8 \
    $(builddir)/gpt-query.8 \
    $(builddir)/gpt-uninstall.8 \
    $(builddir)/gpt-verify.8 \
    $(builddir)/gpt_build_config.8 \
    $(builddir)/gpt_extract_data.8
endif

sbin_SCRIPTS = 	$(documented_scripts) $(undocumented_scripts)

gptdatadir = @gptdatadir@

gptdata_DATA = $(top_builddir)/gpt_scripts_list

gptexecsharedir = @gptexecsharedir@

gptexecshare_SCRIPTS = config.guess

gptmodulesdir = $(perlmoduledir)/Grid/GPT

gptmodules_DATA = \
	perl/GPT/Algorithms.pm \
	perl/GPT/BaseNode.pm \
	perl/GPT/BaseTable.pm \
	perl/GPT/BuildLine.pm \
	perl/GPT/BundleInstallation.pm \
	perl/GPT/BundleSet.pm \
	perl/GPT/DepIndexes.pm \
	perl/GPT/DepNode.pm \
	perl/GPT/FilelistFunctions.pm \
	perl/GPT/Filelist.pm \
	perl/GPT/FilelistSort.pm \
	perl/GPT/GPTFilelist.pm \
	perl/GPT/GPTIdentity.pm \
	perl/GPT/GPTObject.pm \
	perl/GPT/Installation.pm \
	perl/GPT/LocalEnv.pm.in \
	perl/GPT/Localize.pm \
	perl/GPT/Locations.pm \
	perl/GPT/MatchNode.pm \
	perl/GPT/MD5.pm \
	perl/GPT/MyFilelists.pm \
	perl/GPT/PackageFactory.pm \
	perl/GPT/PackageFilelist.pm \
	perl/GPT/PackageFile.pm \
	perl/GPT/PkgDefNode.pm \
	perl/GPT/PkgDefsSet.pm \
	perl/GPT/PkgDist.pm \
	perl/GPT/PkgFileName.pm \
	perl/GPT/PkgMngmt.pm \
	perl/GPT/PkgNode.pm \
	perl/GPT/PkgSet.pm \
	perl/GPT/SetFunctions.pm \
	perl/GPT/SetupInstallation.pm \
	perl/GPT/Setup.pm

v1modulesdir = ${gptmodulesdir}/V1
v1modules_DATA = \
	perl/GPT/V1/BaseDependency.pm \
	perl/GPT/V1/BinaryDependency.pm \
	perl/GPT/V1/BuildFlavors.pm \
	perl/GPT/V1/Bundle.pm \
	perl/GPT/V1/Definitions.pm \
	perl/GPT/V1/FlavorBase.pm \
	perl/GPT/V1/FlavorChoices.pm \
	perl/GPT/V1/FlavorDefinition.pm \
	perl/GPT/V1/Package.pm \
	perl/GPT/V1/SourceDependency.pm \
	perl/GPT/V1/Version.pm \
	perl/GPT/V1/XML.pm

pkgmntmodulesdir = ${gptmodulesdir}/PkgMngmt
pkgmntmodules_DATA = \
	perl/GPT/PkgMngmt/Archive.pm \
	perl/GPT/PkgMngmt/BuildMacros.pm \
	perl/GPT/PkgMngmt/Build.pm \
	perl/GPT/PkgMngmt/ExpandSource.pm \
	perl/GPT/PkgMngmt/FlavorMacros.pm \
	perl/GPT/PkgMngmt/Inform.pm \
	perl/GPT/PkgMngmt/SetupBuildFlavors.pm

filelistmodulesdir = ${gptmodulesdir}/PackageFilelist
filelistmodules_DATA = \
	perl/GPT/PackageFilelist/FileIO.pm \
	perl/GPT/PackageFilelist/flat1.pm \
	perl/GPT/PackageFilelist/List.pm \
	perl/GPT/PackageFilelist/xml1.pm



fileiomodulesdir = ${filelistmodulesdir}/FileIO
fileiomodules_DATA = \
	perl/GPT/PackageFilelist/FileIO/Disk.pm \
	perl/GPT/PackageFilelist/FileIO/Tar.pm


flat1modulesdir = ${filelistmodulesdir}/flat1
flat1modules_DATA = \
	perl/GPT/PackageFilelist/flat1/IO.pm \
	perl/GPT/PackageFilelist/flat1/ListInterface.pm

xml1modulesdir = ${filelistmodulesdir}/xml1
xml1modules_DATA = \
	perl/GPT/PackageFilelist/xml1/IO.pm \
	perl/GPT/PackageFilelist/xml1/ListInterface.pm


amdirdir = @amdir@

amdir_DATA = \
	amdir/data.am \
	amdir/filelist.am \
	amdir/header.am \
	amdir/libs.am \
	amdir/ltlib.am \
	amdir/mans.am \
	amdir/progs.am \
	amdir/scripts.am \
	amdir/subdirs.am \
	amdir/pkgdata_Makefile.am


pkg_confdir = @pkg_confdir@
dtddir = @dtddir@
aclocaldir = @aclocaldir@

pkg_conf_DATA = \
	etc/globus_flavor_labels.conf \
	etc/globus_core-src.tar.gz \
	etc/gpt_rpm.spec

dtd_DATA = \
	etc/globus_package.dtd \
	etc/globus_flavors.dtd \
	etc/gpt_bundle.dtd \
	etc/gpt_reservoir.dtd \
	etc/gpt_filelist.dtd

aclocal_DATA = \
	etc/gpt_autoconf_macros.m4

libexec_SCRIPTS = \
	etc/gpt-bootstrap.sh

install-data-hook: install-localize

install-localize:
	echo "Localizing scripts to $(PERL)"; \
	GLOBUS_LOCATION=$(DESTDIR)$(prefix) \
	GPT_LOCATION=$(DESTDIR)$(prefix) \
	PERLLIB=$(DESTDIR)$(perlmoduledir)$${PERLLIB:+:$$PERLLIB} \
	$(PERL) $(DESTDIR)$(sbindir)/gpt-config -perl=$(PERL) \
	-location=$(DESTDIR)$(prefix) \
	-probe \
	-ignore-errors

if INSTALL_MANS
$(man8_MANS): $(documented_scripts)
	list='$(documented_scripts)'; for p in $$list; do \
            $(POD2MAN) $(srcdir)/$$p > $(builddir)/`basename $$p`.8; \
        done
endif

$(top_builddir)/gpt_scripts_list: Makefile.am
	@echo "Creating script list"
	@echo $(sbin_SCRIPTS) | sed 's!perl/scripts/!!g'> $(top_builddir)/gpt_scripts_list


EXTRA_DIST = \
    $(sbin_SCRIPTS_sources) \
    $(sbin_SCRIPT_nosources) \
    $(gptexecshare_SCRIPTS) \
    $(gptmodules_DATA) \
    $(v1modules_DATA) \
    $(pkgmntmodules_DATA) \
    $(filelistmodules_DATA) \
    $(fileiomodules_DATA) \
    $(flat1modules_DATA) \
    $(xml1modules_DATA) \
    $(amdir_DATA) \
    $(pkg_conf_DATA) \
    $(dtd_DATA) \
    $(aclocal_DATA) \
    $(libexec_SCRIPTS)
