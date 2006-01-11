prefix=$(GPT_LOCATION)

sbin_SCRIPTS = 	\
	perl/scripts/gpt-build \
	perl/scripts/gpt_build_config \
	perl/scripts/gpt-bundle \
	perl/scripts/gpt-config \
	perl/scripts/gpt_create_automake_rules \
        perl/scripts/gpt-deps \
        perl/scripts/gpt_extract_data \
        perl/scripts/gpt-filelist-convert \
        perl/scripts/gpt-filelist-copy \
        perl/scripts/gpt-file-remove \
	perl/scripts/gpt-flavor-configuration \
	perl/scripts/gpt_generate_bin_pkg_data \
	perl/scripts/gpt_get_lib_names \
	perl/scripts/gpt-install \
	perl/scripts/gpt-md5 \
        perl/scripts/gpt-perl-version \
	perl/scripts/gpt-pkg \
	perl/scripts/gpt-postinstall \
	perl/scripts/gpt_save_flavor \
	perl/scripts/gpt-query \
	perl/scripts/gpt-setup \
	perl/scripts/gpt_sort_filelist \
	perl/scripts/gpt-undefines \
	perl/scripts/gpt-uninstall \
	perl/scripts/gpt-update \
	perl/scripts/gpt-verify \
	perl/scripts/gpt-virtual-pkg \
	perl/scripts/gpt_version


gptdatadir = ${prefix}/etc/gpt

gptdata_DATA = gpt_scripts_list

gptexecsharedir = ${prefix}/share/gpt

gptexecshare_SCRIPTS = config.guess

gptmodulesdir = ${prefix}/lib/perl/Grid/GPT

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


amdirdir = $(datadir)/gpt/amdir

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


pkg_confdir = $(sysconfdir)/gpt
dtddir = $(sysconfdir)/gpt/dtd
aclocaldir = $(datadir)/gpt/aclocal

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
	etc/gpt_autoconf_macros.m4 \
	etc/Makefile_am.frg \
	etc/bootstrap.frg \
	etc/configure_in.frg \
	etc/pkg_data_src_gpt_in.frg \
	etc/top_Makefile_am.frg

libexec_SCRIPTS = \
	etc/gpt-bootstrap.sh

install-man: install-pod2man
install-data-hook: install-localize hack-for-globus-core

install-localize:
	@echo "Localizing scripts to $(PERL)"
	$(PERL) $(DESTDIR)$(sbindir)/gpt-config -perl=$(PERL) \
	-probe \
	-ignore-errors

install-pod2man:
	@if test "X$(POD2MAN)" != "X"; then \
		$(mkinstalldirs) $(DESTDIR)man/man1; \
		list='$(sbin_SCRIPTS)'; for p in $$list; do \
	  		script=`echo $$p | sed 's!perl/scripts/!!'`; \
	  		echo "Generating $(DESTDIR)$(prefix)/man/man1/$$script.1"; \
	  		$(POD2MAN) $$p > $(DESTDIR)$(prefix)/man/man1/$$script.1; \
		done \
	else \
		echo "Skipping Man page installation"; \
	fi

hack-for-globus-core:
	@if test ! -h $(datadir)/globus_aclocal; then \
		startdir=`pwd`; \
		cd $(datadir); \
		$(LN_S) gpt/aclocal globus_aclocal; \
		cd $$startdir; \
	fi; \
	if test ! -h $(datadir)/gpt_amdir; then \
		startdir=`pwd`; \
		cd $(datadir); \
		$(LN_S) gpt/amdir gpt_amdir; \
		cd $$startdir; \
	fi

gpt_scripts_list: Makefile.am
	@echo "Creating script list"
	@echo $(sbin_SCRIPTS) | sed 's!perl/scripts/!!g'> $(top_builddir)/gpt_scripts_list

