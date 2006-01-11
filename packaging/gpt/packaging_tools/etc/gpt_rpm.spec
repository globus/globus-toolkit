#
#  Spec file template for GPT. 
#
#########################################################################
Summary: GPT_SUMMARY_GPT
Name: GPT_PACKAGE_GPT
Version: GPT_VERSION_GPT
Release: GPT_PKG_RELEASE_GPT
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
Copyright: GPT_LICENSE_GPT
Group: NMI
Source:GPT_FTPSITE_GPT/GPT_PACKAGE_GPT-GPT_VERSION_GPT-rpm.tar.gz
URL: GPT_URL_GPT
Vendor: GPT_VENDOR_GPT
Packager: GPT_PACKAGER_GPT
Prefix: GPT_PREFIX_GPT
AutoReqProv: no
GPT_REQUIRES_GPT
Provides: GPT_PROVIDES_GPT

#########################################################################
%description
GPT_DESCRIPTION_GPT

#########################################################################
%prep
# unpack source .tar.gz package
%setup

#########################################################################
%build
GPT_INSTALL_LOCATION=${RPM_BUILD_ROOT}GPT_PREFIX_GPT; export GPT_INSTALL_LOCATION; $GPT_LOCATION/sbin/gpt-install --force ${RPM_SOURCE_DIR}/GPT_BIN_PKG_NAME_GPT

rm -f ${RPM_BUILD_ROOT}GPT_PREFIX_GPT/etc/gpt/packages/GPT_NAME_GPT/GPT_FLAVOR_GPTGPT_PKGTYPE_GPT.format


#########################################################################
%install

#########################################################################

%files

%defattr(-,root,root)

GPT_FILELIST_GPT

%defattr(-,root,root)

#########################################################################
%post
#########################################################################
%clean
test "$RPM_BUILD_ROOT" = "/" || rm -rf "$RPM_BUILD_ROOT"
