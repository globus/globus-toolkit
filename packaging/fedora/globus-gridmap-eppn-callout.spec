Name:		globus-gridmap-eppn-callout
%global _name %(tr - _ <<< %{name})
Version:	1.10
Release:	1%{?dist}
Vendor:	Globus Support
Summary:	Globus Toolkit - Globus gridmap eppn callout.

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://toolkit.globus.org/
Source:	http://toolkit.globus.org/ftppub/gt6/packages/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common%{?_isa} >= 14
BuildRequires:	globus-gsi-sysconfig-devel >= 5
BuildRequires:	globus-gss-assist-devel >= 8
BuildRequires:	globus-gridmap-callout-error-devel
BuildRequires:	globus-gssapi-gsi-devel >= 9
BuildRequires:	globus-gsi-credential-devel >= 6
BuildRequires:	globus-gsi-cert-utils-devel >= 8
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:  automake >= 1.11
BuildRequires:  autoconf >= 2.60
BuildRequires:  libtool >= 2.2
%endif
BuildRequires:  pkgconfig

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus gridmap eppn callout.

%prep
%setup -q -n %{_name}-%{version}

%build
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
# Remove files that should be replaced during bootstrap
rm -rf autom4te.cache

autoreconf -if
%endif


%configure \
           --disable-static \
           --docdir=%{_docdir}/%{name}-%{version} \
           --includedir=%{_includedir}/globus \
           --libexecdir=%{_datadir}/globus

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;

%check
make %{?_smp_mflags} check

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%config(noreplace) %{_sysconfdir}/gridmap_eppn_callout-gsi_authz.conf
%{_libdir}/libglobus*

%changelog
* Tue May 03 2016 Globus Toolkit <support@globus.org> - 1.10-1
- Missing dependency

* Mon Dec 14 2015 Globus Toolkit <support@globus.org> - 1.9-1
- GT-373: add support for proxies to eppn callout

* Thu Aug 06 2015 Globus Toolkit <support@globus.org> - 1.8-2
- Add vendor

* Wed Jul 01 2015 Globus Toolkit <support@globus.org> - 1.8-1
- remove unused variable

* Thu Sep 25 2014 Globus Toolkit <support@globus.org> - 1.7-1
- Fix dependency version
- Quiet some autoconf/automake warnings

* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 1.6-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 1.5-2
- Fix Source path

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 1.5-1
- Merge changes from Mattias Ellert

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 1.4-1
- Version bump for consistency

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 1.3-1
- Packaging fixes, Warning Cleanup

* Tue Feb 25 2014 Globus Toolkit <support@globus.org> - 1.2-1
- Packaging fixes

* Fri Feb 14 2014 Globus Toolkit <support@globus.org> - 1.1-1
- Packaging fixes

* Wed Jan 22 2014 Globus Toolkit <support@globus.org> - 1.0-1
- Repackage for GT6 without GPT

* Mon Oct 28 2013 Globus Toolkit <support@globus.org> - 0.6-1
- Update dependencies for new credential functions

* Mon Oct 28 2013 Globus Toolkit <support@globus.org> - 0.5-2
- Update dependencies for new credential functions

* Fri Oct 25 2013 Globus Toolkit <support@globus.org> - 0.5-1
- Missing configure dependency on OpenSSL

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 0.4-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Mon Apr 15 2013 Globus Toolkit <support@globus.org> - 0.4-1
- verify sharing cert chain

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> - 0.3-2
- Update sharing to support a full cert chain at logon

* Tue Mar 12 2013 Globus Toolkit <support@globus.org> - 0.3-1
- Improve error message handling

* Tue Mar 05 2013 Globus Toolkit <support@globus.org> - 0.2-1
- Initial version
