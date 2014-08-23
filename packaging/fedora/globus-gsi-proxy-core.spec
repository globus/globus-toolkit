Name:		globus-gsi-proxy-core
%global _name %(tr - _ <<< %{name})
Version:	7.6
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus GSI Proxy Core Library

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:	http://www.globus.org/ftppub/gt6/packages/globus_gsi_proxy_core-7.6.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-gsi-proxy-ssl%{?_isa} >= 4
Requires:	globus-gsi-credential%{?_isa} >= 5
Requires:	globus-openssl-module%{?_isa} >= 3
Requires:	globus-gsi-openssl-error%{?_isa} >= 2
Requires:	globus-gsi-cert-utils%{?_isa} >= 8
Requires:	globus-common%{?_isa} >= 14
Requires:	globus-gsi-sysconfig%{?_isa} >= 5
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
Requires:	openssl
Requires:	openssl-libs%{?_isa}
%endif
%if %{?fedora}%{!?fedora:0} < 19 && %{?rhel}%{!?rhel:0} < 7
Requires:	openssl%{?_isa}
%endif

BuildRequires:	globus-gsi-proxy-ssl-devel >= 4
BuildRequires:	globus-gsi-credential-devel >= 5
BuildRequires:	globus-openssl-module-devel >= 3
BuildRequires:	globus-gsi-openssl-error-devel >= 2
BuildRequires:	globus-gsi-cert-utils-devel >= 8
BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-gsi-sysconfig-devel >= 5
BuildRequires:	doxygen
BuildRequires:	graphviz
%if "%{?rhel}" == "5"
BuildRequires:	graphviz-gd
%endif
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:	automake >= 1.11
BuildRequires:	autoconf >= 2.60
BuildRequires:	libtool >= 2.2
%endif
BuildRequires:  pkgconfig

%package devel
Summary:	Globus Toolkit - Globus GSI Proxy Core Library Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-gsi-proxy-ssl-devel%{?_isa} >= 4
Requires:	globus-gsi-credential-devel%{?_isa} >= 5
Requires:	globus-openssl-module-devel%{?_isa} >= 3
Requires:	globus-gsi-openssl-error-devel%{?_isa} >= 2
Requires:	globus-gsi-cert-utils-devel%{?_isa} >= 8
Requires:	globus-common-devel%{?_isa} >= 14
Requires:	globus-gsi-sysconfig-devel%{?_isa} >= 5

%package doc
Summary:	Globus Toolkit - Globus GSI Proxy Core Library Documentation Files
Group:		Documentation
%if %{?fedora}%{!?fedora:0} >= 10 || %{?rhel}%{!?rhel:0} >= 6
BuildArch:	noarch
%endif
Requires:	%{name} = %{version}-%{release}

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus GSI Proxy Core Library

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Globus GSI Proxy Core Library Development Files

%description doc
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-doc package contains:
Globus GSI Proxy Core Library Documentation Files

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

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_libdir}/libglobus*.so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/libglobus*.so
%{_libdir}/pkgconfig/*.pc

%files doc
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}/html
%{_docdir}/%{name}-%{version}/html
%{_mandir}/man3/*

%changelog
* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 7.6-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 7.5-2
- Fix Source path

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 7.5-1
- Merge changes from Mattias Ellert

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 7.4-1
- Version bump for consistency

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 7.3-1
- Packaging fixes, Warning Cleanup

* Mon Feb 10 2014 Globus Toolkit <support@globus.org> - 7.2-1
- Packaging fixes

* Mon Jan 27 2014 Globus Toolkit <support@globus.org> - 7.1-1
- GT-515: Increase default proxy key size in gsi-proxy-core

* Tue Jan 21 2014 Globus Toolkit <support@globus.org> - 7.0-1
- Repackage for GT6 without GPT

* Mon Jul 08 2013 Globus Toolkit <support@globus.org> - 6.2-9
- openssl-libs for newer fedora

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 6.2-8
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 6.2-7
- Workaround missing F18 doxygen/latex dependency

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 6.2-6
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 6.2-5
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 6.2-4
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 6.2-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 6.2-2
- SLES 11 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 6.2-1
- RIC-226: Some dependencies are missing in GPT metadata

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 6.1-4
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 6.1-3
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 6.1-2
- Add explicit dependencies on >= 5.2 libraries

* Thu Oct 06 2011 Joseph Bester <bester@mcs.anl.gov> - 6.1-1
- Add backward-compatibility aging

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 6.0-2
- Update for 5.1.2 release

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 4.5-1
- Update to Globus Toolkit 5.0.2
- Drop patch globus-gsi-proxy-core-oid.patch (fixed upstream)

* Mon May 31 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 4.4-2
- Fix OID registration pollution

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 4.4-1
- Update to Globus Toolkit 5.0.1
- Drop patch globus-gsi-proxy-core-typo.patch (fixed upstream)

* Fri Jan 22 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 4.3-1
- Update to Globus Toolkit 5.0.0

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 3.4-4
- rebuilt with new openssl

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.4-3
- Add instruction set architecture (isa) tags
- Make doc subpackage noarch

* Wed Jun 03 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.4-2
- Update to official Fedora Globus packaging guidelines

* Thu Apr 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.4-1
- Make comment about source retrieval more explicit
- Change defines to globals
- Remove explicit requires on library packages
- Put GLOBUS_LICENSE file in extracted source tarball

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.4-0.5
- Adapting to updated globus-core package

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.4-0.4
- Add s390x to the list of 64 bit platforms

* Thu Jan 01 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.4-0.3
- Adapt to updated GPT package

* Wed Oct 15 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.4-0.2
- Update to Globus Toolkit 4.2.1

* Mon Jul 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.3-0.1
- Autogenerated
