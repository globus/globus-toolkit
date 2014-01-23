Name:		globus-gsi-cert-utils
%global _name %(tr - _ <<< %{name})
Version:	9.0
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus GSI Cert Utils Library

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
Requires:	openssl
Requires:	openssl-libs%{?_isa}
%endif
%if %{?fedora}%{!?fedora:0} < 19 && %{?rhel}%{!?rhel:0} < 7
Requires:	openssl%{?_isa}
%endif
Requires:	globus-common%{?_isa} >= 14
Requires:	globus-openssl-module%{?_isa} >= 3
Requires:	globus-gsi-openssl-error%{?_isa} >= 2

BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-openssl-module-devel >= 3
BuildRequires:	globus-gsi-openssl-error-devel >= 2
BuildRequires:	openssl-devel
BuildRequires:	doxygen
BuildRequires:	graphviz
%if "%{?rhel}" == "5"
BuildRequires:	graphviz-gd
%endif

%package progs
Summary:	Globus Toolkit - Globus GSI Cert Utils Library Programs
Group:		Applications/Internet
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	openssl
Requires:	globus-common >= 14
Requires:	globus-common-progs >= 14

%package devel
Summary:	Globus Toolkit - Globus GSI Cert Utils Library Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-common-devel%{?_isa} >= 14
Requires:	globus-openssl-module-devel%{?_isa} >= 3
Requires:	globus-gsi-openssl-error-devel%{?_isa} >= 2
Requires:	openssl-devel%{?_isa}

%package doc
Summary:	Globus Toolkit - Globus GSI Cert Utils Library Documentation Files
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
Globus GSI Cert Utils Library

%description progs
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-progs package contains:
Globus GSI Cert Utils Library Programs

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Globus GSI Cert Utils Library Development Files

%description doc
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-doc package contains:
Globus GSI Cert Utils Library Documentation Files

%prep
%setup -q -n %{_name}-%{version}

%build
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
# Remove files that should be replaced during bootstrap
rm -rf autom4te.cache

autoreconf -i
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

%files progs
%defattr(-,root,root,-)
%{_bindir}/*
%{_sbindir}/*
%{_mandir}/man1/*
%{_mandir}/man8/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/pkgconfig/%{name}.pc
%{_libdir}/libglobus*.so

%files doc
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}/html
%{_docdir}/%{name}-%{version}/html/*
%{_mandir}/man3/*

%changelog
* Tue Jan 21 2014 Globus Toolkit <support@globus.org> - 9.0-1
- Repackage for GT6 without GPT

* Thu Oct 10 2013 Globus Toolkit <support@globus.org> - 8.6-1
- GT-445: Doxygen fixes

* Mon Jul 08 2013 Globus Toolkit <support@globus.org> - 8.5-4
- openssl-libs dep for newer fedora

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 8.5-3
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> - 8.5-2
- Update sharing to support a full cert chain at logon

* Mon Mar 18 2013 Globus Toolkit <support@globus.org> - 8.5-1
- GT-354: Compatibility with automake 1.13

* Tue Mar 05 2013 Globus Toolkit <support@globus.org> - 8.4-1
- GT-365: Switch sharing user identification from DN to CERT

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 8.3-7
- Workaround missing F18 doxygen/latex dependency

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 8.3-6
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 8.3-5
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 8.3-4
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 8.3-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 8.3-2
- SLES 11 patches

* Thu Mar 29 2012 Joseph Bester <bester@mcs.anl.gov> - 8.3-1
- RIC-248: grid-cert-request can't use non-default CA when a default isn't set

* Thu Feb 23 2012 Joseph Bester <bester@mcs.anl.gov> - 8.2-2
- RIC-237: globus-gsi-cert-utils-progs RPM has missing dependency

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 8.2-1
- RIC-226: Some dependencies are missing in GPT metadata
- RIC-227: Potentially unsafe format strings in GSI
- RIC-231: grid-cert-request prints incorrect path in diagnostic message

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 8.1-4
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 8.1-3
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 8.1-2
- Add explicit dependencies on >= 5.2 libraries

* Thu Oct 06 2011 Joseph Bester <bester@mcs.anl.gov> - 8.1-1
- Add backward-compatibility aging

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 8.0-2
- Update for 5.1.2 release

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.6-1
- Update to Globus Toolkit 5.0.2
- Drop patch globus-gsi-cert-utils-oid.patch (fixed upstream)

* Mon May 31 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.5-2
- Fix OID registration pollution

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.5-1
- Update to Globus Toolkit 5.0.1

* Fri Jan 22 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.4-1
- Update to Globus Toolkit 5.0.0

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 5.5-4
- rebuilt with new openssl

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.5-3
- Add instruction set architecture (isa) tags
- Make doc subpackage noarch

* Wed Jun 03 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.5-2
- Update to official Fedora Globus packaging guidelines

* Thu Apr 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.5-1
- Change defines to globals
- Remove explicit requires on library packages

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.5-0.5
- Adapting to updated globus-core package

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.5-0.4
- Add s390x to the list of 64 bit platforms
- Update to upstream update release 5.5
- Drop the environment elimination patch (accepted upstream)

* Thu Jan 01 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.0-0.3
- Adapt to updated GPT package

* Tue Oct 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.0-0.2
- Update to Globus Toolkit 4.2.1

* Mon Jul 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 4.1-0.1
- Autogenerated
