Name:		globus-gsi-callback
%global _name %(tr - _ <<< %{name})
Version:	5.4
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus GSI Callback Library

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-openssl-module%{?_isa} >= 3
Requires:	globus-gsi-openssl-error%{?_isa} >= 2
Requires:	globus-gsi-cert-utils%{?_isa} >= 8
Requires:	globus-common%{?_isa} >= 14
Requires:	globus-gsi-sysconfig%{?_isa} >= 5

BuildRequires:	openssl-devel
BuildRequires:	globus-gsi-proxy-ssl-devel >= 4
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
Summary:	Globus Toolkit - Globus GSI Callback Library Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-gsi-proxy-ssl-devel%{?_isa} >= 4
Requires:	globus-openssl-module-devel%{?_isa} >= 3
Requires:	globus-gsi-openssl-error-devel%{?_isa} >= 2
Requires:	globus-gsi-cert-utils-devel%{?_isa} >= 8
Requires:	globus-common-devel%{?_isa} >= 14
Requires:	globus-gsi-sysconfig-devel%{?_isa} >= 5

%package doc
Summary:	Globus Toolkit - Globus GSI Callback Library Documentation Files
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
Globus GSI Callback Library

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Globus GSI Callback Library Development Files

%description doc
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-doc package contains:
Globus GSI Callback Library Documentation Files

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
%{_libdir}/pkgconfig/%{name}.pc
%{_libdir}/libglobus*.so

%files doc
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}/html
%{_docdir}/%{name}-%{version}/html/*
%{_mandir}/man3/*

%changelog
* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 5.4-1
- Merge changes from Mattias Ellert

* Tue May 27 2014 Globus Toolkit <support@globus.org> - 5.3-1
- Use package-named config.h

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 5.2-1
- Version bump for consistency

* Mon Feb 10 2014 Globus Toolkit <support@globus.org> - 5.1-1
- Packaging fixes

* Mon Jan 27 2014 Globus Toolkit <support@globus.org> - 5.0-1
- Remove GPT and make-packages.pl from build process

* Fri Sep 13 2013 Globus Toolkit <support@globus.org> - 4.6-1
- GT-426: memory leaks in globus-gsi-callback package

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 4.5-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Mon Mar 18 2013 Globus Toolkit <support@globus.org> - 4.5-1
- GT-354: Compatibility with automake 1.13

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 4.4-3
- Workaround missing F18 doxygen/latex dependency

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 4.4-2
- 5.2.3

* Wed Jul 25 2012 Joseph Bester <bester@mcs.anl.gov> - 4.4-1
- GT-235: GSI does not reload CRLs if they are replaced

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 4.3-3
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 4.3-2
- GT 5.2.2 Release

* Wed Jun 27 2012 Joseph Bester <bester@mcs.anl.gov> - 4.3-1
- GT-165: Threaded server has a race condition with parallel data channels and loading crls
- GT-166: Threaded server data channel connection error
- RIC-224: Eliminate some doxygen warnings
- RIC-226: Some dependencies are missing in GPT metadata
- RIC-227: Potentially unsafe format strings in GSI

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 4.2-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 4.2-2
- SLES 11 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 4.2-1
- RIC-224: Eliminate some doxygen warnings
- RIC-226: Some dependencies are missing in GPT metadata
- RIC-227: Potentially unsafe format strings in GSI

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 4.1-4
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 4.1-3
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 4.1-2
- Add explicit dependencies on >= 5.2 libraries

* Thu Oct 06 2011 Joseph Bester <bester@mcs.anl.gov> - 4.1-1
- Add backward-compatibility aging

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 4.0-2
- Update for 5.1.2 release

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.7-1
- Update to Globus Toolkit 5.0.2
- Drop patch globus-gsi-callback-oid.patch (fixed upstream)

* Mon May 31 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-2
- Fix OID registration pollution

* Fri Jan 22 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-1
- Update to Globus Toolkit 5.0.0

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 1.10-4
- rebuilt with new openssl

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.10-3
- Add instruction set architecture (isa) tags
- Make doc subpackage noarch

* Wed Jun 03 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.10-2
- Update to official Fedora Globus packaging guidelines

* Thu Apr 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.10-1
- Make comment about source retrieval more explicit
- Change defines to globals
- Remove explicit requires on library packages
- Put GLOBUS_LICENSE file in extracted source tarball

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.10-0.5
- Adapting to updated globus-core package

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.10-0.4
- Add s390x to the list of 64 bit platforms

* Thu Jan 01 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.10-0.3
- Adapt to updated GPT package

* Tue Oct 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.10-0.2
- Update to Globus Toolkit 4.2.1

* Mon Jul 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.4-0.1
- Autogenerated
