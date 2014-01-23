Name:		globus-gass-server-ez
%global _name %(tr - _ <<< %{name})
Version:	5.0
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus Gass Server_ez

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common%{?_isa} >= 14
Requires:	globus-gss-assist%{?_isa} >= 8
Requires:	globus-gass-transfer%{?_isa} >= 7

BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-gss-assist-devel >= 8
BuildRequires:	globus-gass-transfer-devel >= 7

%package progs
Summary:	Globus Toolkit - Globus Gass Server_ez Programs
Group:		Applications/Internet
Requires:	%{name}%{?_isa} = %{version}-%{release}

%package devel
Summary:	Globus Toolkit - Globus Gass Server_ez Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-common-devel%{?_isa} >= 14
Requires:	globus-gss-assist-devel%{?_isa} >= 8
Requires:	globus-gass-transfer-devel%{?_isa} >= 7

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus Gass Server_ez

%description progs
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-progs package contains:
Globus Gass Server_ez Programs

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Globus Gass Server_ez Development Files

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
%{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_libdir}/libglobus*.so.*

%files progs
%defattr(-,root,root,-)
%{_bindir}/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/libglobus*.so
%{_libdir}/pkgconfig/*.pc

%changelog
* Wed Jan 22 2014 Globus Toolkit <support@globus.org> - 5.0-1
- Repackage for GT6 without GPT

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 4.3-6
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 4.3-5
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 4.3-4
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 4.3-3
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 4.3-2
- RHEL 4 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 4.3-1
- RIC-218: Fd leak in gass server when file read fails
- RIC-226: Some dependencies are missing in GPT metadata

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

* Mon Apr 25 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.6-3
- Add README file

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.6-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.6-1
- Update to Globus Toolkit 5.0.1
- Drop patch globus-gass-server-ez.patch (fixed upstream)

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-2
- Update to Globus Toolkit 5.0.0

* Tue Jul 28 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-1
- Autogenerated
