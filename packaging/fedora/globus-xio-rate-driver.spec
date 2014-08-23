Name:           globus-xio-rate-driver
%global _name %(tr - _ <<< %{name})
Version:	1.7
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus XIO Rate Limiting Driver

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:	http://www.globus.org/ftppub/gt6/packages/globus_xio_rate_driver-1.7.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-xio%{?_isa} >= 0
Requires:	globus-common%{?_isa} >= 0

BuildRequires:	globus-xio-devel >= 0
BuildRequires:	globus-common-devel >= 0
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:  automake >= 1.11
BuildRequires:  autoconf >= 2.60
BuildRequires:  libtool >= 2.2
%endif
BuildRequires:  pkgconfig

%package devel
Summary:	Globus Toolkit - Globus XIO Rate Limiting Driver Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-xio-devel%{?_isa} >= 0

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus XIO Rate Limiting Driver

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Globus XIO Rate Limiting Driver Development Files

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

find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;

%check
make %{?_smp_mflags} check

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/libglobus*.so*
%dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/GLOBUS_LICENSE

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/pkgconfig/%{name}.pc

%changelog
* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 1.7-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 1.6-2
- Fix Source path

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 1.6-1
- Merge changes from Mattias Ellert

* Tue May 06 2014 Globus Toolkit <support@globus.org> - 1.5-1
- Don't version dynamic module

* Thu Apr 24 2014 Globus Toolkit <support@globus.org> - 1.4-2
- Fix .so in filelist

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 1.4-1
- Version bump for consistency

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 1.3-2
- Version bump for consistency

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 1.3-1
- Packaging fixes, Warning Cleanup

* Thu Feb 13 2014 Globus Toolkit <support@globus.org> - 1.2-1
- Packaging Fixes

* Wed Jan 22 2014 Globus Toolkit <support@globus.org> - 1.1-1
- Add license

* Wed Jan 22 2014 Globus Toolkit <support@globus.org> - 1.0-1
- Repackage for GT6 without GPT
