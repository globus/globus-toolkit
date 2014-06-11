Name:		globus-gfork
%global _name %(tr - _ <<< %{name})
Version:	4.5
Release:	1%{?dist}
Summary:	Globus Toolkit - GFork

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common%{?_isa} >= 14
Requires:	globus-xio%{?_isa} >= 3

BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-xio-devel >= 3
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:	automake >= 1.11
BuildRequires:	autoconf >= 2.60
BuildRequires:	libtool >= 2.2
%endif
BuildRequires:  pkgconfig
%if %{?fedora}%{!?fedora:0} >= 18 || %{?rhel}%{!?rhel:0} >= 6
BuildRequires:  perl-Test-Simple
%endif

%package progs
Summary:	Globus Toolkit - GFork Programs
Group:		Applications/Internet
Requires:	%{name}%{?_isa} = %{version}-%{release}

%package devel
Summary:	Globus Toolkit - GFork Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-xio-devel%{?_isa} >= 3

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
GFork Library

%description progs
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-progs package contains:
GFork Programs - GFork is user configurable super-server daemon very similar
to xinetd. It listens on a TCP port. When clients connect to a port it runs an
administrator defined program which services that client connection, just as
x/inetd do.

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
GFork Development Files

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
           --libexecdir=%{_datadir}/share/globus

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;

# Add empty default configuration file
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}
echo "# This is the default gfork configuration file" > \
  $RPM_BUILD_ROOT%{_sysconfdir}/gfork.conf

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
%config(noreplace) %{_sysconfdir}/gfork.conf
%doc %{_docdir}/%{name}-%{version}/README.txt
%{_sbindir}/gfork

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/globus_gfork.h
%{_libdir}/libglobus_*.so
%{_libdir}/pkgconfig/globus-gfork.pc

%changelog
* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 4.5-1
- Merge changes from Mattias Ellert

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 4.4-1
- Version bump for consistency

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 4.3-1
- Packaging fixes, Warning Cleanup

* Tue Feb 25 2014 Globus Toolkit <support@globus.org> - 4.2-1
- Packaging fixes

* Mon Feb 10 2014 Globus Toolkit <support@globus.org> - 4.1-1
- Put automake version requirement first

* Tue Jan 21 2014 Globus Toolkit <support@globus.org> - 4.0-1
- Repackage for GT6 without GPT

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 3.2-7
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Tue Mar 05 2013 Globus Toolkit <support@globus.org> - 3.2-6
- Add missing build dependency

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 3.2-5
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 3.2-4
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 3.2-3
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 3.2-2
- RHEL 4 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 3.2-1
- RIC-229: Clean up GPT metadata

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 3.1-4
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 3.1-3
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 3.1-2
- Add explicit dependencies on >= 5.2 libraries

* Thu Oct 06 2011 Joseph Bester <bester@mcs.anl.gov> - 3.1-1
- Add backward-compatibility aging

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 3.0-2
- Update for 5.1.2 release

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 0.2-4
- Update to Globus Toolkit 5.0.0

* Fri Oct 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 0.2-3
- Fix location of default config file
- Add empty default config file

* Wed Oct 07 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 0.2-2
- Include additional documentation

* Tue Jul 28 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 0.2-1
- Autogenerated
