Name:		globus-scheduler-event-generator
%global _name %(tr - _ <<< %{name})
Version:	5.0
Release:	1%{?dist}
Summary:	Globus Toolkit - Scheduler Event Generator

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-gram-protocol%{?_isa} >= 11
Requires:	globus-common%{?_isa} >= 14
Requires:	globus-xio-gsi-driver%{?_isa} >= 2
Requires:	globus-xio%{?_isa} >= 3

BuildRequires:	globus-gram-protocol-devel >= 11
%if 0%{?suse_version} == 0
%if 0%{?rhel} > 4 || 0%{?rhel} == 0
BuildRequires:	libtool-ltdl-devel
%endif
%endif
BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-xio-gsi-driver-devel >= 2
BuildRequires:	globus-xio-devel >= 3
BuildRequires:	doxygen
BuildRequires:	graphviz
%if "%{?rhel}" == "5"
BuildRequires:	graphviz-gd
%endif

%package progs
Summary:	Globus Toolkit - Scheduler Event Generator Programs
Group:		Applications/Internet
%if 0%{?suse_version} == 0
BuildRequires:       lsb
%else
BuildRequires:       insserv
%endif
Requires:	%{name}%{?_isa} = %{version}-%{release}
%if 0%{?suse_version} == 0
Requires:       lsb
%else
Requires:       insserv
%endif
Requires:	globus-xio-gsi-driver%{?_isa} >= 2
Requires(post): globus-common-progs >= 14
Requires(preun):globus-common-progs >= 14

%package devel
Summary:	Globus Toolkit - Scheduler Event Generator Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-gram-protocol-devel%{?_isa} >= 11
%if 0%{?suse_version} == 0
%if 0%{?rhel} > 4 || 0%{?rhel} == 0
Requires:  libtool-ltdl-devel
%endif
%endif
Requires:	globus-common-devel%{?_isa} >= 14
Requires:	globus-xio-gsi-driver-devel%{?_isa} >= 2
Requires:	globus-xio-devel%{?_isa} >= 3

%package doc
Summary:	Globus Toolkit - Scheduler Event Generator Documentation Files
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
Scheduler Event Generator

%description progs
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-progs package contains:
Scheduler Event Generator Programs

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Scheduler Event Generator Development Files

%description doc
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-doc package contains:
Scheduler Event Generator Documentation Files

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
           --libexecdir=%{_datadir}/globus \
           --with-lsb \
           --with-initscript-config-path=/etc/sysconfig/%{name} \
           --with-lockfile-path='${localstatedir}/lock/subsys/%{name}'

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

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%post progs
if [ $1 -eq 1 ]; then
    /sbin/chkconfig --add %{name}
fi

%preun progs
if [ $1 -eq 0 ]; then
    /sbin/chkconfig --del %{name}
    /sbin/service %{name} stop > /dev/null 2>&1 || :
fi

%postun progs
if [ $1 -eq 1 ]; then
    /sbin/service %{name} condrestart > /dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_libdir}/libglobus*.so.*

%files progs
%defattr(-,root,root,-)
%config(noreplace) /etc/sysconfig/%{name}
%{_sysconfdir}/init.d/%{name}
%{_sbindir}/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/libglobus*.so
%{_libdir}/pkgconfig/*.pc

%files doc
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}/html
%{_docdir}/%{name}-%{version}/html/*
%{_mandir}/man3/*

%changelog
* Tue Jan 21 2014 Globus Toolkit <support@globus.org> - 5.0-1
- Repackage for GT6 without GPT

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 4.7-4
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 4.7-3
- Workaround missing F18 doxygen/latex dependency

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 4.7-2
- 5.2.3

* Tue Oct 09 2012 Globus Toolkit <support@globus.org> - 4.7-1
- GT-295: Missing dependency in globus_scheduler_event_generator debian native packages

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 4.6-5
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 4.6-4
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 4.6-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 4.6-2
- SLES 11 patches

* Fri Apr 13 2012 Joseph Bester <bester@mcs.anl.gov> - 4.6-1
- RIC-258: Can't rely on MKDIR_P

* Fri Apr 06 2012 Joseph Bester <bester@mcs.anl.gov> - 4.5-1
- GRAM-335: init scripts fail on solaris because of stop alias
- RIC-205: Missing directories $GLOBUS_LOCATION/var/lock and $GLOBUS_LOCATION/var/run

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 4.4-2
- Updated version numbers

* Mon Dec 12 2011 Joseph Bester <bester@mcs.anl.gov> - 4.4-1
- init script fixes

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 4.3-3
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 4.3-2
- Last sync prior to 5.2.0

* Tue Nov 22 2011 Joseph Bester <bester@mcs.anl.gov> - 4.3-1
- GRAM-284: init defaults for debian

* Mon Oct 24 2011 Joseph Bester <bester@mcs.anl.gov> - 4.2-2
- Add explicit dependencies on >= 5.2 libraries
- Add backward-compatibility aging
- Fix %post* scripts to check for -eq 1

* Fri Sep 23 2011 Joseph Bester <bester@mcs.anl.gov> - 4.1-1
- GRAM-260: Detect and workaround bug in start_daemon for LSB < 4

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 4.0-2
- Update for 5.1.2 release

* Mon Apr 25 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.1-4
- Add README file

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.1-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.1-2
- Update to Globus Toolkit 5.0.0

* Wed Jul 29 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.1-1
- Autogenerated
