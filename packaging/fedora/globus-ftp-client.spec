Name:		globus-ftp-client
%global _name %(tr - _ <<< %{name})
Version:	8.14
Release:	1%{?dist}
Summary:	Globus Toolkit - GridFTP Client Library

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:	http://www.globus.org/ftppub/gt6/packages/globus_ftp_client-8.14.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-xio-popen-driver%{?_isa} >= 2
Requires:	globus-common%{?_isa} >= 15
Requires:	globus-ftp-control%{?_isa} >= 4

BuildRequires:	globus-xio-popen-driver-devel >= 2
BuildRequires:	globus-common-devel >= 15
BuildRequires:	globus-ftp-control-devel >= 4
BuildRequires:	globus-ftp-control-doc >= 4
BuildRequires:	globus-gridftp-server-progs
BuildRequires:	doxygen
BuildRequires:	graphviz
BuildRequires:	globus-gridftp-server-devel >= 0
BuildRequires:	globus-xio-pipe-driver-devel >= 0
%if "%{?rhel}" == "5"
BuildRequires:	graphviz-gd
%endif
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:  automake >= 1.11
BuildRequires:  autoconf >= 2.60
BuildRequires:  libtool >= 2.2
%endif
BuildRequires:  pkgconfig
%if %{?fedora}%{!?fedora:0} >= 18 || %{?rhel}%{!?rhel:0} >= 6
BuildRequires:  perl-Test-Simple
%endif
%if 0%{?suse_version} > 0
BuildRequires: libtool
%else
BuildRequires: libtool-ltdl-devel
%endif

%package devel
Summary:	Globus Toolkit - GridFTP Client Library Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-xio-popen-driver-devel%{?_isa}
Requires:	globus-common-devel%{?_isa} >= 15
Requires:	globus-ftp-control-devel%{?_isa} >= 4

%package doc
Summary:	Globus Toolkit - GridFTP Client Library Documentation Files
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
GridFTP Client Library

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
GridFTP Client Library Development Files

%description doc
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-doc package contains:
GridFTP Client Library Documentation Files

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
make %{_smp_mflags} check

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_libdir}/libglobus*.so.*
%{_datadir}/globus/gridftp-ssh

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
* Tue Oct 28 2014 Globus Toolkit <support@globus.org> - 8.14-1
- GT-572: globus-ftp-client performs MLSD with incorrect TYPE

* Tue Sep 23 2014 Globus Toolkit <support@globus.org> - 8.13-1
- Include more manpages for API
- Fix some Doxygen issues
- Fix dependency
- Quiet some autoconf/automake warnings
- Use mixed case man page install for all packages

* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 8.12-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 8.11-2
- Fix Source path

* Wed Aug 06 2014 Globus Toolkit <support@globus.org> - 8.11-1
- Skip put-test.pl on mingw

* Tue Aug 05 2014 Globus Toolkit <support@globus.org> - 8.10-1
- Skip put-test.pl on mingw

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 8.9-1
- Merge changes from Mattias Ellert

* Thu Apr 24 2014 Globus Toolkit <support@globus.org> - 8.8-1
- Test fixes

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 8.7-1
- Version bump for consistency

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 8.6-1
- Packaging fixes, Warning Cleanup

* Thu Feb 20 2014 Globus Toolkit <support@globus.org> - 8.5-1
- GLOBUS_USAGE_OPTOUT tests

* Mon Feb 17 2014 Globus Toolkit <support@globus.org> - 8.4-1
- Packaging fixes

* Mon Feb 17 2014 Globus Toolkit <support@globus.org> - 8.3-1
- Packaging fixes

* Fri Feb 14 2014 Globus Toolkit <support@globus.org> - 8.2-1
- Packaging fixes

* Fri Feb 14 2014 Globus Toolkit <support@globus.org> - 8.1-2
- Test fixes

* Fri Feb 14 2014 Globus Toolkit <support@globus.org> - 8.1-1
- Packaging fixes

* Wed Jan 22 2014 Globus Toolkit <support@globus.org> - 8.0-1
- Repackage for GT6 without GPT

* Thu Aug 15 2013 Globus Toolkit <support@globus.org> - 7.6-1
- GT-425: add environment variable to force IPV6 compatibility

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 7.5-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Thu May 09 2013 Globus Toolkit <support@globus.org> - 7.5-1
- Fix performance issue, don't need to check binary data buffers for newlines

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 7.4-5
- Workaround missing F18 doxygen/latex dependency

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 7.4-4
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 7.4-3
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 7.4-2
- GT 5.2.2 Release

* Wed Jun 27 2012 Joseph Bester <bester@mcs.anl.gov> - 7.4-1
- GT-153: make gridftp-v2 GET/PUT the default for server that support it
- GT-15: Add explicit CWD command to client API
- GT-9: Failure in globus_ftp_client_operationattr_set_authorization() results in using freed memory
- RIC-226: Some dependencies are missing in GPT metadata

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 7.3-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 7.3-2
- SLES 11 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 7.3-1
- RIC-226: Some dependencies are missing in GPT metadata

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 7.2-4
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 7.2-3
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 7.1-2
- Add explicit dependencies on >= 5.2 libraries

* Thu Oct 06 2011 Joseph Bester <bester@mcs.anl.gov> - 7.1-1
- Add backward-compatibility aging

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 7.0-2
- Update for 5.1.2 release

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3-2
- Update to Globus Toolkit 5.0.2

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3-1
- Update to Globus Toolkit 5.0.1

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.2-1
- Update to Globus Toolkit 5.0.0

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.14-3
- Add instruction set architecture (isa) tags
- Make doc subpackage noarch

* Thu Jun 04 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.14-2
- Update to official Fedora Globus packaging guidelines

* Thu Apr 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.14-1
- Make comment about source retrieval more explicit
- Change defines to globals
- Remove explicit requires on library packages
- Put GLOBUS_LICENSE file in extracted source tarball

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.14-0.5
- Adapting to updated globus-core package

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.14-0.4
- Add s390x to the list of 64 bit platforms

* Thu Jan 01 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.14-0.3
- Adapt to updated GPT package

* Tue Oct 21 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.14-0.2
- Update to Globus Toolkit 4.2.1

* Tue Jul 15 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.11-0.1
- Autogenerated
