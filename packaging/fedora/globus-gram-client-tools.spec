Name:		globus-gram-client-tools
%global _name %(tr - _ <<< %{name})
Version:	11.5
Release:	1%{?dist}
Summary:	Globus Toolkit - Job Management Tools (globusrun)

Group:		Applications/Internet
License:	ASL 2.0
URL:		http://www.globus.org/
Source:	http://www.globus.org/ftppub/gt6/packages/globus_gram_client_tools-11.5.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common-progs%{?_isa} >= 14
Requires:	globus-gass-server-ez%{?_isa} >= 4
Requires:	globus-gram-client%{?_isa} >= 12
Requires:	globus-gss-assist%{?_isa} >= 8
Requires:	globus-rsl%{?_isa} >= 9

BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-gass-server-ez-devel >= 4
BuildRequires:	globus-gram-client-devel >= 12
BuildRequires:	globus-gss-assist-devel >= 8
BuildRequires:	globus-rsl-devel >= 9
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
Job Management Tools (globusrun)

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

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_bindir}/*
%{_mandir}/man1/*
%{_libdir}/pkgconfig/*.pc

%changelog
* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 11.5-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 11.4-2
- Fix Source path

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 11.4-1
- Merge changes from Mattias Ellert

* Fri Apr 25 2014 Globus Toolkit <support@globus.org> - 11.3-1
- Packaging fixes

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 11.2-1
- Version bump for consistency

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 11.1-1
- Packaging fixes, Warning Cleanup

* Thu Jan 23 2014 Globus Toolkit <support@globus.org> - 11.0-1
- Repackage for GT6 without GPT

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 10.4-5
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 10.4-4
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 10.4-3
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 10.4-2
- GT 5.2.2 Release

* Mon May 21 2012 Joseph Bester <bester@mcs.anl.gov> - 10.4-1
- GT-198: globusrun crashes when authentication fails for status check

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 10.3-2
- RHEL 4 patches

* Wed Apr 11 2012 Joseph Bester <bester@mcs.anl.gov> - 10.3-1
- GRAM-339: globus-job-run and globus-job-submit can't always handle "-e" as an argument

* Wed Apr 11 2012 Joseph Bester <bester@mcs.anl.gov> - 10.2-1
- GRAM-331: Remove dead code from globusrun
- GRAM-341: globusrun ignores state callbacks that occur too early

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 10.1-1
- GRAM-311: Undefined variable defaults in shell scripts
- RIC-226: Some dependencies are missing in GPT metadata

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 10.0-5
- Update for 5.2.0 release

* Mon Nov 21 2011 Joseph Bester <bester@mcs.anl.gov> - 10.0-4
- GRAM-281: Missing dependency in globus-gram-client-tools RPM

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 10.0-3
- Add explicit dependencies on >= 5.2 libraries

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 10.0-2
- Update for 5.1.2 release

* Wed Aug 31 2011 Joseph Bester <bester@mcs.anl.gov> - 10.0-1
- Updated version numbers

* Mon Apr 25 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 8.2-3
- Add README file

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 8.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 8.2-1
- Update to Globus Toolkit 5.0.2

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 8.1-1
- Update to Globus Toolkit 5.0.1
- Drop patch globus-gram-client-tools.patch (fixed upstream)

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.3-1
- Update to Globus Toolkit 5.0.0

* Tue Jul 28 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.0-1
- Autogenerated
