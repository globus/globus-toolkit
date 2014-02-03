Name:		globus-gridftp-server-control
%global _name %(tr - _ <<< %{name})
Version:	3.0
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus GridFTP Server Library

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common%{?_isa} >= 14
Requires:	globus-xio%{?_isa} >= 3
Requires:	globus-xio-pipe-driver%{?_isa} >= 2
Requires:	globus-xio-gsi-driver%{?_isa} >= 2
Requires:	globus-gssapi-error%{?_isa} >= 4
Requires:	globus-gss-assist%{?_isa} >= 8

BuildRequires:	globus-xio-pipe-driver-devel >= 2
BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-xio-gsi-driver-devel >= 2
BuildRequires:	globus-xio-devel >= 3
BuildRequires:	globus-gss-assist-devel >= 8

%package devel
Summary:	Globus Toolkit - Globus GridFTP Server Library Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-xio-pipe-driver-devel%{?_isa} >= 2
Requires:	globus-common-devel%{?_isa} >= 14
Requires:	globus-xio-gsi-driver-devel%{?_isa} >= 2
Requires:	globus-xio-devel%{?_isa} >= 3
Requires:	globus-gssapi-error-devel%{?_isa} >= 4
Requires:	globus-gss-assist-devel%{?_isa} >= 8

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus GridFTP Server Library

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Globus GridFTP Server Library Development Files

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
%{_libdir}/libglobus*so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/libglobus*.so
%{_libdir}/pkgconfig/%{name}.pc

%changelog
* Tue Jan 21 2014 Globus Toolkit <support@globus.org> - 3.0-1
- Repackage for GT6 without GPT

* Tue Oct 15 2013 Globus Toolkit <support@globus.org> - 2.10-1
- GT-472: GridFTP server fails to detect client disconnection with piplining

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 2.9-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Wed Jun 05 2013 Globus Toolkit <support@globus.org> - 2.9-1
- GT-396: fix mlst on filenames that end in a newline
- GT-412: add -version-tag to set an identifier in the server version string
- fix minor memory leaks
- fix mlsx symlink target not urlencoding properly

* Wed Mar 06 2013  Globus Toolkit <support@globus.org> - 2.8-2
- Add missing build dependency

* Mon Feb 04 2013 Globus Toolkit <support@globus.org> - 2.8-1
- GT-302: Add initial sharing support to the GridFTP server
- GT-356: Add configuration and a command to make the sharing authorization file easier to manage

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 2.7-3
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 2.7-2
- GT 5.2.2 final

* Thu Jul 12 2012 Joseph Bester <bester@mcs.anl.gov> - 2.7-1
- GT-172: Removed custom MLSx tag feature
- GT-244: Cleaned up memory leaks
- GT-243: Fix needless frontend->backend connections

* Thu May 17 2012 Joseph Bester <bester@mcs.anl.gov> - 2.6-1
- GT-195: GridFTP acts as wrong user when user doesn't exist

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 2.5-2
- RHEL 4 patches

* Tue Mar 06 2012 Joseph Bester <bester@mcs.anl.gov> - 2.5-1
- GRIDFTP-165: correct chunking of MLSC response
- GRIDFTP-165: fix MLSC over split processes
- GRIDFTP-198: performance improvements for control channel messages
- GRIDFTP-201: Add heartbeat/status markers to CKSM and RETR
- GRIDFTP-222: fix threaded issues with streaming dir info for mlsd and mlsc

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 2.4-1
- RIC-226: Some dependencies are missing in GPT metadata

* Mon Dec 06 2011 Joseph Bester <bester@mcs.anl.gov> - 2.3-1
- fix mlst double space

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 2.2-4
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 2.2-3
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 2.1-2
- Add explicit dependencies on >= 5.2 libraries

* Thu Oct 06 2011 Joseph Bester <bester@mcs.anl.gov> - 2.1-1
- Add backward-compatibility aging

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 2.0-3
- Fix missing whitespace in Requires

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 2.0-2
- Update for 5.1.2 release

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 0.43-1
- Update to Globus Toolkit 5.0.2

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 0.42-1
- Update to Globus Toolkit 5.0.1

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 0.40-1
- Update to Globus Toolkit 5.0.0

* Tue Jul 28 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 0.36-1
- Autogenerated
