Name:		globus-io
%global _name %(tr - _ <<< %{name})
Version:	10.9
Release:	1%{?dist}
Summary:	Globus Toolkit - uniform I/O interface

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common%{?_isa} >= 14
Requires:	globus-xio-gsi-driver%{?_isa} >= 2
Requires:	globus-gss-assist%{?_isa} >= 8
Requires:	globus-xio%{?_isa} >= 3
Requires:	globus-gssapi-gsi%{?_isa} >= 10

BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-xio-gsi-driver-devel >= 2
BuildRequires:	globus-gss-assist-devel >= 8
BuildRequires:	globus-xio-devel >= 3
BuildRequires:	globus-gssapi-gsi-devel >= 10
BuildRequires:	globus-gssapi-error-devel >= 4
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:	automake >= 1.11
BuildRequires:	autoconf >= 2.60
BuildRequires:	libtool >= 2.2
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
Summary:	Globus Toolkit - uniform I/O interface Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-common-devel%{?_isa} >= 14
Requires:	globus-xio-gsi-driver-devel%{?_isa} >= 2
Requires:	globus-gss-assist-devel%{?_isa} >= 8
Requires:	globus-xio-devel%{?_isa} >= 3
Requires:	globus-gssapi-gsi-devel%{?_isa} >= 10
Requires:	globus-gssapi-error-devel%{?_isa} >= 4

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
uniform I/O interface to stream and datagram style communications

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
uniform I/O interface Development Files

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
rm -rvf $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/html
rm -rvf $RPM_BUILD_ROOT%{_mandir}

%check
make %{?_smp_mflags} check

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_libdir}/libglobus_*.so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/lib*.so
%{_libdir}/pkgconfig/%{name}.pc

%changelog
* Mon Apr 21 2014 Globus Toolkit <support@globus.org> - 10.9-1
- Test fixes

* Mon Apr 21 2014 Globus Toolkit <support@globus.org> - 10.8-1
- Test fixes

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 10.7-1
- Version bump for consistency

* Mon Mar 03 2014 Globus Toolkit <support@globus.org> - 10.5-1
- Packaging fixes

* Mon Feb 24 2014 Globus Toolkit <support@globus.org> - 10.4-1
- Test fixes

* Mon Feb 24 2014 Globus Toolkit <support@globus.org> - 10.3-1
- Test fixes

* Tue Feb 11 2014 Globus Toolkit <support@globus.org> - 10.2-1
- Packaging fixes

* Sat Feb 01 2014 Globus Toolkit <support@globus.org> - 10.1-1
- umask for test creds

* Tue Jan 21 2014 Globus Toolkit <support@globus.org> - 10.0-1
- Repackage for GT6 without GPT

* Tue Oct 15 2013 Globus Toolkit <support@globus.org> - 9.5-1
- GT-470: Globus IO reports timeout error as cancellation

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 9.4-3
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Wed Mar 06 2013 Globus Toolkit <support@globus.org> - 9.4-2
- missing dependency on globus-gssapi-error

* Mon Feb 04 2013 Globus Toolkit <support@globus.org> - 9.4-1
- GT-32: Force IPv6 in globus_io with an environment variable

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 9.3-5
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 9.3-4
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 9.3-3
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 9.3-2
- RHEL 4 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 9.3-1
- RIC-226: Some dependencies are missing in GPT metadata

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 9.2-3
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 9.2-2
- Last sync prior to 5.2.0

* Thu Dec 01 2011 Joseph Bester <bester@mcs.anl.gov> - 9.2-1
- GRAM-290: GRAM protocol misinterprets some GSSAPI errors as connection errors

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 9.1-2
- Add explicit dependencies on >= 5.2 libraries

* Thu Oct 06 2011 Joseph Bester <bester@mcs.anl.gov> - 9.1-1
- Add backward-compatibility aging

* Mon Sep 26 2011 Joseph Bester <bester@mcs.anl.gov> - 9.0-2
- pick up new GSSAPI version dependency

* Tue Sep 20 2011  <bester@mcs.anl.gov> - 9.0-1
- Add channel mode GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP_SSL3 to force SSLv3

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 8.0-2
- Update for 5.1.2 release

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3-4
- Update to Globus Toolkit 5.0.0

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3-3
- Add instruction set architecture (isa) tags

* Thu Jun 04 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3-2
- Update to official Fedora Globus packaging guidelines

* Thu Apr 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3-1
- Make comment about source retrieval more explicit
- Change defines to globals
- Remove explicit requires on library packages
- Put GLOBUS_LICENSE file in extracted source tarball

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3-0.5
- Adapting to updated globus-core package

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3-0.4
- Add s390x to the list of 64 bit platforms

* Tue Dec 30 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3-0.3
- Adapt to updated GPT package

* Tue Oct 21 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3-0.2
- Update to Globus Toolkit 4.2.1

* Mon Jul 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3-0.1
- Autogenerated
