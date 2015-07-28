Name:		globus-proxy-utils
%global _name %(tr - _ <<< %{name})
Version:	6.12
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus GSI Proxy Utility Programs

Group:		Applications/Internet
License:	ASL 2.0
URL:		http://toolkit.globus.org/
Source:	http://toolkit.globus.org/ftppub/gt6/packages/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
Requires:	openssl
Requires:	openssl-libs%{?_isa}
%endif
%if %{?fedora}%{!?fedora:0} < 19 && %{?rhel}%{!?rhel:0} < 7
Requires:	openssl%{?_isa}
%endif
Requires:	globus-gsi-proxy-ssl%{?_isa} >= 4
Requires:	globus-gsi-credential%{?_isa} >= 5
Requires:	globus-gsi-callback%{?_isa} >= 4
Requires:	globus-openssl-module%{?_isa} >= 3
Requires:	globus-gss-assist%{?_isa} >= 8
Requires:	globus-gsi-openssl-error%{?_isa} >= 2
Requires:	globus-gsi-proxy-core%{?_isa} >= 6
Requires:	globus-gsi-cert-utils%{?_isa} >= 8
Requires:	globus-common%{?_isa} >= 14
Requires:	globus-gsi-sysconfig%{?_isa} >= 5


BuildRequires:	globus-gsi-proxy-ssl-devel >= 4
BuildRequires:	globus-gsi-credential-devel >= 5
BuildRequires:	globus-gsi-callback-devel >= 4
BuildRequires:	globus-openssl-module-devel >= 3
BuildRequires:	globus-gss-assist-devel >= 8
BuildRequires:	globus-gsi-openssl-error-devel >= 2
BuildRequires:	openssl-devel
BuildRequires:	globus-gsi-proxy-core-devel >= 6
BuildRequires:	globus-gsi-cert-utils-devel >= 8
BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-gsi-sysconfig-devel >= 5
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:  automake >= 1.11
BuildRequires:  autoconf >= 2.60
BuildRequires:  libtool >= 2.2
%endif
BuildRequires:  pkgconfig
%if %{?fedora}%{!?fedora:0} >= 18 || %{?rhel}%{!?rhel:0} >= 6
BuildRequires:  perl-Test-Simple
%endif

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus GSI Proxy Utility Programs

%prep
%setup -q -n %{_name}-%{version}

%build
# Remove files that should be replaced during bootstrap
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

%check
make %{?_smp_mflags} check

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_bindir}/*
%{_mandir}/man1/*

%changelog
* Tue Jul 28 2015 Globus Toolkit <support@globus.org> - 6.12-1
- Add explicit name comparison result and mode select option

* Wed Jul 01 2015 Globus Toolkit <support@globus.org> - 6.11-1
- Remove unused label
- Check for c99 compiler flags

* Wed Jul 01 2015 Globus Toolkit <support@globus.org> - 6.10-1
- GT-607: improve grid-cert-diagnostic command to retrieve endpoint cert

* Thu Sep 25 2014 Globus Toolkit <support@globus.org> - 6.9-1
- Remove unused Doxygen headers
- Quiet some autoconf/automake warnings
- Convert manpages to asciidoc source

* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 6.8-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 6.7-2
- Fix Source path

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 6.7-1
- Merge changes from Mattias Ellert

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 6.6-1
- Version bump for consistency

* Tue Feb 25 2014 Globus Toolkit <support@globus.org> - 6.5-1
- Packaging fixes

* Sat Feb 01 2014 Globus Toolkit <support@globus.org> - 6.4-1
- Fix test wrapper with old automake

* Sat Feb 01 2014 Globus Toolkit <support@globus.org> - 6.3-1
- Fix test cred permissions

* Sat Feb 01 2014 Globus Toolkit <support@globus.org> - 6.2-1
- version update

* Mon Jan 27 2014 Globus Toolkit <support@globus.org> - 6.0-1
- Add tests to globus_proxy_utils
- Doxygen / header cleanup
- Native debian package updates
- New version of rectify-versions
- Opt for POSIX 1003.1-2001 (pax) format tarballs
- Remove GPT and make-packages.pl from build process
- Remove GPT metadata
- autoconf/automake updates

* Thu Jan 23 2014 Globus Toolkit <support@globus.org> - 6.1-1
- Add openssl dependency

* Thu Jan 23 2014 Globus Toolkit <support@globus.org> - 6.0-1
- Repackage for GT6 without GPT

* Tue Sep 10 2013 Globus Toolkit <support@globus.org> - 5.2-1
- GT-387: grid-proxy-init -pwstdin reads too many characters

* Mon Jul 08 2013 Globus Toolkit <support@globus.org> - 5.1-3
- openssl-libs for newer fedora

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 5.1-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Wed May 15 2013 Globus Toolkit <support@globus.org> - 5.1-1
- GT-272: Increase default proxy key size

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 5.0-10
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 5.0-9
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 5.0-8
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 5.0-7
- RHEL 4 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 5.0-6
- Updated version numbers

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 5.0-5
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 5.0-4
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 5.0-3
- Add explicit dependencies on >= 5.2 libraries

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 5.0-2
- Update for 5.1.2 release

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.9-1
- Update to Globus Toolkit 5.0.2
- Drop patch globus-proxy-utils-oid.patch (fixed upstream)

* Mon May 31 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.7-2
- Fix OID registration pollution

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.7-1
- Update to Globus Toolkit 5.0.1
- Drop patches globus-proxy-utils-ldflag-overwrt.patch and
  globus-proxy-utils-deps.patch (fixed upstream)

* Fri Jan 22 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.5-1
- Update to Globus Toolkit 5.0.0

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 2.5-4
- rebuilt with new openssl

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-3
- Add instruction set architecture (isa) tags

* Wed Jun 03 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-2
- Update to official Fedora Globus packaging guidelines

* Thu Apr 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-1
- Make comment about source retrieval more explicit
- Change defines to globals
- Remove explicit requires on library packages
- Put GLOBUS_LICENSE file in extracted source tarball

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-0.5
- Adapting to updated globus-core package

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-0.4
- Add s390x to the list of 64 bit platforms

* Tue Dec 30 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-0.3
- Adapt to updated GPT package

* Wed Oct 15 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.5-0.2
- Update to Globus Toolkit 4.2.1

* Mon Jul 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.1-0.1
- Autogenerated
