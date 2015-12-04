Name:		globus-gssapi-gsi
%global _name %(tr - _ <<< %{name})
Version:	11.24
Release:	1%{?dist}
Vendor:	Globus Support
Summary:	Globus Toolkit - GSSAPI library

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://toolkit.globus.org/
Source:	http://toolkit.globus.org/ftppub/gt6/packages/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-gsi-credential%{?_isa} >= 5
Requires:	globus-gsi-callback%{?_isa} >= 4
Requires:	globus-openssl-module%{?_isa} >= 3
Requires:	globus-gsi-openssl-error%{?_isa} >= 2
Requires:	globus-gsi-proxy-core%{?_isa} >= 6
Requires:	globus-gsi-cert-utils%{?_isa} >= 8
Requires:	globus-common%{?_isa} >= 14
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
Requires:	openssl
Requires:	openssl-libs%{?_isa}
%endif
%if %{?fedora}%{!?fedora:0} < 19 && %{?rhel}%{!?rhel:0} < 7
Requires:	openssl%{?_isa}
%endif

BuildRequires:	globus-gsi-credential-devel >= 5
BuildRequires:	globus-gsi-callback-devel >= 4
BuildRequires:	globus-openssl-module-devel >= 3
BuildRequires:	globus-gsi-openssl-error-devel >= 2
BuildRequires:	globus-gsi-proxy-core-devel >= 6
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
%if %{?fedora}%{!?fedora:0} >= 18 || %{?rhel}%{!?rhel:0} >= 6
BuildRequires:  perl-Test-Simple
%endif
BuildRequires:  openssl

%package devel
Summary:	Globus Toolkit - GSSAPI library Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-gsi-credential-devel%{?_isa} >= 5
Requires:	globus-gsi-callback-devel%{?_isa} >= 4
Requires:	globus-openssl-module-devel%{?_isa} >= 3
Requires:	globus-gsi-openssl-error-devel%{?_isa} >= 2
Requires:	globus-gsi-proxy-core-devel%{?_isa} >= 6
Requires:	globus-gsi-cert-utils-devel%{?_isa} >= 8
Requires:	globus-common-devel%{?_isa} >= 14

%package doc
Summary:	Globus Toolkit - GSSAPI library Documentation Files
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
GSSAPI library

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
GSSAPI library Development Files

%description doc
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-doc package contains:
GSSAPI library Documentation Files

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
make %{?_smp_mflags} check

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%config(noreplace) %{_sysconfdir}/grid-security/gsi.conf
%{_libdir}/libglobus_*.so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/libglobus_*.so
%{_libdir}/pkgconfig/*.pc

%files doc
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}/html
%{_docdir}/%{name}-%{version}/html/*
%{_mandir}/man3/*

%changelog
* Fri Dec 04 2015 Globus Toolkit <support@globus.org> - 11.24-1
- Don't call SSLv3_method unless it is available

* Wed Nov 25 2015 Globus Toolkit <support@globus.org> - 11.23-1
- Remove @} without matching @{

* Tue Sep 08 2015 Globus Toolkit <support@globus.org> - 11.22-1
- GT-627: gss_import_cred crash
- Improve portability for some tests

* Thu Aug 06 2015 Globus Toolkit <support@globus.org> - 11.21-2
- Add vendor

* Wed Jul 29 2015 Globus Toolkit <support@globus.org> - 11.21-1
- Find thread libs for in-tree testing

* Thu Jul 23 2015 Globus Toolkit <support@globus.org> - 11.20-1
- GT-614: GLOBUS_GSS_C_NT_HOST_IP doesn't allow host-only imports and comparisons

* Mon Jun 08 2015 Globus Toolkit <support@globus.org> - 11.19-1
- export config file values into environment if not set already

* Thu Jun 04 2015 Globus Toolkit <support@globus.org> - 11.18-1
- Revert to HYBRID name mode by default

* Mon Jun 01 2015 Globus Toolkit <support@globus.org> - 11.17-1
- Threaded test fixes

* Thu May 28 2015 Globus Toolkit <support@globus.org> - 11.16-1
- Update autoconf script

* Thu May 28 2015 Globus Toolkit <support@globus.org> - 11.15-1
- Add config file for GSI options
- Allow configuration of SSL cipher suite
- Allow server preference for SSL cipher suite ordering
- Fix thread test to run without unix domain sockets

* Tue May 19 2015 Globus Toolkit <support@globus.org> - 11.14-2
- Add openssl build dependency

* Mon Nov 03 2014 Globus Toolkit <support@globus.org> - 11.14-1
- doxygen fixes

* Thu Sep 25 2014 Globus Toolkit <support@globus.org> - 11.13-1
- Include more manpages for API
- Use consistent PREDEFINED in all Doxyfiles
- Fix dependency version
- Fix typos and clarify some documentation
- Quiet some autoconf/automake warnings

* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 11.12-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 11.11-2
- Fix Source path

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 11.11-1
- Merge changes from Mattias Ellert

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 11.10-1
- Version bump for consistency

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 11.9-1
- Test Fixes

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 11.8-1
- Packaging fixes, Warning Cleanup

* Tue Feb 25 2014 Globus Toolkit <support@globus.org> - 11.7-1
- Packaging fixes

* Tue Feb 25 2014 Globus Toolkit <support@globus.org> - 11.6-1
- Test fixes

* Tue Feb 11 2014 Globus Toolkit <support@globus.org> - 11.5-1
- Test fixes

* Tue Feb 11 2014 Globus Toolkit <support@globus.org> - 11.4-1
- Test fixes

* Tue Feb 11 2014 Globus Toolkit <support@globus.org> - 11.3-1
- Test fixes

* Mon Feb 10 2014 Globus Toolkit <support@globus.org> - 11.2-1
- Packaging fixes

* Tue Jan 28 2014 Globus Toolkit <support@globus.org> - 11.1-1
- Add #include <sys/wait.h>

* Tue Jan 21 2014 Globus Toolkit <support@globus.org> - 11.0-1
- Repackage for GT6 without GPT

* Thu Oct 10 2013 Globus Toolkit <support@globus.org> - 10.10-1
- GT-445: Doxygen fixes

* Thu Oct 10 2013 Globus Toolkit <support@globus.org> - 10.9-1
- GT-454: memory leak in gss_accept_sec_context

* Mon Jul 08 2013 Globus Toolkit <support@globus.org> - 10.8-3
- openssl-libs for newer fedora

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 10.8-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Fri Feb 22 2013 Globus Toolkit <support@globus.org> - 10.8-1
- GT-363: gss_get_mic/gss_verify_mic fail for some TLS ciphers with OpenSSL 1.0.1

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 10.7-6
- Workaround missing F18 doxygen/latex dependency

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 10.7-5
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 10.7-4
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 10.7-3
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 10.7-2
- RHEL 4 patches

* Mon May 07 2012 Joseph Bester <bester@mcs.anl.gov> - 10.7-1
- RIC-265: Memory leak in gss_accept_delegation()

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 10.6-2
- SLES 11 patches

* Wed Apr 11 2012 Joseph Bester <bester@mcs.anl.gov> - 10.6-1
- RIC-254: gssapi probe for whether it can use openssl internals doesn't always work

* Fri Mar 09 2012 Joseph Bester <bester@mcs.anl.gov> - 10.5-1
- RIC-243: gss_import_cred can't handle non-null terminated token

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 10.4-1
- RIC-215: gss_import_cred() doesn't match properly the OID passed
- RIC-224: Eliminate some doxygen warnings
- RIC-226: Some dependencies are missing in GPT metadata
- RIC-227: Potentially unsafe format strings in GSI

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 10.2-3
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 10.2-2
- Last sync prior to 5.2.0

* Wed Nov 02 2011 Joseph Bester <bester@mcs.anl.gov> - 10.2-1
- Bug 7159 - globus-gssapi-gsi uses openssl symbols that are not part of the
  API

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 10.1-2
- Add explicit dependencies on >= 5.2 libraries

* Thu Oct 06 2011 Joseph Bester <bester@mcs.anl.gov> - 10.1-1
- Add backward-compatibility aging

* Tue Sep 20 2011  <bester@mcs.anl.gov> - 10.0-1
- Add flag to force SSLv3 when initiating a security context

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 9.0-2
- Update for 5.1.2 release

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.5-1
- Update to Globus Toolkit 5.0.1
- Drop patch globus-gssapi-gsi-openssl.patch (fixed upstream)

* Mon Feb 08 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.0-2
- Update openssl 1.0.0 patch based on RIC-29 branch in upstream CVS

* Fri Jan 22 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.0-1
- Update to Globus Toolkit 5.0.0

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 5.9-5
- rebuilt with new openssl

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9-4
- Add instruction set architecture (isa) tags
- Make doc subpackage noarch

* Wed Jun 03 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9-3
- Update to official Fedora Globus packaging guidelines

* Tue May 12 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9-2
- Change the License tag to take the library/ssl_locl.h file into account

* Thu Apr 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9-1
- Make comment about source retrieval more explicit
- Change defines to globals
- Remove explicit requires on library packages
- Put GLOBUS_LICENSE file in extracted source tarball

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9-0.5
- Adapting to updated globus-core package

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9-0.4
- Add s390x to the list of 64 bit platforms

* Thu Jan 01 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9-0.3
- Adapt to updated GPT package

* Wed Oct 15 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9-0.2
- Update to Globus Toolkit 4.2.1

* Mon Jul 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3-0.1
- Autogenerated
