Name:		globus-gsi-credential
%global _name %(tr - _ <<< %{name})
Version:	7.0
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus GSI Credential Library

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common%{?_isa} >= 14
Requires:	globus-gsi-callback%{?_isa} >= 4
Requires:	globus-openssl-module%{?_isa} >= 3
Requires:	globus-gsi-openssl-error%{?_isa} >= 2
Requires:	globus-gsi-cert-utils%{?_isa} >= 8
Requires:	globus-gsi-sysconfig%{?_isa} >= 5

BuildRequires:	globus-gsi-callback-devel >= 4
BuildRequires:	globus-openssl-module-devel >= 3
BuildRequires:	globus-gsi-openssl-error-devel >= 2
BuildRequires:	openssl-devel
BuildRequires:	globus-gsi-cert-utils-devel >= 8
BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-gsi-sysconfig-devel >= 5
BuildRequires:	doxygen
BuildRequires:	graphviz
%if "%{?rhel}" == "5"
BuildRequires:	graphviz-gd
%endif

%package devel
Summary:	Globus Toolkit - Globus GSI Credential Library Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-gsi-callback-devel%{?_isa} >= 4
Requires:	globus-openssl-module-devel%{?_isa} >= 3
Requires:	globus-gsi-openssl-error-devel%{?_isa} >= 2
Requires:	openssl-devel%{?_isa}
Requires:	globus-gsi-cert-utils-devel%{?_isa} >= 8
Requires:	globus-common-devel%{?_isa} >= 14
Requires:	globus-gsi-sysconfig-devel%{?_isa} >= 5

%package doc
Summary:	Globus Toolkit - Globus GSI Credential Library Documentation Files
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
Globus GSI Credential Library

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Globus GSI Credential Library Development Files

%description doc
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-doc package contains:
Globus GSI Credential Library Documentation Files

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
%doc %{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_libdir}/libglobus_*.so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/pkgconfig/%{name}.pc
%{_libdir}/libglobus_*.so

%files doc
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}/html
%{_docdir}/%{name}-%{version}/html/*
%{_mandir}/man3/*

%changelog
* Tue Jan 21 2014 Globus Toolkit <support@globus.org> - 7.0-1
- Repackage for GT6 without GPT

* Mon Oct 28 2013 Globus Toolkit <support@globus.org> - 6.0-1
- Update Major version for globus_gsi_cred_read_cert_buffer and globus_gsi_cred_verify_cert_chain_when

* Wed Jul 17 2013 Globus Toolkit <support@globus.org> - 5.7-1
- GT-437: grid-proxy-init broken for PKCS12 files with CA certificates

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 5.6-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Fri Apr 26 2013 Globus Toolkit <support@globus.org> - 5.6-1
- fix leak in verify_when

* Mon Apr 15 2013 Globus Toolkit <support@globus.org> - 5.5-1
- verify sharing cert chain

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> - 5.4-1
- Update sharing to support a full cert chain at logon

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 5.3-7
- Workaround missing F18 doxygen/latex dependency

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 5.3-6
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 5.3-5
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 5.3-4
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 5.3-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 5.3-2
- SLES 11 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 5.3-1
- RIC-213: support for private keys in PKCS8 format broken
- RIC-226: Some dependencies are missing in GPT metadata

* Thu Jan 05 2012 Joseph Bester <bester@mcs.anl.gov> - 5.2-1
- RIC-213: support for private keys in PKCS8 format broken

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 5.1-4
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 5.1-3
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 5.1-2
- Add explicit dependencies on >= 5.2 libraries

* Thu Oct 06 2011 Joseph Bester <bester@mcs.anl.gov> - 5.1-1
- Add backward-compatibility aging

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 5.0-3
- Fix missing whitespace in Requires

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 5.0-2
- Update for 5.1.2 release

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.5-1
- Update to Globus Toolkit 5.0.2
- Drop patch globus-gsi-credential-oid.patch (fixed upstream)

* Mon May 31 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.3-2
- Fix OID registration pollution

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.3-1
- Update to Globus Toolkit 5.0.1
- Drop patch globus-gsi-credential-openssl.patch (fixed upstream)

* Fri Jan 22 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-1
- Update to Globus Toolkit 5.0.0

* Sat Aug 22 2009 Tomas Mraz <tmraz@redhat.com> - 2.2-4
- rebuilt with new openssl

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.2-3
- Add instruction set architecture (isa) tags
- Make doc subpackage noarch

* Wed Jun 03 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.2-2
- Update to official Fedora Globus packaging guidelines

* Thu Apr 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.2-1
- Make comment about source retrieval more explicit
- Change defines to globals
- Remove explicit requires on library packages
- Put GLOBUS_LICENSE file in extracted source tarball

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.2-0.5
- Adapting to updated globus-core package

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.2-0.4
- Add s390x to the list of 64 bit platforms

* Thu Jan 01 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.2-0.3
- Adapt to updated GPT package

* Wed Oct 15 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.2-0.2
- Update to Globus Toolkit 4.2.1

* Mon Jul 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 2.0-0.1
- Autogenerated
