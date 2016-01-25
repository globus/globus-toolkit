%ifarch alpha ia64 ppc64 s390x sparc64 x86_64
%global flavor gcc64
%else
%global flavor gcc32
%endif

%if "%{?rhel}" == "4" || "%{?rhel}" == "5"
%global docdiroption "with-docdir"
%else
%global docdiroption "docdir"
%endif

Name:		globus-gssapi-gsi
%global _name %(tr - _ <<< %{name})
Version:	10.16
Release:	1%{?dist}
Summary:	Globus Toolkit - GSSAPI library

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
#		This is a workaround for the broken epstopdf script in RHEL5
#		See: https://bugzilla.redhat.com/show_bug.cgi?id=450388
Source9:	epstopdf-2.9.5gw
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

BuildRequires:	grid-packaging-tools >= 3.4
BuildRequires:	globus-gsi-credential-devel >= 5
BuildRequires:	globus-gsi-callback-devel >= 4
BuildRequires:	globus-openssl-module-devel >= 3
BuildRequires:	globus-gsi-openssl-error-devel >= 2
BuildRequires:	globus-gsi-proxy-core-devel >= 6
BuildRequires:	globus-core >= 8
BuildRequires:	globus-gsi-cert-utils-devel >= 8
BuildRequires:	globus-common-devel >= 14
BuildRequires:	doxygen
BuildRequires:	graphviz
%if "%{?rhel}" == "5"
BuildRequires:	graphviz-gd
%endif
BuildRequires:	ghostscript
%if %{?fedora}%{!?fedora:0} >= 9 || %{?rhel}%{!?rhel:0} >= 6
BuildRequires:	tex(latex)
%else
%if 0%{?suse_version} > 0
BuildRequires:  texlive-latex
%else
BuildRequires:	tetex-latex
%endif
%endif

%if %{?fedora}%{!?fedora:0} >= 18 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires: tex(sectsty.sty)
BuildRequires: tex(tocloft.sty)
BuildRequires: tex(xtab.sty)
BuildRequires: tex(multirow.sty)
BuildRequires: tex(fullpage.sty)
%endif

%package devel
Summary:	Globus Toolkit - GSSAPI library Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-gsi-credential-devel%{?_isa} >= 5
Requires:	globus-gsi-callback-devel%{?_isa} >= 4
Requires:	globus-openssl-module-devel%{?_isa} >= 3
Requires:	globus-gsi-openssl-error-devel%{?_isa} >= 2
Requires:	globus-gsi-proxy-core-devel%{?_isa} >= 6
Requires:	globus-core%{?_isa} >= 8
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

%if "%{rhel}" == "5"
mkdir bin
install %{SOURCE9} bin/epstopdf
%endif

%build
%if "%{rhel}" == "5"
export PATH=$PWD/bin:$PATH
%endif

# Remove files that should be replaced during bootstrap
rm -f doxygen/Doxyfile*
rm -f doxygen/Makefile.am
rm -f pkgdata/Makefile.am
rm -f globus_automake*
rm -rf autom4te.cache
unset GLOBUS_LOCATION
unset GPT_LOCATION

%{_datadir}/globus/globus-bootstrap.sh

%configure --with-flavor=%{flavor} --enable-doxygen \
           --%{docdiroption}=%{_docdir}/%{name}-%{version} \
           --disable-static

make %{?_smp_mflags}

%install
%if "%{rhel}" == "5"
export PATH=$PWD/bin:$PATH
%endif

rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;
sed '/lib.*\.la$/d' -i $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist

# Remove unwanted documentation (needed for RHEL4)
rm -f $RPM_BUILD_ROOT%{_mandir}/man3/*_%{_name}-%{version}_*.3
sed -e '/_%{_name}-%{version}_.*\.3/d' \
  -i $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist

# Remove deprecated.3 man page (too common name)
rm -f $RPM_BUILD_ROOT%{_mandir}/man3/deprecated.3
sed -e '/deprecated\.3/d' -i $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist

# Generate package filelists
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_rtl.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | grep -v '/etc' \
  | sed -e s!^!%{_prefix}! > package.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | grep '^/etc' \
  >> package.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist \
  | sed s!^!%{_prefix}! > package-devel.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
  | grep -v GLOBUS_LICENSE \
  | sed -e 's!/man/.*!&*!' -e 's!^!%doc %{_prefix}!' > package-doc.filelist

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files -f package.filelist
%defattr(-,root,root,-)
%dir %{_datadir}/globus/packages/%{_name}
%dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/GLOBUS_LICENSE

%files -f package-devel.filelist devel
%defattr(-,root,root,-)

%files -f package-doc.filelist doc
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}/html

%changelog
* Mon Jan 25 2016 Globus Toolkit <support@globus.org> - 10.16-1
- Fix FORCE_TLS setting to allow TLSv1.1 and TLS1.2, not just TLSv1.0

* Thu Jul 23 2015 Globus Toolkit <support@globus.org> - 10.15-1
- GT-614: GLOBUS_GSS_C_NT_HOST_IP doesn't allow host-only imports and comparisons

* Thu Jun 04 2015 Globus Toolkit <support@globus.org> - 10.14-1
- Revert to HYBRID name comparisons by default

* Fri May 29 2015 Globus Toolkit <support@globus.org> - 10.13-3
- Add noflavor_data to package

* Fri May 29 2015 Globus Toolkit <support@globus.org> - 10.13-2
- Fix latex dependency on fedora > 18

* Fri May 29 2015 Globus Toolkit <support@globus.org> - 10.13-1
- Add config file for GSI options
- Allow configuration of SSL cipher suite
- Allow server preference for SSL cipher suite ordering

* Tue Mar 11 2014 Globus Toolkit <support@globus.org> - 10.12-2
- Updated version numbers

* Thu Dec 12 2013 Globus Toolkit <support@globus.org> - 10.12-1
- Enable adding in memory CA cert to cert store

* Fri Dec 06 2013 Globus Toolkit <support@globus.org> - 10.11-1
- GT-489: xio_gsi errors with OpenSSL 1.0.1e

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
