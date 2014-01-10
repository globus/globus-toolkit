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

Name:		globus-io
%global _name %(tr - _ <<< %{name})
Version:	9.6
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

BuildRequires:	grid-packaging-tools >= 3.4
BuildRequires:	globus-xio-gsi-driver-devel >= 2
BuildRequires:	globus-gss-assist-devel >= 8
BuildRequires:	globus-xio-devel >= 3
BuildRequires:	globus-gssapi-gsi-devel >= 10
BuildRequires:	globus-core >= 8
BuildRequires:	globus-gssapi-error >= 4

%package devel
Summary:	Globus Toolkit - uniform I/O interface Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-xio-gsi-driver-devel%{?_isa} >= 2
Requires:	globus-gss-assist-devel%{?_isa} >= 8
Requires:	globus-xio-devel%{?_isa} >= 3
Requires:	globus-gssapi-gsi-devel%{?_isa} >= 10
Requires:	globus-core%{?_isa} >= 8
BuildRequires:	globus-gssapi-error-devel%{?_isa} >= 4

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
# Remove files that should be replaced during bootstrap
rm -f doxygen/Doxyfile*
rm -f doxygen/Makefile.am
rm -f pkgdata/Makefile.am
rm -f globus_automake*
rm -rf autom4te.cache
unset GLOBUS_LOCATION
unset GPT_LOCATION

%{_datadir}/globus/globus-bootstrap.sh

%configure --with-flavor=%{flavor} \
           --%{docdiroption}=%{_docdir}/%{name}-%{version} \
           --disable-static

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;
sed '/lib.*\.la$/d' -i $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist

# Generate package filelists
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_rtl.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist  \
  | sed s!^!%{_prefix}! > package.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist \
  | sed s!^!%{_prefix}! > package-devel.filelist

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
%{_libdir}/pkgconfig/%{name}.pc

%changelog
* Fri Jan 10 2014 Globus Toolkit <support@globus.org> - 9.6-1
- Fix some bootstrapping issues

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
