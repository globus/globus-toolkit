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

Name:		globus-xio-udt-driver
%global _name %(tr - _ <<< %{name})
Version:	0.4
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus XIO UDT Driver

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common >= 14
Requires:	globus-xio%{?_isa} >= 3
Requires:       libudt >= 4
Requires:       glib2 >= 2.22.5
Requires:       libnice >= 0.0.9

BuildRequires:	grid-packaging-tools >= 3.4
BuildRequires:	globus-xio-devel >= 3
BuildRequires:	globus-core >= 8
BuildRequires:	globus-common-devel >= 14
BuildRequires:  libudt-devel >= 4
BuildRequires:  glib2-devel >= 2.22.5
BuildRequires:  libnice-devel >= 0.0.9

%package devel
Summary:	Globus Toolkit - Globus XIO UDT Driver Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-xio-devel%{?_isa} >= 3

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus XIO UDT Driver

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Globus XIO UDT Driver Development Files

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

# This library is opened using lt_dlopenext, so the libtool archives
# (.la files) can not be removed - fix the libdir...
for lib in `find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la'` ; do
  sed "s!^libdir=.*!libdir=\'%{_libdir}\'!" -i $lib
done

# Generate package filelists
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_rtl.filelist \
  $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist  \
  | sed s!^!%{_prefix}! > package.filelist
# Add libtool archive to runtime filelist
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist \
  | grep 'lib[^/]*\.la$' \
  | sed s!^!%{_prefix}! >> package.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist \
  | grep -v 'lib[^/]*\.la$' \
  | sed s!^!%{_prefix}! > package-devel.filelist

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files -f package.filelist
%defattr(-,root,root,-)
%dir %{_datadir}/globus/packages/%{_name}
%dir %{_docdir}/%{name}-%{version}

%files -f package-devel.filelist devel
%defattr(-,root,root,-)

%changelog
* Wed May 24 2013 Globus Toolkit <support@globus.org> - 0.4-1
- New package

