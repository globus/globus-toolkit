Name:		globus-xio-udt-driver
%global _name %(tr - _ <<< %{name})
Version:	1.10
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus XIO UDT Driver

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common%{?_isa} >= 14
Requires:	globus-xio%{?_isa} >= 3
%if %{?fedora}%{!?fedora:0} >= 18
Requires:       glib2%{?_isa} >= 2.32
Requires:       libnice%{?_isa} >= 0.0.12
%endif
Requires:       libffi

BuildRequires:	globus-xio-devel >= 3
BuildRequires:	globus-common-devel >= 14
%if %{?fedora}%{!?fedora:0} >= 18
BuildRequires:  glib2-devel >= 2.32
BuildRequires:  libnice-devel >= 0.0.12
%else
%if 0%{?suse_version} > 0
BuildRequires:  gettext-tools
%else
BuildRequires:  gettext-devel
%endif
BuildRequires:  xz
BuildRequires:  curl
BuildRequires:  zlib-devel
%endif
%if %{?rhel}%{!?rhel:0} == 5
BuildRequires:  python26
%endif
BuildRequires:  libffi-devel
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:  automake >= 1.11
BuildRequires:  autoconf >= 2.60
BuildRequires:  libtool >= 2.2
%endif
BuildRequires:  pkgconfig

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
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
# Remove files that should be replaced during bootstrap
rm -rf autom4te.cache

autoreconf -if
%endif


%if 0%{?suse_version} > 0
# SuSE 11 doesn't include libffi's pkg-config file, but the library
# is available natively. LIBFFI_CFLAGS must be non-empty for autoconf to
# detect it as set in the configure invocation in the glib2 source directory
export LIBFFI_CFLAGS="-DGT6_UDT_DRIVER_SuSE_HACK"
export LIBFFI_LIBS="-lffi"
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

find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_libdir}/libglobus*.so*
%{_libdir}/globus/lib*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/pkgconfig/%{name}.pc

%changelog
* Fri Apr 25 2014 Globus Toolkit <support@globus.org> - 1.10-1
- Packaging fixes

* Fri Apr 25 2014 Globus Toolkit <support@globus.org> - 1.9-1
- Packaging fixes

* Fri Apr 25 2014 Globus Toolkit <support@globus.org> - 1.8-1
- Packaging fixes

* Fri Apr 25 2014 Globus Toolkit <support@globus.org> - 1.7-1
- Packaging fixes

* Fri Apr 25 2014 Globus Toolkit <support@globus.org> - 1.6-1
- Packaging fixes

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 1.5-1
- Version bump for consistency

* Wed Mar 05 2014 Globus Toolkit <support@globus.org> - 1.0-1
- Packaging fixes

* Wed Oct 16 2013 Globus Toolkit <support@globus.org> - 0.6-2
- New package
